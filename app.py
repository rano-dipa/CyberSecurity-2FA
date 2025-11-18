from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from risk_engine import calculate_risk
from geo import get_geo
import qrcode
import io
import json
import os
import secrets
import datetime
import base64

KNOWN_LOC_FILE = 'known_locations.json'
SESSION_FILE = 'session_store.json'
AUDIT_FILE = "audit_log.json"
FAILED_ATTEMPTS_FILE = "failed_attempts.json"

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # required for flash messages

USERS_FILE = 'users.json'

# Initialize users file if it doesn't exist
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, 'w') as f:
        json.dump({}, f)


def load_json(path, default):
    if not os.path.exists(path):
        with open(path, 'w') as f:
            json.dump(default, f)
    with open(path, 'r') as f:
        return json.load(f)


def save_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)


def load_users():
    return load_json(USERS_FILE, {})


def save_users(users):
    save_json(USERS_FILE, users)


def load_known_locations():
    return load_json(KNOWN_LOC_FILE, {})


def save_known_locations(locations):
    save_json(KNOWN_LOC_FILE, locations)


def load_sessions():
    return load_json(SESSION_FILE, {})


def save_sessions(sessions):
    save_json(SESSION_FILE, sessions)


def load_audit():
    return load_json(AUDIT_FILE, [])


def save_audit(logs):
    save_json(AUDIT_FILE, logs)


def load_attempts():
    return load_json(FAILED_ATTEMPTS_FILE, {})


def save_attempts(attempts):
    save_json(FAILED_ATTEMPTS_FILE, attempts)


def add_audit_entry(username, ip, score, reasons):
    logs = load_audit()
    logs.append({
        "user": username,
        "ip": ip,
        "risk_score": score,
        "reasons": reasons,
        "timestamp": str(datetime.datetime.now())
    })
    save_audit(logs)


@app.route('/')
def home():
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        users = load_users()
        if username in users:
            flash('Username already exists. Please log in instead.')
            return redirect(url_for('home'))

        users[username] = password
        save_users(users)

        flash('Signup successful! You can now log in.')
        return redirect(url_for('home'))

    return render_template('signup.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent')

    users = load_users()
    attempts = load_attempts()

    # Initialize attempt counter
    if username not in attempts:
        attempts[username] = 0

    # Wrong password → increase attempt counter
    if username not in users or users[username] != password:
        attempts[username] += 1
        save_attempts(attempts)
        flash("Invalid username or password")
        return redirect(url_for('home'))

    # Reset attempts after successful password check
    attempts[username] = 0
    save_attempts(attempts)

    # -----------------------------
    # RISK ENGINE SECTION
    # -----------------------------
    known_locations = load_known_locations()
    failed_attempts = attempts.get(username, 0)

    risk_score, reasons = calculate_risk(
        username=username,
        ip=ip_address,
        known_locations=known_locations,
        user_agent=user_agent,
        failed_attempts=failed_attempts
    )

    # Log audit record
    add_audit_entry(username, ip_address, risk_score, reasons)

    # Decide risk action
    if risk_score >= 70:
        flash("HIGH RISK LOGIN BLOCKED! Contact admin.")
        return redirect(url_for('home'))

    # If medium risk → require QR approval
    if risk_score >= 30:
        flash("Unusual login detected. Additional approval required.")
    else:
        flash("Login from trusted environment.")

    # -------------------------------
    # CREATE QR VERIFICATION SESSION
    # -------------------------------
    token = secrets.token_hex(16)
    sessions = load_sessions()
    sessions[token] = {
        "username": username,
        "verified": False,
        "ip": ip_address
    }
    save_sessions(sessions)

    # Create QR code URL
    qr_url = request.host_url + "approve/" + token
    qr_img = qrcode.make(qr_url)

    img_io = io.BytesIO()
    qr_img.save(img_io, 'PNG')
    img_io.seek(0)

    qr_base64 = base64.b64encode(img_io.getvalue()).decode()

    return render_template("verify.html", token=token, qr_image=qr_base64)


@app.route('/check_status/<token>')
def check_status(token):
    sessions = load_sessions()
    if token in sessions and sessions[token]["verified"]:
        return {"status": "verified"}
    return {"status": "pending"}


@app.route('/approve/<token>')
def approve(token):
    sessions = load_sessions()

    if token not in sessions:
        return "Invalid or expired session."

    username = sessions[token]["username"]
    user_ip = sessions[token]["ip"]

    # Mark session as verified
    sessions[token]["verified"] = True
    save_sessions(sessions)

    # --------------------------
    # SAVE GEOLOCATION HERE
    # --------------------------
    geo = get_geo(user_ip)

    known_locations = load_known_locations()

    if username not in known_locations:
        known_locations[username] = []

    # Avoid duplicates
    already_exists = any(loc["ip"] == user_ip for loc in known_locations[username])

    if not already_exists:
        known_locations[username].append({
            "ip": user_ip,
            "country": geo["country"],
            "city": geo["city"],
            "isp": geo["isp"]
        })

    save_known_locations(known_locations)

    return render_template("approve.html", user=username)

@app.route('/dashboard/<token>')
def dashboard(token):
    sessions = load_sessions()
    if token in sessions and sessions[token]["verified"]:
        return render_template("dashboard.html", user=sessions[token]["username"])
    return "Unauthorized"


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)

