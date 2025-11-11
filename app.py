from flask import Flask, render_template, request, send_file, redirect, url_for, flash
import qrcode
import io
import json
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # required for flash messages

USERS_FILE = 'users.json'

# Initialize users file if it doesn't exist
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, 'w') as f:
        json.dump({}, f)

def load_users():
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

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

    users = load_users()
    if username not in users or users[username] != password:
        flash('Invalid username or password. Please sign up first.')
        return redirect(url_for('home'))

    print(f"Login attempt from user: {username}, IP: {ip_address}")

    qr_data = f"User:{username},IP:{ip_address}"
    qr_img = qrcode.make(qr_data)

    img_io = io.BytesIO()
    qr_img.save(img_io, 'PNG')
    img_io.seek(0)
    return send_file(img_io, mimetype='image/png')

if __name__ == '__main__':
    app.run(debug=True)
