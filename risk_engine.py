import datetime
from geo import get_geo


# Fake list of suspicious IPs
BAD_IPS = {"123.45.67.89", "66.66.66.66"}

def calculate_risk(username, ip, known_locations, user_agent, failed_attempts):
    risk = 0
    reasons = []

    # 1. LOCATION RISK
    if username not in known_locations or ip not in known_locations.get(username, []):
        risk += 30
        reasons.append("Unfamiliar IP address")

    # 2. TIME RISK
    hour = datetime.datetime.now().hour
    if hour < 6 or hour > 23:
        risk += 10
        reasons.append("Login at unusual hours")

    # 3. DEVICE RISK
    if "Mobile" not in user_agent and "Windows" in user_agent:
        pass  # common
    else:
        risk += 10
        reasons.append("New or unusual device/browser")

    # 4. FAILED ATTEMPT RISK
    if failed_attempts >= 3:
        risk += 40
        reasons.append("Multiple failed login attempts")

    # 5. BAD IP CHECK
    if ip in BAD_IPS:
        risk += 80
        reasons.append("IP flagged as suspicious/malicious")

    return risk, reasons
