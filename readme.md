# Cybersecurity Login System (Risk-Adaptive Authentication)

This project implements a security-oriented web application featuring risk-based authentication, geolocation checks, session monitoring, and administrative oversight. It is built using Flask and uses JSON files for data storage, keeping the system simple and portable.

Project Members:  
- Dipanwita Rano  
- Arun Akash Rangraj  
- Rushil Ravi  

---

## Features
- User sign-up, login, and verification
- Risk Engine analyzing:
  - Geolocation and ISP data
  - New or unfamiliar IPs and locations
  - Impossible travel patterns
  - Device characteristics
  - Failed login attempts
  - Suspicious / flagged IPs
- Admin dashboard for logs, users, and risk assessment
- JSON-based lightweight storage

---

## Project Structure
```
Cybersec/
│
├── app.py
├── risk_engine.py
├── geo.py
│
├── templates/
│   ├── login.html
│   ├── signup.html
│   ├── verify.html
│   ├── dashboard.html
│   ├── approve.html
│   ├── admin.html
│
├── audit_log.json
├── failed_attempts.json
├── known_locations.json
├── session_store.json
├── users.json
│
└── static/
```

---

## Requirements
```
Python 3.10+
Flask
requests
qrcode
```

Install:
```
pip install flask requests qrcode
```

---

## How to Run
```
python app.py
```

Open in browser:
```
http://127.0.0.1:5000
```

---

## How the Risk Engine Works

### 1. Geolocation
`get_geo(ip)` retrieves country, city, ISP, latitude, longitude. These are compared to prior logins stored in `known_locations.json`.

### 2. New/Unusual Login Indicators
Risk increases if login comes from:
- new IP  
- new city  
- new country  
- new ISP  

### 3. Impossible Travel
Uses haversine distance between last login and current login.  
If required travel speed exceeds ~900 km/h, it is flagged.

### 4. Time-Based Risk
Logins at unusual hours (before 6 AM or after 11 PM) add risk.

### 5. Device/User-Agent Risk
Detects irregular device/browser patterns.

### 6. Failed Attempt Accumulation
Repeated failed attempts increase risk sharply.

### 7. Malicious IP Check
A small list of flagged IPs is penalized heavily.

### Outcome
- Low risk → login allowed  
- Medium risk → requires confirmation  
- High risk → login blocked and logged  

This demonstrates an adaptive authentication flow that adjusts access decisions based on contextual and behavioral risk signals.

## Testing the QR Flow on a Phone 

When testing the QR-based approval workflow, ensure that the phone can reach the Flask server over the local network. Use your laptop’s LAN IP address in the QR URL; `127.0.0.1` will not work on a phone. Both devices must be on the same Wi-Fi network. If the phone cannot load the approval page, check whether Windows Defender or another firewall is blocking inbound connections and allow `python.exe` on private networks. If the QR image appears blank, verify that `verify.html` correctly receives and renders the Base64-encoded `qr_image` string generated in `app.py`.

## Conclusion

This project demonstrates a practical implementation of adaptive authentication by combining location awareness, device analysis, user behavior, and real-time risk scoring. The system highlights how modern security models can move beyond static passwords to incorporate contextual signals that strengthen account protection while maintaining usability. The modular structure—separating risk evaluation, geolocation, session tracking, and user interaction—makes the project extensible for future enhancements such as MFA integration, anomaly detection models, or enterprise-grade logging. This serves as a foundational prototype for understanding and experimenting with real-world authentication hardening techniques.


