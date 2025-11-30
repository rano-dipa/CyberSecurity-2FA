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
```

Install:
```
pip install flask requests
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