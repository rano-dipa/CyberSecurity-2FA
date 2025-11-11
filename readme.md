# Enhanced Two-Factor Authentication with Location and QR-Based Verification

## Project Overview
Traditional Two-Factor Authentication (2FA) systems strengthen password-based security but still face vulnerabilities such as phishing attacks, SIM swapping, and unauthorized access from unfamiliar locations or devices.  
This project proposes an Enhanced 2FA System that adds context-aware verification and QR-based confirmation to improve both security and usability.

---

## Key Features
1. **Location-Aware Authentication**  
   - The system verifies the user’s login location (via IP address or Wi-Fi SSID).  
   - If the login originates from an unfamiliar or suspicious location, an additional verification step is triggered.  
   - This introduces adaptive, context-based security.

2. **QR Code Confirmation**  
   - When logging in from a desktop or web interface, a unique QR code is generated.  
   - The user scans this QR code using their registered mobile device to confirm the login attempt.  
   - Ensures that only the trusted device holder can approve access, reducing phishing risk.

---

## Project Goals
- Strengthen authentication by integrating environmental context (location).  
- Prevent unauthorized access from unfamiliar networks or devices.  
- Streamline verification using a fast and intuitive QR scan method.  
- Demonstrate a lightweight and practical security prototype.

---

## Current Progress
- Flask backend initialized with a `/login` route and IP address logging.  
- Basic web frontend created for login and QR display.  
- Static QR code generation implemented using Python’s `qrcode` library.  
- GitHub repository and documentation setup for collaborative development.

---

## Tech Stack
- **Backend:** Python (Flask)  
- **Frontend:** HTML, CSS, JavaScript  
- **Libraries:** `flask`, `qrcode`, `requests`, `geocoder` (for future location handling)

---

## Team Members and Roles
- **Dipanwita Rano** – Documentation and Frontend Development  
- **Arun Akash Rangaraj** – Backend and Location Verification  
- **Rushil Ravi** – Mobile Development and QR Verification System  

---

## Next Steps
- Implement dynamic QR generation linked to user sessions.  
- Build a mobile interface for scanning and verifying QR codes.  
- Add real-time location-based risk assessment.  
- Integrate all components for end-to-end authentication testing.
