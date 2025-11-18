import datetime
from geo import get_geo   # ← NEW IMPORT
from math import radians, sin, cos, sqrt, atan2

# Fake list of suspicious IPs
BAD_IPS = {"123.45.67.89", "66.66.66.66"}

def calculate_distance(lat1, lon1, lat2, lon2):
    """Returns distance between two GPS points in km using haversine formula."""
    R = 6371  # Earth radius in km

    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])

    dlon = lon2 - lon1
    dlat = lat2 - lat1

    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))

    return R * c

def calculate_risk(username, ip, known_locations, user_agent, failed_attempts):
    risk = 0
    reasons = []

    # ---------------------------
    # GET GEOLOCATION OF CURRENT LOGIN
    # ---------------------------
    geo_now = get_geo(ip)
    country_now = geo_now.get("country")
    city_now = geo_now.get("city")
    isp_now = geo_now.get("isp")

    user_known_locs = known_locations.get(username, [])

    # ---------------------------
    # 1. LOCATION-BASED RISK
    # ---------------------------

    # No stored locations → first login on new device
    if not user_known_locs:
        risk += 20
        reasons.append("First-time login from any location")

    else:
        # Check if IP has been seen before
        if not any(loc["ip"] == ip for loc in user_known_locs):
            risk += 15
            reasons.append("New IP address")

        # Check for new CITY
        if city_now and not any(loc["city"] == city_now for loc in user_known_locs):
            risk += 20
            reasons.append("Login from new city")

        # Check for new COUNTRY
        if country_now and not any(loc["country"] == country_now for loc in user_known_locs):
            risk += 40
            reasons.append("Login from new country")

        # Check for new ISP (common sign of VPN)
        if isp_now and not any(loc["isp"] == isp_now for loc in user_known_locs):
            risk += 15
            reasons.append("Unusual ISP detected (possible VPN)")

    # ---------------------------
    # 1B. IMPOSSIBLE TRAVEL RISK
    # ---------------------------
    if user_known_locs:

        last_loc = user_known_locs[-1]

        if last_loc.get("lat") and geo_now.get("lat"):

            # Distance in km
            dist = calculate_distance(
                last_loc["lat"], last_loc["lon"],
                geo_now["lat"], geo_now["lon"]
            )

            # Time difference in hours
            t1 = datetime.datetime.fromisoformat(last_loc["timestamp"])
            t2 = datetime.datetime.now()
            hours = (t2 - t1).total_seconds() / 3600

            if hours > 0:
                speed = dist / hours   # km/h

                # Commercial jets average ~850-900 km/h
                if speed > 900:
                    risk += 50
                    reasons.append(
                        f"Impossible travel detected: {int(speed)} km/h required"
                    )

    # ---------------------------
    # 2. TIME-BASED RISK
    # ---------------------------
    hour = datetime.datetime.now().hour
    if hour < 6 or hour > 23:
        risk += 10
        reasons.append("Login at unusual hours")

    # ---------------------------
    # 3. DEVICE RISK
    # ---------------------------
    if "Mobile" not in user_agent and "Windows" in user_agent:
        pass  # treat as normal
    else:
        risk += 10
        reasons.append("Unusual device/browser")

    # ---------------------------
    # 4. FAILED ATTEMPTS RISK
    # ---------------------------
    if failed_attempts >= 3:
        risk += 40
        reasons.append("Multiple failed login attempts")

    # ---------------------------
    # 5. BAD IP CHECK
    # ---------------------------
    if ip in BAD_IPS:
        risk += 80
        reasons.append("IP flagged as suspicious/malicious")

    return risk, reasons
