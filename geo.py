import requests

def get_geo(ip):
    """
    Returns geolocation info for the given IP address
    using the free ip-api.com service.
    """
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=2)
        data = response.json()

        if data.get("status") != "success":
            return {
                "country": None,
                "city": None,
                "isp": None
            }

        return {
            "country": data.get("country"),
            "city": data.get("city"),
            "isp": data.get("isp")
        }

    except Exception:
        # In case API is down
        return {
            "country": None,
            "city": None,
            "isp": None
        }
