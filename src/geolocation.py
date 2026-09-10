import requests
import ipaddress


def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
    except ValueError:
        return False


def get_ip_location(ip):
    if is_private_ip(ip):
        return {
            "ip": ip,
            "type": "Private IP",
            "country": "Private Network",
            "city": "Internal Relay",
            "region": "Local",
            "organization": "RFC 1918 Private Subnet",
            "latitude": None,
            "longitude": None
        }

    # Primary: ip-api.com (fast, free, standard for SIH26106)
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,org,as"
        response = requests.get(url, timeout=4)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "type": "Public IP",
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "organization": data.get("org") or data.get("as") or "Unknown",
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon")
                }
    except Exception:
        pass

    # Secondary fallback: ipapi.co
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=4)
        if response.status_code == 200:
            data = response.json()
            return {
                "ip": ip,
                "type": "Public IP",
                "country": data.get("country_name", "Unknown"),
                "city": data.get("city", "Unknown"),
                "region": data.get("region", "Unknown"),
                "organization": data.get("org", "Unknown"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude")
            }
    except Exception as e:
        return {
            "ip": ip,
            "type": "Public IP",
            "country": "Unavailable",
            "city": "Unavailable",
            "region": "Unavailable",
            "organization": "Unavailable",
            "latitude": None,
            "longitude": None,
            "error": str(e)
        }

    return {
        "ip": ip,
        "type": "Public IP",
        "country": "Unavailable",
        "city": "Unavailable",
        "region": "Unavailable",
        "organization": "Unavailable",
        "latitude": None,
        "longitude": None
    }