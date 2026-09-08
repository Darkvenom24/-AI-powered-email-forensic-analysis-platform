import requests
import ipaddress


def is_private_ip(ip):

    try:

        return ipaddress.ip_address(
            ip
        ).is_private

    except ValueError:

        return False


def get_ip_location(ip):

    if is_private_ip(ip):

        return {
            "ip": ip,
            "type": "Private IP",
            "country": "N/A",
            "city": "N/A",
            "region": "N/A",
            "organization": "N/A"
        }


    try:

        response = requests.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=10
        )

        response.raise_for_status()

        data = response.json()


        return {

            "ip": ip,

            "type": "Public IP",

            "country": data.get(
                "country_name",
                "Unknown"
            ),

            "city": data.get(
                "city",
                "Unknown"
            ),

            "region": data.get(
                "region",
                "Unknown"
            ),

            "organization": data.get(
                "org",
                "Unknown"
            ),

            "latitude": data.get(
                "latitude"
            ),

            "longitude": data.get(
                "longitude"
            )
        }


    except Exception as e:

        return {

            "ip": ip,

            "type": "Public IP",

            "error": str(e)

        }