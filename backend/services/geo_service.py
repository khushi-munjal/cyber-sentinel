import ipaddress
import os
import requests


# =========================================================
# GEOLOCATION CONFIGURATION
# =========================================================

# GeoIP provider.
#
# This implementation uses ip-api.com for demonstration.
# It does NOT use any hardcoded email/domain locations.
#
# If you later want to use another provider, only this
# service needs to be changed.

GEO_API_URL = "http://ip-api.com/json/{ip}"

GEO_API_TIMEOUT = 5


# =========================================================
# IP VALIDATION
# =========================================================

def is_public_ip(ip):
    """
    Check whether an IP address is publicly routable.
    """

    try:

        address = ipaddress.ip_address(str(ip).strip())

        return address.is_global

    except ValueError:

        return False


# =========================================================
# SINGLE IP GEOLOCATION
# =========================================================

def geolocate_ip(ip):
    """
    Perform approximate geolocation of a public IP.

    Returns city/region/country information when the
    external GeoIP provider has data for the IP.

    IMPORTANT:
    This represents approximate IP infrastructure
    location, NOT the exact physical location of
    the sender.
    """

    result = {
        "ip": ip,
        "available": False,
        "city": None,
        "region": None,
        "country": None,
        "country_code": None,
        "latitude": None,
        "longitude": None,
        "isp": None,
        "organization": None,
        "timezone": None,
        "source": None,
        "precision": "APPROXIMATE",
        "message": None
    }

    # -----------------------------------------------------
    # Validate IP
    # -----------------------------------------------------

    if not is_public_ip(ip):

        result["message"] = (
            "IP is private, reserved, loopback, "
            "or otherwise not publicly routable."
        )

        return result

    # -----------------------------------------------------
    # GeoIP request
    # -----------------------------------------------------

    try:

        url = GEO_API_URL.format(
            ip=str(ip).strip()
        )

        response = requests.get(
            url,
            timeout=GEO_API_TIMEOUT
        )

        response.raise_for_status()

        data = response.json()

        # -------------------------------------------------
        # Provider response validation
        # -------------------------------------------------

        if data.get("status") != "success":

            result["message"] = (
                data.get(
                    "message",
                    "GeoIP provider could not locate this IP."
                )
            )

            return result

        # -------------------------------------------------
        # Extract location
        # -------------------------------------------------

        result["available"] = True

        result["city"] = data.get("city")

        result["region"] = data.get("regionName")

        result["country"] = data.get("country")

        result["country_code"] = data.get("countryCode")

        result["latitude"] = data.get("lat")

        result["longitude"] = data.get("lon")

        result["isp"] = data.get("isp")

        result["organization"] = data.get("org")

        result["timezone"] = data.get("timezone")

        result["source"] = "IP Geolocation"

        result["precision"] = "APPROXIMATE"

        result["message"] = (
            "Approximate location obtained from "
            "public IP geolocation."
        )

        return result

    except requests.Timeout:

        result["message"] = (
            "GeoIP request timed out."
        )

        return result

    except requests.RequestException as error:

        result["message"] = (
            f"GeoIP request failed: {str(error)}"
        )

        return result

    except Exception as error:

        result["message"] = (
            f"Unexpected geolocation error: {str(error)}"
        )

        return result


# =========================================================
# MULTIPLE IP GEOLOCATION
# =========================================================

def get_geo_intelligence(
    ip_addresses=None,
    domains=None
):
    """
    Generate geo-intelligence from actual IP addresses
    extracted from the uploaded email.

    `domains` is retained in the function signature for
    compatibility with the existing backend, but domains
    are NOT used to invent or determine a location.

    No demo locations are used.
    """

    if ip_addresses is None:

        ip_addresses = []

    if domains is None:

        domains = []

    # -----------------------------------------------------
    # Remove duplicates
    # -----------------------------------------------------

    unique_ips = list(
        dict.fromkeys(
            str(ip).strip()
            for ip in ip_addresses
            if ip
        )
    )

    public_ips = []
    non_public_ips = []

    geo_results = []

    # -----------------------------------------------------
    # Classify IPs
    # -----------------------------------------------------

    for ip in unique_ips:

        if is_public_ip(ip):

            public_ips.append(ip)

        else:

            non_public_ips.append(ip)

    # -----------------------------------------------------
    # Geolocate public IPs
    # -----------------------------------------------------

    for ip in public_ips:

        geo_result = geolocate_ip(ip)

        geo_results.append(
            geo_result
        )

    # -----------------------------------------------------
    # Select best available location
    # -----------------------------------------------------

    selected_location = None
    selected_ip = None

    for result in geo_results:

        if result.get("available"):

            selected_location = {
                "city": result.get("city"),
                "region": result.get("region"),
                "country": result.get("country"),
                "country_code": result.get("country_code"),
                "latitude": result.get("latitude"),
                "longitude": result.get("longitude"),
                "isp": result.get("isp"),
                "organization": result.get("organization"),
                "timezone": result.get("timezone"),
                "source": "IP Geolocation",
                "precision": "Approximate",
                "demo_mode": False
            }

            selected_ip = result.get("ip")

            break

    # -----------------------------------------------------
    # LOCATION FOUND
    # -----------------------------------------------------

    if selected_location:

        return {

            "available": True,

            "mode": "IP_GEOLOCATION",

            "source_ip": selected_ip,

            "location": selected_location,

            "locations": geo_results,

            "ip_analysis": {

                "total_ips": len(unique_ips),

                "public_ips": public_ips,

                "non_public_ips": non_public_ips,

                "public_ip_count": len(public_ips),

                "non_public_ip_count": len(
                    non_public_ips
                )
            },

            "message": (
                "Approximate source infrastructure "
                "location obtained from the public "
                "IP found in the email headers."
            ),

            "precision_policy": (
                "IP geolocation provides an approximate "
                "network/infrastructure location. It "
                "does not establish the exact physical "
                "location of the sender."
            ),

            "demo_mode": False
        }

    # -----------------------------------------------------
    # PUBLIC IP EXISTS BUT GEOLOCATION FAILED
    # -----------------------------------------------------

    if public_ips:

        return {

            "available": False,

            "mode": "IP_GEOLOCATION_UNAVAILABLE",

            "source_ip": public_ips[0],

            "location": None,

            "locations": geo_results,

            "ip_analysis": {

                "total_ips": len(unique_ips),

                "public_ips": public_ips,

                "non_public_ips": non_public_ips,

                "public_ip_count": len(public_ips),

                "non_public_ip_count": len(
                    non_public_ips
                )
            },

            "message": (
                "A public IP was found in the email "
                "headers, but its approximate location "
                "could not be obtained."
            ),

            "precision_policy": (
                "No location is invented when the "
                "GeoIP provider has insufficient data."
            ),

            "demo_mode": False
        }

    # -----------------------------------------------------
    # NO PUBLIC IP
    # -----------------------------------------------------

    return {

        "available": False,

        "mode": "UNAVAILABLE",

        "source_ip": None,

        "location": None,

        "locations": [],

        "ip_analysis": {

            "total_ips": len(unique_ips),

            "public_ips": [],

            "non_public_ips": non_public_ips,

            "public_ip_count": 0,

            "non_public_ip_count": len(
                non_public_ips
            )
        },

        "message": (
            "No publicly routable IP address was "
            "available in the analyzed email headers."
        ),

        "precision_policy": (
            "No sender location is inferred when "
            "a usable public IP is unavailable."
        ),

        "demo_mode": False
    }

