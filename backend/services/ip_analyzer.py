import ipaddress


def analyze_ip(ip):
    """
    Analyze an IP address.

    Determines whether the IP is:
    - PUBLIC
    - PRIVATE
    - LOOPBACK
    - RESERVED
    - SPECIAL
    - INVALID

    This module does NOT perform geolocation.
    Public IPs can be passed to geo_service.py.
    """

    result = {
        "ip": ip,
        "valid": False,
        "type": "UNKNOWN",
        "is_public": False,
        "is_private": False,
        "is_loopback": False,
        "is_reserved": False,
        "is_global": False,
        "risk_score": 0,
        "geo_eligible": False,
        "findings": []
    }

    try:

        address = ipaddress.ip_address(ip)

        result["valid"] = True

        result["is_private"] = address.is_private
        result["is_loopback"] = address.is_loopback
        result["is_reserved"] = address.is_reserved
        result["is_global"] = address.is_global

        # -------------------------------------------------
        # LOOPBACK
        # -------------------------------------------------

        if address.is_loopback:

            result["type"] = "LOOPBACK"

            result["findings"].append(
                "IP address is a loopback address."
            )

            result["risk_score"] = 0

        # -------------------------------------------------
        # PRIVATE
        # -------------------------------------------------

        elif address.is_private:

            result["type"] = "PRIVATE"

            result["findings"].append(
                "IP address belongs to a private network."
            )

            result["risk_score"] = 0

        # -------------------------------------------------
        # RESERVED
        # -------------------------------------------------

        elif address.is_reserved:

            result["type"] = "RESERVED"

            result["findings"].append(
                "IP address belongs to a reserved range."
            )

            result["risk_score"] = 5

        # -------------------------------------------------
        # PUBLIC / GLOBAL
        # -------------------------------------------------

        elif address.is_global:

            result["type"] = "PUBLIC"

            result["is_public"] = True
            result["geo_eligible"] = True

            result["findings"].append(
                "Public IP detected."
            )

            result["findings"].append(
                "IP is eligible for approximate geolocation."
            )

            # Public IP itself is NOT evidence of maliciousness.
            result["risk_score"] = 0

        # -------------------------------------------------
        # SPECIAL
        # -------------------------------------------------

        else:

            result["type"] = "SPECIAL"

            result["findings"].append(
                "IP address belongs to a special-use range."
            )

            result["risk_score"] = 5

        return result

    except ValueError:

        result["findings"].append(
            "Invalid IP address format."
        )

        return result


def analyze_ips(ip_addresses):
    """
    Analyze multiple IP addresses.

    Returns:
    - individual analysis
    - public IPs
    - private IPs
    - GeoIP-eligible IPs
    """

    results = []

    if not ip_addresses:
        return {
            "results": [],
            "total_ips": 0,
            "public_ips": [],
            "private_ips": [],
            "geo_eligible_ips": [],
            "public_ip_count": 0,
            "private_ip_count": 0
        }

    # Remove duplicates while preserving order
    unique_ips = list(dict.fromkeys(ip_addresses))

    for ip in unique_ips:

        results.append(
            analyze_ip(ip)
        )

    public_ips = [
        item["ip"]
        for item in results
        if item["is_public"]
    ]

    private_ips = [
        item["ip"]
        for item in results
        if item["is_private"]
    ]

    geo_eligible_ips = [
        item["ip"]
        for item in results
        if item["geo_eligible"]
    ]

    return {

        "results": results,

        "total_ips": len(results),

        "public_ips": public_ips,

        "private_ips": private_ips,

        "geo_eligible_ips": geo_eligible_ips,

        "public_ip_count": len(public_ips),

        "private_ip_count": len(private_ips),

        "geo_eligible_count": len(geo_eligible_ips)
    }

