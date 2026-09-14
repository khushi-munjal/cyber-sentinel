import ipaddress


PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def analyze_ip(ip):
    """
    Analyze an IP address and determine
    whether it is public, private, loopback,
    or reserved.
    """

    result = {
        "ip": ip,
        "valid": False,
        "type": "UNKNOWN",
        "is_public": False,
        "is_private": False,
        "is_loopback": False,
        "is_reserved": False,
        "risk_score": 0,
        "findings": []
    }

    try:
        address = ipaddress.ip_address(ip)

        result["valid"] = True

        result["is_private"] = address.is_private
        result["is_loopback"] = address.is_loopback
        result["is_reserved"] = address.is_reserved

        if address.is_loopback:

            result["type"] = "LOOPBACK"

            result["findings"].append(
                "IP address is a loopback address."
            )

        elif address.is_private:

            result["type"] = "PRIVATE"

            result["findings"].append(
                "IP address belongs to a private network."
            )

        elif address.is_reserved:

            result["type"] = "RESERVED"

            result["findings"].append(
                "IP address belongs to a reserved range."
            )

        elif address.is_global:

            result["type"] = "PUBLIC"

            result["is_public"] = True

            result["findings"].append(
                "Public IP detected and eligible for geo-intelligence enrichment."
            )

        else:

            result["type"] = "SPECIAL"

            result["findings"].append(
                "IP address belongs to a special-use range."
            )

        # -------------------------------------------------
        # RISK SCORE
        # -------------------------------------------------

        if result["is_public"]:
            result["risk_score"] = 10

        elif result["is_private"]:
            result["risk_score"] = 0

        elif result["is_loopback"]:
            result["risk_score"] = 0

        elif result["is_reserved"]:
            result["risk_score"] = 5

        else:
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
    """

    results = []

    for ip in ip_addresses:

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

    return {
        "results": results,
        "total_ips": len(results),
        "public_ips": public_ips,
        "private_ips": private_ips,
        "public_ip_count": len(public_ips),
        "private_ip_count": len(private_ips)
    }