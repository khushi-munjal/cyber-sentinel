import ipaddress


# ---------------------------------------------------------
# DEMO GEO INTELLIGENCE
# ---------------------------------------------------------
# These locations are controlled demo locations.
# They are NOT claimed as the exact physical location
# of the sender.
# ---------------------------------------------------------

DEMO_LOCATIONS = {
    "bank-alert.example": {
        "city": "Delhi",
        "region": "Delhi",
        "country": "India",
        "latitude": 28.6139,
        "longitude": 77.2090,
        "isp": "Demo Banking Infrastructure"
    },
"ceo-office.example": {
    "city": "London",
    "region": "England",
    "country": "United Kingdom",
    "latitude": 51.5074,
    "longitude": -0.1278,
    "isp": "Demo International Corporate Infrastructure"
},

"college.example": {
    "city": "Panipat",
    "region": "Haryana",
    "country": "India",
    "latitude": 29.3909,
    "longitude": 76.9635,
    "isp": "Demo Educational Infrastructure"
},

"account-security.example": {
    "city": "Samalkha",
    "region": "Haryana",
    "country": "India",
    "latitude": 29.2350,
    "longitude": 77.1500,
    "isp": "Demo Security Infrastructure"
},
    "secure-login.example": {
        "city": "Mumbai",
        "region": "Maharashtra",
        "country": "India",
        "latitude": 19.0760,
        "longitude": 72.8777,
        "isp": "Demo Cloud Infrastructure"
    },

    "executive-office.example": {
        "city": "Bengaluru",
        "region": "Karnataka",
        "country": "India",
        "latitude": 12.9716,
        "longitude": 77.5946,
        "isp": "Demo Corporate Infrastructure"
    },

    "bank-security.example": {
        "city": "Hyderabad",
        "region": "Telangana",
        "country": "India",
        "latitude": 17.3850,
        "longitude": 78.4867,
        "isp": "Demo Financial Infrastructure"
    },

    "refund-center.example": {
        "city": "Chennai",
        "region": "Tamil Nadu",
        "country": "India",
        "latitude": 13.0827,
        "longitude": 80.2707,
        "isp": "Demo Payment Infrastructure"
    },

    "invoice-docs.example": {
        "city": "Pune",
        "region": "Maharashtra",
        "country": "India",
        "latitude": 18.5204,
        "longitude": 73.8567,
        "isp": "Demo Hosting Infrastructure"
    },

    "support-desk.example": {
        "city": "Kolkata",
        "region": "West Bengal",
        "country": "India",
        "latitude": 22.5726,
        "longitude": 88.3639,
        "isp": "Demo Support Infrastructure"
    },

    "ceo-office.example": {
        "city": "Jaipur",
        "region": "Rajasthan",
        "country": "India",
        "latitude": 26.9124,
        "longitude": 75.7873,
        "isp": "Demo Corporate Infrastructure"
    },

    "college.example": {
        "city": "Chandigarh",
        "region": "Chandigarh",
        "country": "India",
        "latitude": 30.7333,
        "longitude": 76.7794,
        "isp": "Demo Educational Infrastructure"
    },

    "account-security.example": {
        "city": "Ahmedabad",
        "region": "Gujarat",
        "country": "India",
        "latitude": 23.0225,
        "longitude": 72.5714,
        "isp": "Demo Security Infrastructure"
    }
}


def is_public_ip(ip):
    """
    Check whether an IP address is publicly routable.
    """

    try:

        address = ipaddress.ip_address(
            ip
        )

        return (
            not address.private
            and not address.loopback
            and not address.reserved
            and not address.is_multicast
        )

    except ValueError:

        return False


def get_demo_location(domain):
    """
    Return controlled demo location
    based on the email infrastructure domain.
    """

    domain = str(
        domain
    ).lower().strip()

    if domain in DEMO_LOCATIONS:

        location = DEMO_LOCATIONS[
            domain
        ].copy()

        location["source"] = "MailTrace AI Demo Geo Dataset"

        location["precision"] = (
            "City-level demo intelligence"
        )

        location["demo_mode"] = True

        return location

    return None


def get_geo_intelligence(
    ip_addresses=None,
    domains=None
):
    """
    Generate geo-intelligence for an email.

    Demo domains have deterministic locations.
    Real IPs are classified for public/private status,
    but exact physical location is NOT inferred.
    """

    if ip_addresses is None:

        ip_addresses = []

    if domains is None:

        domains = []

    ip_results = []

    public_ips = []

    private_ips = []

    for ip in ip_addresses:

        if is_public_ip(ip):

            public_ips.append(ip)

            ip_results.append({
                "ip": ip,
                "type": "PUBLIC",
                "location_available": False,
                "message": (
                    "Public IP detected. "
                    "External IP geolocation can be "
                    "used for enrichment."
                )
            })

        else:

            private_ips.append(ip)

            ip_results.append({
                "ip": ip,
                "type": "PRIVATE_OR_RESERVED",
                "location_available": False,
                "message": (
                    "Private, reserved or non-routable "
                    "IP address."
                )
            })


    # -------------------------------------------------
    # DEMO DOMAIN MATCH
    # -------------------------------------------------

    demo_location = None

    for domain in domains:

        demo_location = get_demo_location(
            domain
        )

        if demo_location:

            break


    # -------------------------------------------------
    # FINAL GEO RESULT
    # -------------------------------------------------

    if demo_location:

        return {
            "available": True,
            "mode": "DEMO",
            "location": demo_location,
            "ip_analysis": {
                "total_ips": len(
                    ip_addresses
                ),
                "public_ips": public_ips,
                "private_ips": private_ips
            },
            "message": (
                "Controlled demo geo-intelligence "
                "location returned for reliable "
                "jury demonstration."
            ),
            "precision_policy": (
                "Location represents city-level "
                "infrastructure intelligence and "
                "does not claim an exact physical "
                "sender location."
            )
        }


    # -------------------------------------------------
    # NO DEMO LOCATION
    # -------------------------------------------------

    if public_ips:

        return {
            "available": True,
            "mode": "IP_ANALYSIS",
            "location": None,
            "ip_analysis": {
                "total_ips": len(
                    ip_addresses
                ),
                "public_ips": public_ips,
                "private_ips": private_ips
            },
            "message": (
                "Public IP infrastructure detected. "
                "External geolocation enrichment "
                "can be performed."
            ),
            "precision_policy": (
                "Exact physical location is not "
                "inferred from an IP address."
            )
        }


    return {
        "available": False,
        "mode": "UNAVAILABLE",
        "location": None,
        "ip_analysis": {
            "total_ips": len(
                ip_addresses
            ),
            "public_ips": [],
            "private_ips": private_ips
        },
        "message": (
            "No geolocation-ready public "
            "infrastructure detected."
        ),
        "precision_policy": (
            "No exact physical location "
            "is inferred."
        )
    }