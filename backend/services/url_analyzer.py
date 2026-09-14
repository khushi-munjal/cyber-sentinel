from urllib.parse import urlparse
import re


SHORTENING_SERVICES = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at"
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "verification",
    "account",
    "password",
    "secure",
    "security",
    "update",
    "confirm",
    "bank",
    "payment",
    "wallet",
    "invoice",
    "refund",
    "credential",
    "otp"
}


def analyze_url(url):
    """
    Analyze a URL for basic phishing and
    suspicious infrastructure indicators.
    """

    result = {
        "url": url,
        "protocol": "",
        "domain": "",
        "path": "",
        "query": "",
        "is_https": False,
        "is_ip_url": False,
        "is_shortened": False,
        "suspicious_keywords": [],
        "risk_score": 0,
        "risk_level": "LOW",
        "findings": []
    }

    try:
        parsed = urlparse(url)

        protocol = parsed.scheme.lower()
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()

        result["protocol"] = protocol
        result["domain"] = domain
        result["path"] = path
        result["query"] = query

        result["is_https"] = protocol == "https"

        # Remove username/password if present
        clean_domain = domain.split("@")[-1]

        # Remove port
        clean_domain = clean_domain.split(":")[0]

        # -------------------------------------------------
        # IP ADDRESS URL
        # -------------------------------------------------

        ip_pattern = (
            r"^(?:"
            r"25[0-5]|"
            r"2[0-4][0-9]|"
            r"1[0-9]{2}|"
            r"[1-9]?[0-9]"
            r")(?:\.(?:"
            r"25[0-5]|"
            r"2[0-4][0-9]|"
            r"1[0-9]{2}|"
            r"[1-9]?[0-9]"
            r")){3}$"
        )

        if re.match(ip_pattern, clean_domain):
            result["is_ip_url"] = True

            result["risk_score"] += 30

            result["findings"].append(
                "URL uses a direct IP address instead of a domain."
            )

        # -------------------------------------------------
        # URL SHORTENER
        # -------------------------------------------------

        if clean_domain in SHORTENING_SERVICES:

            result["is_shortened"] = True

            result["risk_score"] += 20

            result["findings"].append(
                "URL uses a URL shortening service."
            )

        # -------------------------------------------------
        # SUSPICIOUS KEYWORDS
        # -------------------------------------------------

        full_url = url.lower()

        detected_keywords = []

        for keyword in SUSPICIOUS_KEYWORDS:

            if keyword in full_url:

                detected_keywords.append(
                    keyword
                )

        result["suspicious_keywords"] = sorted(
            set(detected_keywords)
        )

        if detected_keywords:

            result["risk_score"] += min(
                len(set(detected_keywords)) * 5,
                30
            )

            result["findings"].append(
                "URL contains security or credential-related keywords."
            )

        # -------------------------------------------------
        # HTTP
        # -------------------------------------------------

        if protocol == "http":

            result["risk_score"] += 10

            result["findings"].append(
                "URL does not use HTTPS encryption."
            )

        # -------------------------------------------------
        # EXCESSIVE SUBDOMAINS
        # -------------------------------------------------

        domain_parts = clean_domain.split(".")

        if len(domain_parts) >= 4:

            result["risk_score"] += 10

            result["findings"].append(
                "Domain contains an unusually deep subdomain structure."
            )

        # -------------------------------------------------
        # SUSPICIOUS DOMAIN PATTERNS
        # -------------------------------------------------

        suspicious_domain_patterns = [
            "login-",
            "verify-",
            "secure-",
            "account-",
            "update-",
            "paypal-",
            "bank-",
            "microsoft-",
            "google-",
            "apple-"
        ]

        for pattern in suspicious_domain_patterns:

            if pattern in clean_domain:

                result["risk_score"] += 15

                result["findings"].append(
                    "Domain contains a potentially deceptive brand/security pattern."
                )

                break

        # -------------------------------------------------
        # LONG URL
        # -------------------------------------------------

        if len(url) > 150:

            result["risk_score"] += 5

            result["findings"].append(
                "URL is unusually long."
            )

        # -------------------------------------------------
        # FINAL SCORE
        # -------------------------------------------------

        result["risk_score"] = min(
            result["risk_score"],
            100
        )

        if result["risk_score"] >= 70:

            result["risk_level"] = "HIGH"

        elif result["risk_score"] >= 40:

            result["risk_level"] = "MEDIUM"

        else:

            result["risk_level"] = "LOW"

        return result

    except Exception as error:

        result["risk_level"] = "UNKNOWN"

        result["findings"].append(
            f"URL analysis error: {str(error)}"
        )

        return result


def analyze_urls(urls):
    """
    Analyze multiple URLs.
    """

    results = []

    for url in urls:

        results.append(
            analyze_url(url)
        )

    high_risk_count = sum(
        1
        for item in results
        if item["risk_level"] == "HIGH"
    )

    medium_risk_count = sum(
        1
        for item in results
        if item["risk_level"] == "MEDIUM"
    )

    return {
        "urls": results,
        "total_urls": len(results),
        "high_risk_urls": high_risk_count,
        "medium_risk_urls": medium_risk_count
    }