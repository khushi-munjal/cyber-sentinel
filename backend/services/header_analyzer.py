import re
import ipaddress
from email.utils import parseaddr


# IPv4 and IPv6 extraction pattern
IP_PATTERN = re.compile(
    r"\b(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}"
    r")\b"
)


def extract_ips_from_text(text):
    """
    Extract valid IP addresses from a header string.
    """

    if not text:
        return []

    found_ips = []

    for match in IP_PATTERN.findall(str(text)):

        try:
            ip = ipaddress.ip_address(match)

            if str(ip) not in found_ips:
                found_ips.append(str(ip))

        except ValueError:
            continue

    return found_ips


def is_public_ip(ip):
    """
    Check whether an IP is publicly routable.

    Private, loopback, link-local and reserved addresses
    are not useful for external geolocation.
    """

    try:
        address = ipaddress.ip_address(ip)

        return (
            not address.is_private
            and not address.is_loopback
            and not address.is_link_local
            and not address.is_reserved
            and not address.is_multicast
        )

    except ValueError:
        return False


def analyze_headers(email_data):
    """
    Analyze email headers for forensic indicators.

    This function:
    - analyzes sender/reply-to/return-path
    - checks SPF/DKIM/DMARC
    - preserves the Received chain
    - extracts IP addresses from Received headers
    - identifies publicly routable IPs

    IMPORTANT:
    IP geolocation is NOT performed here.
    The extracted public IP is passed to geo_service.py.
    """

    headers = email_data.get("headers", {})

    sender = email_data.get("sender", "")
    receiver = email_data.get("receiver", "")
    reply_to = email_data.get("reply_to", "")
    return_path = email_data.get("return_path", "")

    received_headers = headers.get("Received", [])

    authentication_results = headers.get(
        "Authentication-Results", []
    )

    spf_headers = headers.get(
        "Received-SPF", []
    )

    dkim_headers = headers.get(
        "DKIM-Signature", []
    )

    # ---------------------------------------------------------
    # Normalize headers
    # ---------------------------------------------------------

    if isinstance(received_headers, str):
        received_headers = [received_headers]

    if isinstance(authentication_results, str):
        authentication_results = [authentication_results]

    if isinstance(spf_headers, str):
        spf_headers = [spf_headers]

    if isinstance(dkim_headers, str):
        dkim_headers = [dkim_headers]

    # ---------------------------------------------------------
    # DMARC headers
    # ---------------------------------------------------------

    dmarc_headers = []

    for key, values in headers.items():

        if "DMARC" in key.upper():

            if isinstance(values, list):
                dmarc_headers.extend(values)

            else:
                dmarc_headers.append(values)

    # ---------------------------------------------------------
    # Parse email addresses
    # ---------------------------------------------------------

    sender_email = parseaddr(sender)[1].lower()
    reply_to_email = parseaddr(reply_to)[1].lower()
    return_path_email = parseaddr(return_path)[1].lower()

    sender_domain = ""
    reply_to_domain = ""
    return_path_domain = ""

    if "@" in sender_email:
        sender_domain = sender_email.split("@")[-1]

    if "@" in reply_to_email:
        reply_to_domain = reply_to_email.split("@")[-1]

    if "@" in return_path_email:
        return_path_domain = return_path_email.split("@")[-1]

    # ---------------------------------------------------------
    # Anomalies
    # ---------------------------------------------------------

    anomalies = []

    # Reply-To mismatch
    if reply_to_email and sender_email:

        if reply_to_domain != sender_domain:

            anomalies.append({
                "type": "Reply-To Mismatch",
                "severity": "HIGH",
                "message": (
                    "Reply-To domain differs from sender domain."
                )
            })

    # Return-Path mismatch
    if return_path_email and sender_email:

        if return_path_domain != sender_domain:

            anomalies.append({
                "type": "Return-Path Mismatch",
                "severity": "MEDIUM",
                "message": (
                    "Return-Path domain differs from sender domain."
                )
            })

    # ---------------------------------------------------------
    # Authentication analysis
    # ---------------------------------------------------------

    authentication_text = " ".join(
        str(x) for x in authentication_results
    ).lower()

    spf_status = "NOT_FOUND"
    dkim_status = "NOT_FOUND"
    dmarc_status = "NOT_FOUND"

    # SPF
    if "spf=pass" in authentication_text:

        spf_status = "PASS"

    elif "spf=fail" in authentication_text:

        spf_status = "FAIL"

    elif spf_headers:

        spf_text = " ".join(
            str(x) for x in spf_headers
        ).lower()

        if "pass" in spf_text:

            spf_status = "PASS"

        elif "fail" in spf_text:

            spf_status = "FAIL"

    # DKIM
    if "dkim=pass" in authentication_text:

        dkim_status = "PASS"

    elif "dkim=fail" in authentication_text:

        dkim_status = "FAIL"

    elif dkim_headers:

        dkim_status = "PRESENT"

    # DMARC
    if "dmarc=pass" in authentication_text:

        dmarc_status = "PASS"

    elif "dmarc=fail" in authentication_text:

        dmarc_status = "FAIL"

    elif dmarc_headers:

        dmarc_status = "PRESENT"

    # ---------------------------------------------------------
    # Authentication anomalies
    # ---------------------------------------------------------

    if spf_status == "FAIL":

        anomalies.append({
            "type": "SPF Failure",
            "severity": "HIGH",
            "message": "SPF authentication failed."
        })

    if dkim_status == "FAIL":

        anomalies.append({
            "type": "DKIM Failure",
            "severity": "HIGH",
            "message": "DKIM authentication failed."
        })

    if dmarc_status == "FAIL":

        anomalies.append({
            "type": "DMARC Failure",
            "severity": "HIGH",
            "message": "DMARC authentication failed."
        })

    # ---------------------------------------------------------
    # Received chain + IP extraction
    # ---------------------------------------------------------

    received_chain = []

    all_received_ips = []
    public_ips = []

    for received in received_headers:

        received_text = str(received)

        extracted_ips = extract_ips_from_text(
            received_text
        )

        public_received_ips = [
            ip for ip in extracted_ips
            if is_public_ip(ip)
        ]

        received_chain.append({
            "header": received_text,
            "ips": extracted_ips,
            "public_ips": public_received_ips
        })

        for ip in extracted_ips:

            if ip not in all_received_ips:
                all_received_ips.append(ip)

        for ip in public_received_ips:

            if ip not in public_ips:
                public_ips.append(ip)

    # ---------------------------------------------------------
    # Select candidate source IP
    # ---------------------------------------------------------

    # The first public IP encountered in the Received chain
    # is used as the initial candidate.
    #
    # IMPORTANT:
    # This is a candidate infrastructure IP, NOT proof of
    # the physical location of the sender.

    source_ip = public_ips[0] if public_ips else None

    # ---------------------------------------------------------
    # Result
    # ---------------------------------------------------------

    return {

        "sender": sender,
        "receiver": receiver,
        "reply_to": reply_to,
        "return_path": return_path,

        "sender_domain": sender_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,

        "authentication": {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status
        },

        "received_chain": received_chain,

        "received_hops": len(received_chain),

        # All IPs found in Received headers
        "extracted_ips": all_received_ips,

        # Only publicly routable IPs
        "public_ips": public_ips,

        # Candidate IP for GeoIP lookup
        "source_ip": source_ip,

        "anomalies": anomalies,

        "anomaly_count": len(anomalies),

        "forensic_status": (
            "SUSPICIOUS"
            if anomalies
            else "NO_MAJOR_HEADER_ANOMALY"
        )
    }
