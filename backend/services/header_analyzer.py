from email.utils import parseaddr


def analyze_headers(email_data):
    """
    Analyze email headers for forensic indicators.
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

    spf_headers = headers.get("Received-SPF", [])

    dkim_headers = headers.get("DKIM-Signature", [])

    dmarc_headers = []

    for key, values in headers.items():
        if "DMARC" in key.upper():
            dmarc_headers.extend(values)

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

    anomalies = []

    if reply_to_email and sender_email:
        if reply_to_domain != sender_domain:
            anomalies.append({
                "type": "Reply-To Mismatch",
                "severity": "HIGH",
                "message": (
                    "Reply-To domain differs from sender domain."
                )
            })

    if return_path_email and sender_email:
        if return_path_domain != sender_domain:
            anomalies.append({
                "type": "Return-Path Mismatch",
                "severity": "MEDIUM",
                "message": (
                    "Return-Path domain differs from sender domain."
                )
            })

    authentication_text = " ".join(
        authentication_results
    ).lower()

    spf_status = "NOT_FOUND"
    dkim_status = "NOT_FOUND"
    dmarc_status = "NOT_FOUND"

    if "spf=pass" in authentication_text:
        spf_status = "PASS"
    elif "spf=fail" in authentication_text:
        spf_status = "FAIL"
    elif spf_headers:
        spf_text = " ".join(spf_headers).lower()

        if "pass" in spf_text:
            spf_status = "PASS"
        elif "fail" in spf_text:
            spf_status = "FAIL"

    if "dkim=pass" in authentication_text:
        dkim_status = "PASS"
    elif "dkim=fail" in authentication_text:
        dkim_status = "FAIL"
    elif dkim_headers:
        dkim_status = "PRESENT"

    if "dmarc=pass" in authentication_text:
        dmarc_status = "PASS"
    elif "dmarc=fail" in authentication_text:
        dmarc_status = "FAIL"
    elif dmarc_headers:
        dmarc_status = "PRESENT"

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

    received_chain = []

    for received in received_headers:
        received_chain.append({
            "header": received
        })

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
        "anomalies": anomalies,
        "anomaly_count": len(anomalies),
        "forensic_status": (
            "SUSPICIOUS"
            if anomalies
            else "NO_MAJOR_HEADER_ANOMALY"
        )
    }