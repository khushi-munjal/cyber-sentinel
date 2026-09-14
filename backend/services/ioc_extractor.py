import re
import hashlib


def extract_iocs(email_data):
    """
    Extract Indicators of Compromise (IOCs)
    from email headers, body and HTML content.
    """

    body_text = email_data.get("body_text", "")
    body_html = email_data.get("body_html", "")

    sender = email_data.get("sender", "")
    receiver = email_data.get("receiver", "")

    headers = email_data.get("headers", {})

    all_text = " ".join([
        body_text,
        body_html,
        sender,
        receiver
    ])

    for key, values in headers.items():
        all_text += " " + " ".join(values)

    # -------------------------------------------------
    # EMAIL ADDRESSES
    # -------------------------------------------------

    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

    emails = re.findall(email_pattern, all_text)

    emails = sorted(set(
        email.lower()
        for email in emails
    ))

    # -------------------------------------------------
    # IP ADDRESSES
    # -------------------------------------------------

    ip_pattern = (
        r"\b(?:"
        r"25[0-5]|"
        r"2[0-4][0-9]|"
        r"1[0-9]{2}|"
        r"[1-9]?[0-9]"
        r")"
        r"(?:\.(?:"
        r"25[0-5]|"
        r"2[0-4][0-9]|"
        r"1[0-9]{2}|"
        r"[1-9]?[0-9]"
        r")){3}\b"
    )

    ip_addresses = re.findall(
        ip_pattern,
        all_text
    )

    ip_addresses = sorted(set(ip_addresses))

    # -------------------------------------------------
    # URLS
    # -------------------------------------------------

    url_pattern = r"https?://[^\s<>'\"]+"

    urls = re.findall(
        url_pattern,
        all_text,
        flags=re.IGNORECASE
    )

    cleaned_urls = []

    for url in urls:

        url = url.rstrip(
            ".,;:!?)]}>"
        )

        if url not in cleaned_urls:
            cleaned_urls.append(url)

    urls = cleaned_urls

    # -------------------------------------------------
    # DOMAINS
    # -------------------------------------------------

    domain_pattern = (
        r"\b(?:"
        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
        r"[A-Za-z0-9])?\."
        r")+"
        r"[A-Za-z]{2,63}\b"
    )

    domains = re.findall(
        domain_pattern,
        all_text
    )

    domains = sorted(set(
        domain.lower()
        for domain in domains
    ))

    # Remove common false positives
    ignored_domains = {
        "example.com",
        "localhost",
        "w3.org"
    }

    domains = [
        domain
        for domain in domains
        if domain not in ignored_domains
    ]

    # -------------------------------------------------
    # HASHES
    # -------------------------------------------------

    md5_pattern = r"\b[a-fA-F0-9]{32}\b"

    sha1_pattern = r"\b[a-fA-F0-9]{40}\b"

    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

    md5_hashes = sorted(set(
        re.findall(
            md5_pattern,
            all_text
        )
    ))

    sha1_hashes = sorted(set(
        re.findall(
            sha1_pattern,
            all_text
        )
    ))

    sha256_hashes = sorted(set(
        re.findall(
            sha256_pattern,
            all_text
        )
    ))

    # -------------------------------------------------
    # ATTACHMENT HASHES
    # -------------------------------------------------

    attachment_hashes = []

    for attachment in email_data.get(
        "attachments",
        []
    ):

        attachment_content = attachment.get(
            "content",
            b""
        )

        if isinstance(
            attachment_content,
            bytes
        ):

            attachment_hashes.append({
                "filename": attachment.get(
                    "filename",
                    "unknown"
                ),
                "md5": hashlib.md5(
                    attachment_content
                ).hexdigest(),
                "sha256": hashlib.sha256(
                    attachment_content
                ).hexdigest()
            })

    # -------------------------------------------------
    # IOC SUMMARY
    # -------------------------------------------------

    total_iocs = (
        len(emails)
        + len(ip_addresses)
        + len(urls)
        + len(domains)
        + len(md5_hashes)
        + len(sha1_hashes)
        + len(sha256_hashes)
    )

    return {
        "emails": emails,

        "ip_addresses": ip_addresses,

        "urls": urls,

        "domains": domains,

        "hashes": {
            "md5": md5_hashes,
            "sha1": sha1_hashes,
            "sha256": sha256_hashes
        },

        "attachment_hashes": attachment_hashes,

        "summary": {
            "email_count": len(emails),
            "ip_count": len(ip_addresses),
            "url_count": len(urls),
            "domain_count": len(domains),
            "md5_count": len(md5_hashes),
            "sha1_count": len(sha1_hashes),
            "sha256_count": len(sha256_hashes),
            "total_iocs": total_iocs
        }
    }