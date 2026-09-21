import re
import hashlib
import ipaddress


# =========================================================
# REGEX PATTERNS
# =========================================================

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@"
    r"[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b"
)

IP_PATTERN = re.compile(
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

URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"]+",
    flags=re.IGNORECASE
)

# Domain must contain a real dot and a valid TLD.
DOMAIN_PATTERN = re.compile(
    r"\b(?:"
    r"[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"\.)+"
    r"[A-Za-z]{2,63}\b"
)

MD5_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
)

SHA1_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{40}\b"
)

SHA256_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{64}\b"
)


# =========================================================
# COMMON NON-DOMAIN VALUES
# =========================================================

IGNORED_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "localhost",
    "w3.org",
    "schema.org",
    "www.w3.org"
}


# Common file extensions which should never be treated
# as domain TLDs.
FILE_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "webp",
    "ico",
    "css",
    "js",
    "json",
    "xml",
    "html",
    "htm",
    "txt",
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "zip",
    "rar",
    "woff",
    "woff2",
    "ttf",
    "map"
}


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def unique_sorted(values):
    """
    Remove duplicates while preserving clean lowercase values.
    """

    cleaned = []

    for value in values:

        value = str(value).strip().lower()

        if value and value not in cleaned:
            cleaned.append(value)

    return sorted(cleaned)


def is_valid_ipv4(ip):
    """
    Confirm that the extracted IPv4 address is valid.
    """

    try:

        address = ipaddress.ip_address(
            ip
        )

        return address.version == 4

    except ValueError:

        return False


def clean_url(url):
    """
    Remove punctuation accidentally captured at the end
    of URLs.
    """

    if not url:
        return ""

    url = url.strip()

    url = url.rstrip(
        ".,;:!?)]}>\"'"
    )

    return url


def is_valid_domain(domain):
    """
    Validate that a candidate really looks like a domain.

    Prevents values such as:
        footer-mark.png
        row.header
        loose.dtd
        header.from

    from being treated as useful domains.
    """

    if not domain:
        return False

    domain = domain.lower().strip()

    if domain in IGNORED_DOMAINS:
        return False

    # Must contain a dot.
    if "." not in domain:
        return False

    # No consecutive dots.
    if ".." in domain:
        return False

    # Must not contain invalid characters.
    if not re.fullmatch(
        r"[a-z0-9.-]+",
        domain
    ):
        return False

    labels = domain.split(".")

    if len(labels) < 2:
        return False

    # TLD validation.
    tld = labels[-1]

    if len(tld) < 2:
        return False

    # Ignore obvious file extensions.
    if tld in FILE_EXTENSIONS:
        return False

    # Every label must be valid.
    for label in labels:

        if not label:
            return False

        if label.startswith("-"):
            return False

        if label.endswith("-"):
            return False

        if len(label) > 63:
            return False

    return True


# =========================================================
# MAIN IOC EXTRACTION
# =========================================================

def extract_iocs(email_data):
    """
    Extract Indicators of Compromise (IOCs) from:

    - Email body
    - HTML body
    - Sender
    - Receiver
    - Email headers
    - Attachments

    Extracted IOC types:
    - Email addresses
    - IPv4 addresses
    - URLs
    - Domains
    - MD5
    - SHA1
    - SHA256
    - Attachment hashes
    """

    if not isinstance(
        email_data,
        dict
    ):

        email_data = {}

    # =====================================================
    # COLLECT SOURCE TEXT
    # =====================================================

    body_text = str(
        email_data.get(
            "body_text",
            ""
        ) or ""
    )

    body_html = str(
        email_data.get(
            "body_html",
            ""
        ) or ""
    )

    sender = str(
        email_data.get(
            "sender",
            ""
        ) or ""
    )

    receiver = str(
        email_data.get(
            "receiver",
            ""
        ) or ""
    )

    reply_to = str(
        email_data.get(
            "reply_to",
            ""
        ) or ""
    )

    return_path = str(
        email_data.get(
            "return_path",
            ""
        ) or ""
    )

    headers = email_data.get(
        "headers",
        {}
    )

    text_parts = [
        body_text,
        body_html,
        sender,
        receiver,
        reply_to,
        return_path
    ]

    # Add all email headers.
    if isinstance(
        headers,
        dict
    ):

        for key, values in headers.items():

            if isinstance(
                values,
                list
            ):

                text_parts.extend(
                    str(value)
                    for value in values
                    if value
                )

            else:

                text_parts.append(
                    str(values)
                )

    all_text = " ".join(
        text_parts
    )

    # =====================================================
    # EMAIL ADDRESSES
    # =====================================================

    emails = EMAIL_PATTERN.findall(
        all_text
    )

    emails = unique_sorted(
        emails
    )

    # =====================================================
    # IPv4 ADDRESSES
    # =====================================================

    extracted_ips = IP_PATTERN.findall(
        all_text
    )

    ip_addresses = []

    for ip in extracted_ips:

        if is_valid_ipv4(ip):

            if ip not in ip_addresses:

                ip_addresses.append(
                    ip
                )

    ip_addresses = sorted(
        ip_addresses
    )

    # =====================================================
    # URLS
    # =====================================================

    raw_urls = URL_PATTERN.findall(
        all_text
    )

    urls = []

    for url in raw_urls:

        cleaned = clean_url(
            url
        )

        if cleaned and cleaned not in urls:

            urls.append(
                cleaned
            )

    # =====================================================
    # DOMAINS
    # =====================================================

    raw_domains = DOMAIN_PATTERN.findall(
        all_text
    )

    domains = []

    for domain in raw_domains:

        domain = domain.lower().strip()

        # Remove trailing punctuation.
        domain = domain.rstrip(
            ".,;:!?)]}>\"'"
        )

        if not is_valid_domain(
            domain
        ):
            continue

        # If this domain is an obvious part of a URL,
        # it is still a valid IOC and should be retained.

        if domain not in domains:

            domains.append(
                domain
            )

    domains = sorted(
        domains
    )

    # =====================================================
    # HASHES
    # =====================================================

    md5_hashes = unique_sorted(
        MD5_PATTERN.findall(
            all_text
        )
    )

    sha1_hashes = unique_sorted(
        SHA1_PATTERN.findall(
            all_text
        )
    )

    sha256_hashes = unique_sorted(
        SHA256_PATTERN.findall(
            all_text
        )
    )

    # =====================================================
    # ATTACHMENT HASHES
    # =====================================================

    attachment_hashes = []

    attachments = email_data.get(
        "attachments",
        []
    )

    if isinstance(
        attachments,
        list
    ):

        for attachment in attachments:

            if not isinstance(
                attachment,
                dict
            ):
                continue

            attachment_content = attachment.get(
                "content",
                None
            )

            filename = attachment.get(
                "filename",
                "unknown"
            )

            # -------------------------------------------------
            # Current parser may provide metadata only.
            # Hash only when actual bytes are available.
            # -------------------------------------------------

            if isinstance(
                attachment_content,
                bytes
            ):

                attachment_hashes.append({
                    "filename": str(
                        filename
                    ),
                    "md5": hashlib.md5(
                        attachment_content
                    ).hexdigest(),
                    "sha256": hashlib.sha256(
                        attachment_content
                    ).hexdigest()
                })

    # =====================================================
    # TOTAL IOC COUNT
    # =====================================================

    total_iocs = (
        len(emails)
        + len(ip_addresses)
        + len(urls)
        + len(domains)
        + len(md5_hashes)
        + len(sha1_hashes)
        + len(sha256_hashes)
        + len(attachment_hashes)
    )

    # =====================================================
    # SUMMARY
    # =====================================================

    summary = {

        "email_count": len(
            emails
        ),

        "ip_count": len(
            ip_addresses
        ),

        "url_count": len(
            urls
        ),

        "domain_count": len(
            domains
        ),

        "md5_count": len(
            md5_hashes
        ),

        "sha1_count": len(
            sha1_hashes
        ),

        "sha256_count": len(
            sha256_hashes
        ),

        "attachment_hash_count": len(
            attachment_hashes
        ),

        "total_iocs": total_iocs
    }

    # =====================================================
    # FINAL RESULT
    # =====================================================

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

        "summary": summary
    }