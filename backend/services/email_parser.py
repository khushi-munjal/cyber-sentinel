from email import policy
from email.parser import BytesParser


def _get_header_values(message, header_name):
    """
    Return all values for a header, case-insensitively.

    Example:
        Received
        received
        RECEIVED

    are treated as the same header.
    """

    values = []

    for key, value in message.raw_items():

        if key.lower() == header_name.lower():

            values.append(str(value))

    return values


def _get_first_header(message, header_name):
    """
    Return the first matching header value.
    """

    values = _get_header_values(
        message,
        header_name
    )

    if values:

        return values[0]

    return ""


def _extract_body(message):
    """
    Extract plain-text and HTML body safely.
    """

    body_text = ""
    body_html = ""

    if message.is_multipart():

        for part in message.walk():

            # Ignore multipart containers
            if part.is_multipart():
                continue

            content_type = (
                part.get_content_type()
            )

            disposition = (
                part.get_content_disposition()
            )

            # Do not treat attachments as email body
            if disposition == "attachment":
                continue

            try:

                content = part.get_content()

            except Exception:

                try:

                    payload = part.get_payload(
                        decode=True
                    )

                    if payload:

                        charset = (
                            part.get_content_charset()
                            or "utf-8"
                        )

                        content = payload.decode(
                            charset,
                            errors="replace"
                        )

                    else:

                        content = ""

                except Exception:

                    content = ""

            if content_type == "text/plain":

                body_text += (
                    str(content) + "\n"
                )

            elif content_type == "text/html":

                body_html += (
                    str(content) + "\n"
                )

    else:

        try:

            content = message.get_content()

        except Exception:

            try:

                payload = message.get_payload(
                    decode=True
                )

                if payload:

                    charset = (
                        message.get_content_charset()
                        or "utf-8"
                    )

                    content = payload.decode(
                        charset,
                        errors="replace"
                    )

                else:

                    content = ""

            except Exception:

                content = ""

        if message.get_content_type() == "text/html":

            body_html = str(content)

        else:

            body_text = str(content)

    return body_text, body_html


def _extract_attachments(message):
    """
    Extract attachment metadata.
    """

    attachments = []

    for part in message.iter_attachments():

        filename = part.get_filename()

        if not filename:
            continue

        payload = part.get_payload(
            decode=True
        )

        attachments.append({

            "filename": filename,

            "content_type": (
                part.get_content_type()
            ),

            "size": len(
                payload or b""
            )
        })

    return attachments


def _build_header_dictionary(message):
    """
    Build a forensic-friendly header dictionary.

    Repeated headers such as Received are preserved
    instead of being overwritten.
    """

    headers = {}

    for key, value in message.raw_items():

        normalized_key = key.strip()

        if normalized_key not in headers:

            headers[normalized_key] = []

        headers[normalized_key].append(
            str(value)
        )

    return headers


def parse_email(content: bytes):
    """
    Parse an .eml file and extract forensic email information.

    The parser preserves the original email headers,
    including repeated Received headers.

    No location is assigned here.

    Location is determined later from actual public
    IP addresses extracted from the headers.
    """

    # -----------------------------------------------------
    # Validate input
    # -----------------------------------------------------

    if not content:

        raise ValueError(
            "Email file is empty."
        )

    if not isinstance(content, bytes):

        raise TypeError(
            "Email content must be provided as bytes."
        )

    # -----------------------------------------------------
    # Parse email
    # -----------------------------------------------------

    message = BytesParser(
        policy=policy.default
    ).parsebytes(content)

    # -----------------------------------------------------
    # Basic headers
    # -----------------------------------------------------

    sender = _get_first_header(
        message,
        "From"
    )

    receiver = _get_first_header(
        message,
        "To"
    )

    subject = _get_first_header(
        message,
        "Subject"
    )

    date = _get_first_header(
        message,
        "Date"
    )

    reply_to = _get_first_header(
        message,
        "Reply-To"
    )

    return_path = _get_first_header(
        message,
        "Return-Path"
    )

    message_id = _get_first_header(
        message,
        "Message-ID"
    )

    # -----------------------------------------------------
    # All headers
    # -----------------------------------------------------

    headers = _build_header_dictionary(
        message
    )

    # -----------------------------------------------------
    # Important forensic headers
    # -----------------------------------------------------

    received_headers = _get_header_values(
        message,
        "Received"
    )

    authentication_results = (
        _get_header_values(
            message,
            "Authentication-Results"
        )
    )

    received_spf = _get_header_values(
        message,
        "Received-SPF"
    )

    dkim_signatures = _get_header_values(
        message,
        "DKIM-Signature"
    )

    # -----------------------------------------------------
    # Body
    # -----------------------------------------------------

    body_text, body_html = _extract_body(
        message
    )

    # -----------------------------------------------------
    # Attachments
    # -----------------------------------------------------

    attachments = _extract_attachments(
        message
    )

    # -----------------------------------------------------
    # Final parsed object
    # -----------------------------------------------------

    return {

        # Basic information
        "sender": sender,
        "receiver": receiver,
        "subject": subject,
        "date": date,

        # Addressing
        "reply_to": reply_to,
        "return_path": return_path,

        # Identification
        "message_id": message_id,

        # Content
        "body_text": body_text,
        "body_html": body_html,

        # Complete headers
        "headers": headers,

        # Explicit forensic headers
        "received_headers": received_headers,

        "authentication_results": (
            authentication_results
        ),

        "received_spf": received_spf,

        "dkim_signatures": (
            dkim_signatures
        ),

        # Attachments
        "attachments": attachments,

        # Useful metadata
        "received_hops": len(
            received_headers
        ),

        "has_html": bool(
            body_html.strip()
        ),

        "has_attachments": bool(
            attachments
        )
    }

