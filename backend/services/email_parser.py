from email import policy
from email.parser import BytesParser


def parse_email(content: bytes):
    """
    Parse an .eml file and extract basic email information.
    """

    message = BytesParser(policy=policy.default).parsebytes(content)

    sender = message.get("From", "")
    receiver = message.get("To", "")
    subject = message.get("Subject", "")
    date = message.get("Date", "")
    reply_to = message.get("Reply-To", "")
    return_path = message.get("Return-Path", "")
    message_id = message.get("Message-ID", "")

    headers = {}

    for key, value in message.items():
        if key not in headers:
            headers[key] = []

        headers[key].append(str(value))

    body_text = ""
    body_html = ""

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()

            if content_type == "text/plain":
                try:
                    body_text += part.get_content()
                except Exception:
                    pass

            elif content_type == "text/html":
                try:
                    body_html += part.get_content()
                except Exception:
                    pass

    else:

        try:
            content_type = message.get_content_type()

            if content_type == "text/html":
                body_html = message.get_content()
            else:
                body_text = message.get_content()

        except Exception:
            body_text = ""

    attachments = []

    for part in message.iter_attachments():

        filename = part.get_filename()

        if filename:
            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "size": len(part.get_payload(decode=True) or b"")
            })

    return {
        "sender": sender,
        "receiver": receiver,
        "subject": subject,
        "date": date,
        "reply_to": reply_to,
        "return_path": return_path,
        "message_id": message_id,
        "body_text": body_text,
        "body_html": body_html,
        "headers": headers,
        "attachments": attachments
    }