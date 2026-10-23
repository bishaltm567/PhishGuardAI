from email import policy
from email.parser import BytesParser

MAX_EML_BYTES = 1_000_000
MAX_PARTS = 100


def parse_eml(data):
    if not data:
        raise ValueError("The uploaded message is empty.")
    if len(data) > MAX_EML_BYTES:
        raise ValueError("EML file must be 1 MB or smaller.")
    message = BytesParser(policy=policy.default).parsebytes(data)
    parts = list(message.walk())
    if len(parts) > MAX_PARTS:
        raise ValueError(f"Message contains too many MIME parts (maximum {MAX_PARTS}).")
    if any(part.defects for part in parts):
        raise ValueError("EML contains malformed message or MIME structure.")
    text_parts = []
    attachment_metadata = []
    for part in parts:
        filename = part.get_filename()
        if filename:
            attachment_metadata.append({"filename": filename[:255], "content_type": part.get_content_type()})
        if part.get_content_type() == "text/plain" and not part.get_content_disposition() == "attachment":
            try:
                content = part.get_content()
                if isinstance(content, str):
                    text_parts.append(content)
            except (LookupError, UnicodeError):
                continue
    auth_headers = "\n".join(message.get_all("Authentication-Results", []))
    return {
        "body": "\n".join(text_parts)[:100_000],
        "authentication_results": auth_headers[:10_000],
        "attachment_metadata": attachment_metadata,
        "subject_present": bool(message.get("Subject")),
        "sender_present": bool(message.get("From")),
    }
