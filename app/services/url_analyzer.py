import ipaddress
import re
from urllib.parse import parse_qsl, urlsplit

MAX_URL_LENGTH = 4096
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly", "lnkd.in"}
RISKY_TERMS = {"verify", "signin", "login", "account", "password", "secure", "billing", "wallet"}
REDIRECT_KEYS = {"url", "redirect", "redirect_url", "continue", "return", "next", "target"}


def _finding(name, category, evidence, severity, source="heuristic"):
    return {
        "indicator": name,
        "category": category,
        "evidence": evidence,
        "severity": severity,
        "reliability": "heuristic",
        "source": source,
        "recommended_action": "Review the destination and context independently; this indicator is not proof of maliciousness.",
    }


def analyze_url(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Enter a URL to analyze.")
    value = value.strip()
    if len(value) > MAX_URL_LENGTH:
        raise ValueError(f"URL must be {MAX_URL_LENGTH} characters or fewer.")
    if any(ord(ch) < 32 for ch in value):
        raise ValueError("URL contains control characters.")
    if not re.match(r"^https?://", value, re.IGNORECASE):
        raise ValueError("Enter a complete URL beginning with http:// or https://.")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        if not hostname or parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError
        if parsed.username is not None or parsed.password is not None:
            has_credentials = True
        else:
            has_credentials = False
        try:
            ip_address = ipaddress.ip_address(hostname.strip("[]"))
            ascii_host = ip_address.compressed.lower()
            is_ip = True
        except ValueError:
            ascii_host = hostname.encode("idna").decode("ascii").lower().rstrip(".")
            labels = ascii_host.split(".")
            if (
                len(ascii_host) > 253
                or any(
                    not label
                    or len(label) > 63
                    or not re.fullmatch(r"[a-z0-9-]+", label)
                    or label.startswith("-")
                    or label.endswith("-")
                    for label in labels
                )
            ):
                raise ValueError
            is_ip = False
    except (ValueError, UnicodeError):
        raise ValueError("URL is malformed or contains an invalid hostname.") from None

    findings = []
    if is_ip:
        findings.append(_finding("IP address used as host", "host", "The hostname is an IP address.", "medium"))
    if parsed.scheme.lower() == "http":
        findings.append(_finding("Unencrypted transport", "transport", "The URL uses HTTP.", "low"))
    if has_credentials:
        findings.append(_finding("Embedded URL credentials", "syntax", "The authority component contains user information.", "high"))
    if len(ascii_host) > 70:
        findings.append(_finding("Long hostname", "host", "Hostname exceeds 70 characters.", "low"))
    labels = ascii_host.split(".")
    if len(labels) > 5:
        findings.append(_finding("Many hostname labels", "host", f"Hostname has {len(labels)} labels.", "medium"))
    if any(label.startswith("xn--") for label in labels):
        findings.append(_finding("Internationalized/punycode hostname", "unicode", "Hostname contains an IDN punycode label.", "medium"))
    if ascii_host in SHORTENERS:
        findings.append(_finding("URL shortener", "destination", "Hostname matches a commonly used URL shortener.", "medium"))
    if len(value) > 200:
        findings.append(_finding("Long URL", "structure", "URL exceeds 200 characters.", "low"))
    if len(parsed.query) > 500:
        findings.append(_finding("Long query string", "structure", "Query string exceeds 500 characters.", "low"))
    try:
        query_keys = {
            key.lower()
            for key, _ in parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=100)
        }
    except ValueError:
        findings.append(_finding(
            "Excessive query parameters", "structure",
            "Query contains more than 100 parameters.", "medium"
        ))
        query_keys = set()
    if query_keys.intersection(REDIRECT_KEYS):
        findings.append(_finding("Redirect-style parameter", "redirect", "Query contains a parameter commonly used to carry a destination.", "low"))
    if RISKY_TERMS.intersection(set(re.findall(r"[a-z]+", (ascii_host + parsed.path).lower()))):
        findings.append(_finding("Account-related wording", "content", "Hostname or path includes account-related wording.", "low"))
    if not findings:
        findings.append(_finding("No listed structural warning", "baseline", "No configured URL heuristic matched.", "info"))
    return {"normalized_host": ascii_host, "scheme": parsed.scheme.lower(), "findings": findings}
