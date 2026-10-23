import re
from urllib.parse import urlsplit

from .authentication_analyzer import analyze_authentication
from .url_analyzer import analyze_url

MAX_EMAIL_LENGTH = 100_000
PATTERNS = [
    ("Urgency or pressure", "urgency", r"\b(urgent|immediately|within\s+\d+\s+hours?|act now|final warning)\b", "medium"),
    ("Credential or code request", "credential_request", r"\b(password|passcode|verification code|one[- ]time code|login credentials)\b", "high"),
    ("Payment diversion language", "payment", r"\b(gift cards?|wire transfer|change (the )?bank details|urgent payment)\b", "high"),
    ("Secrecy pressure", "secrecy", r"\b(don't tell|do not tell|keep this confidential|secret)\b", "medium"),
    ("Account threat language", "account_threat", r"\b(account (will be|has been) suspended|lose access|account closure)\b", "medium"),
]


def analyze_email(text, authentication_results=""):
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Enter email text to analyze.")
    if len(text) > MAX_EMAIL_LENGTH:
        raise ValueError(f"Email text must be {MAX_EMAIL_LENGTH} characters or fewer.")
    findings = []
    for name, category, pattern, severity in PATTERNS:
        if re.search(pattern, text, re.I):
            findings.append({
                "indicator": name, "category": category,
                "evidence": "A configured language pattern was present; message context is not evaluated.",
                "severity": severity, "reliability": "heuristic", "source": "email text",
                "recommended_action": "Verify the request using a known, independent communication channel.",
            })
    links = []
    for match in re.findall(r"""(?i)\bhttps?://[^\s<>"']+""", text)[:20]:
        cleaned = match.rstrip(".,);]")
        try:
            result = analyze_url(cleaned)
            links.append({"host": result["normalized_host"], "findings": result["findings"]})
            if any(item["severity"] in {"medium", "high"} for item in result["findings"]):
                findings.append({
                    "indicator": "Link with structural warnings", "category": "links",
                    "evidence": "At least one extracted link matched URL heuristics.",
                    "severity": "medium", "reliability": "heuristic", "source": "embedded URL analysis",
                    "recommended_action": "Do not follow the link; inspect it through approved controls.",
                })
        except ValueError:
            continue
    if not findings:
        findings.append({
            "indicator": "No configured language warning", "category": "baseline",
            "evidence": "No configured email-language pattern matched.",
            "severity": "info", "reliability": "heuristic", "source": "email text",
            "recommended_action": "A clean heuristic result does not establish that the message is safe.",
        })
    return {
        "findings": findings,
        "links": links,
        "authentication": analyze_authentication(authentication_results),
        "retention": "Message body is not stored; only findings and a one-way fingerprint are retained.",
    }
