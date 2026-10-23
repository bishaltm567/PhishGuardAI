import re


def analyze_authentication(headers):
    """Interpret supplied Authentication-Results text; it is not independently verified."""
    if not headers:
        return {"source": "No trusted Authentication-Results header supplied", "results": []}
    results = []
    for mechanism in ("spf", "dkim", "dmarc"):
        matches = re.findall(rf"\b{mechanism}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", headers, re.I)
        if not matches:
            status = "not present"
            explanation = "No result for this mechanism was found in the supplied header text."
        elif len(set(item.lower() for item in matches)) > 1:
            status = "conflicting"
            explanation = "Supplied header text contains contradictory results."
        else:
            status = matches[0].lower()
            explanation = f"Supplied header text reports {status}; header provenance has not been independently verified."
        results.append({"mechanism": mechanism.upper(), "status": status, "explanation": explanation})
    return {"source": "User-supplied header text; not independently verified", "results": results}
