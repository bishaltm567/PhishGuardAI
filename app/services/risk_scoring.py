def assess(findings):
    """Deterministic triage score; related findings contribute only their strongest weight."""
    weights = {"info": 0, "low": 8, "medium": 16, "high": 25}
    groups = {}
    for finding in findings:
        group = finding.get("category", "other")
        severity = finding.get("severity", "info")
        groups[group] = max(groups.get(group, 0), weights.get(severity, 0))
    score = min(100, sum(groups.values()))
    if score >= 75:
        category = "High-risk indicators"
    elif score >= 50:
        category = "Elevated risk"
    elif score >= 25:
        category = "Needs review"
    else:
        category = "Lower observed risk"
    return {"score": score, "category": category, "method": "maximum severity per evidence category"}
