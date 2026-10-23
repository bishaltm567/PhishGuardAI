from app.services.risk_scoring import assess


def test_risk_score_caps_correlated_findings_in_one_category():
    findings = [
        {"category": "host", "severity": "medium"},
        {"category": "host", "severity": "high"},
        {"category": "content", "severity": "low"},
    ]
    result = assess(findings)
    assert result["score"] == 33
    assert result["category"] == "Needs review"
    assert result["method"] == "maximum severity per evidence category"
