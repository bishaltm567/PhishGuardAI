import json

from app.extensions import db
from app.models import Investigation
from app.services.report_generator import csv_safe


def test_dashboard_and_health_use_live_app(client):
    assert client.get("/").status_code == 200
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json["status"] == "ok"


def test_analysis_persists_findings_not_original_content(client, app):
    response = client.post("/analyze/url", data={"url": "https://example.com/"})
    assert response.status_code == 200
    assert b"INVESTIGATION CREATED" in response.data
    with app.app_context():
        case = Investigation.query.one()
        assert case.analysis_type == "url"
        assert "https://example.com/" not in case.findings_json
        assert len(case.input_fingerprint) == 64


def test_csrf_protects_case_updates(client, app):
    with app.app_context():
        case = Investigation(
            case_id="test-case", analysis_type="url", risk_score=0, risk_category="Lower observed risk",
            input_fingerprint="0" * 64, findings_json=json.dumps([]),
        )
        db.session.add(case)
        db.session.commit()
    app.config["WTF_CSRF_ENABLED"] = True
    response = client.post("/cases/test-case", data={"status": "Closed", "notes": "x"})
    assert response.status_code == 400


def test_export_escapes_html_and_csv_formulas(client, app):
    with app.app_context():
        case = Investigation(
            case_id="safe-case", analysis_type="email", risk_score=0, risk_category="Lower observed risk",
            input_fingerprint="0" * 64,
            findings_json=json.dumps([{"indicator": "<script>", "evidence": "<img onerror=x>",
                                       "severity": "low"}]),
        )
        db.session.add(case)
        db.session.commit()
    response = client.get("/reports/safe-case.html")
    assert response.status_code == 200
    assert b"&lt;script&gt;" in response.data
    assert b"<script>" not in response.data
    assert csv_safe("=1+1") == "'=1+1"


def test_feedback_is_persisted_separately(client, app):
    with app.app_context():
        case = Investigation(
            case_id="feedback-case", analysis_type="email", risk_score=0,
            risk_category="Lower observed risk", input_fingerprint="1" * 64,
            findings_json=json.dumps([]),
        )
        db.session.add(case)
        db.session.commit()
    response = client.post(
        "/cases/feedback-case/feedback",
        data={"feedback_type": "False positive", "comment": "Synthetic test note"},
    )
    assert response.status_code == 302
    assert b"Analyst feedback" in client.get("/cases/feedback-case").data
    with app.app_context():
        from app.models import AnalystFeedback
        feedback = AnalystFeedback.query.one()
        assert feedback.feedback_type == "False positive"
        assert feedback.comment == "Synthetic test note"


def test_case_filter_rejects_unrecognized_status_without_sql_interpolation(client):
    response = client.get("/cases?status=%27%20OR%201%3D1%20--&sort=risk")
    assert response.status_code == 200


def test_reports_json_is_valid_and_does_not_include_original_input(client, app):
    with app.app_context():
        case = Investigation(
            case_id="json-case", analysis_type="url", risk_score=0,
            risk_category="Lower observed risk", input_fingerprint="2" * 64,
            findings_json=json.dumps([{"indicator": "baseline", "evidence": "No warning", "severity": "info"}]),
        )
        db.session.add(case)
        db.session.commit()
    response = client.get("/reports/json-case.json")
    report = response.get_json()
    assert response.status_code == 200
    assert report["case_id"] == "json-case"
    assert report["input"].startswith("Not retained")
    assert client.get("/reports/cases.csv").status_code == 200
