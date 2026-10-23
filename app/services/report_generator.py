import csv
import html
import io
import json


def csv_safe(value):
    text = str(value)
    if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


def json_report(case):
    return json.dumps({
        "case_id": case.case_id,
        "created_at": case.created_at.isoformat(),
        "analysis_type": case.analysis_type,
        "risk_score": case.risk_score,
        "risk_category": case.risk_category,
        "status": case.status,
        "findings": json.loads(case.findings_json),
        "analyst_notes": case.notes,
        "input": "Not retained; a one-way fingerprint is stored.",
        "threat_intelligence": "Not checked",
        "model_version": "Not trained",
        "limitations": "Automated indicators are a triage aid and not proof of malicious intent.",
    }, ensure_ascii=False, indent=2)


def csv_report(cases):
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["case_id", "created_at", "analysis_type", "risk_score", "risk_category", "status"])
    for case in cases:
        writer.writerow([csv_safe(case.case_id), case.created_at.isoformat(), case.analysis_type,
                         case.risk_score, csv_safe(case.risk_category), csv_safe(case.status)])
    return output.getvalue()


def html_report(case):
    findings = json.loads(case.findings_json)
    rows = "".join(
        f"<li><strong>{html.escape(item['indicator'])}</strong> — "
        f"{html.escape(item['evidence'])} ({html.escape(item['severity'])})</li>"
        for item in findings
    )
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Investigation report</title></head>"
        "<body><h1>PhishGuard AI investigation</h1>"
        f"<p>Case: {html.escape(case.case_id)}</p><p>Score: {case.risk_score}/100</p>"
        f"<p>Category: {html.escape(case.risk_category)}</p><ul>{rows}</ul>"
        "<p>Automated triage is not proof of malicious intent. Submitted content is not retained.</p></body></html>"
    )
