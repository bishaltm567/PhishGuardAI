import hashlib
import json
import uuid
from datetime import datetime, timezone

from flask import Blueprint, abort, flash, jsonify, make_response, redirect, render_template, request, url_for
from sqlalchemy import func

from .extensions import db, limiter
from .models import AnalystFeedback, CASE_STATUSES, Investigation
from .services import email_analyzer, eml_parser, intelligence, report_generator, risk_scoring, url_analyzer
from .services.ml_classifier import classify_url, model_status

bp = Blueprint("main", __name__)


def _save_case(kind, submitted, findings, risk):
    record = Investigation(
        case_id=str(uuid.uuid4()),
        analysis_type=kind,
        risk_score=risk["score"],
        risk_category=risk["category"],
        input_fingerprint=hashlib.sha256(submitted.encode("utf-8", errors="replace")).hexdigest(),
        findings_json=json.dumps(findings, ensure_ascii=False),
    )
    db.session.add(record)
    db.session.commit()
    return record


def _analyze(kind, submitted, result):
    findings = result["findings"]
    risk = risk_scoring.assess(findings)
    case = _save_case(kind, submitted, findings, risk)
    return render_template("result.html", case=case, findings=findings, risk=risk, detail=result)


@bp.get("/")
def dashboard():
    total = db.session.query(func.count(Investigation.id)).scalar() or 0
    high = db.session.query(func.count(Investigation.id)).filter(Investigation.risk_score >= 75).scalar() or 0
    medium = db.session.query(func.count(Investigation.id)).filter(
        Investigation.risk_score.between(25, 74)
    ).scalar() or 0
    low = total - high - medium
    recent = Investigation.query.order_by(Investigation.created_at.desc()).limit(8).all()
    return render_template("dashboard.html", total=total, high=high, medium=medium, low=low,
                           recent=recent, intel=intelligence.status(), model_status=model_status())


@bp.route("/analyze/url", methods=["GET", "POST"])
@limiter.limit("30 per minute", methods=["POST"])
def analyze_url():
    if request.method == "POST":
        try:
            value = request.form.get("url", "")
            result = url_analyzer.analyze_url(value)
            result["model"] = classify_url(value)
            if result["model"].get("available") and result["model"].get("label") == "phishing-like":
                result["findings"].append({
                    "indicator": "Model prediction: phishing-like",
                    "category": "model",
                    "evidence": "The optional URL model classified the input as phishing-like; this prediction is uncalibrated.",
                    "severity": "medium",
                    "reliability": "uncalibrated model prediction",
                    "source": "local machine-learning model",
                    "recommended_action": "Treat as a triage signal and corroborate with independent evidence.",
                })
            return _analyze("url", value, result)
        except ValueError as exc:
            flash(str(exc), "error")
    return render_template("analyze.html", kind="URL", endpoint="main.analyze_url")


@bp.route("/analyze/email", methods=["GET", "POST"])
@limiter.limit("20 per minute", methods=["POST"])
def analyze_email():
    if request.method == "POST":
        try:
            text = request.form.get("email_text", "")
            result = email_analyzer.analyze_email(text, request.form.get("authentication_results", ""))
            return _analyze("email", text, result)
        except ValueError as exc:
            flash(str(exc), "error")
    return render_template("analyze.html", kind="Email", endpoint="main.analyze_email")


@bp.route("/analyze/eml", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def analyze_eml():
    if request.method == "POST":
        upload = request.files.get("eml_file")
        try:
            if not upload or not upload.filename:
                raise ValueError("Choose an EML file.")
            parsed = eml_parser.parse_eml(upload.stream.read(eml_parser.MAX_EML_BYTES + 1))
            result = email_analyzer.analyze_email(parsed["body"] or "No plain-text body found.",
                                                   parsed["authentication_results"])
            result["attachment_metadata"] = parsed["attachment_metadata"]
            result["message_metadata"] = {
                "subject_present": parsed["subject_present"],
                "sender_present": parsed["sender_present"],
            }
            return _analyze("eml", parsed["body"], result)
        except ValueError as exc:
            flash(str(exc), "error")
    return render_template("analyze.html", kind="EML file", endpoint="main.analyze_eml")


@bp.get("/cases")
def cases():
    status_filter = request.args.get("status", "")
    search = request.args.get("q", "").strip()[:80]
    sort = request.args.get("sort", "newest")
    try:
        page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        page = 1
    query = Investigation.query
    if status_filter in CASE_STATUSES:
        query = query.filter_by(status=status_filter)
    if search:
        query = query.filter(Investigation.case_id.ilike(f"%{search}%"))
    if sort == "risk":
        query = query.order_by(Investigation.risk_score.desc(), Investigation.created_at.desc())
    else:
        sort = "newest"
        query = query.order_by(Investigation.created_at.desc())
    pagination = query.paginate(page=page, per_page=25, error_out=False)
    return render_template("cases.html", pagination=pagination, cases=pagination.items,
                           statuses=sorted(CASE_STATUSES), status_filter=status_filter,
                           search=search, sort=sort)


@bp.route("/cases/<case_id>", methods=["GET", "POST"])
def case_detail(case_id):
    case = Investigation.query.filter_by(case_id=case_id).first_or_404()
    if request.method == "POST":
        status = request.form.get("status", "")
        notes = request.form.get("notes", "")
        if status not in CASE_STATUSES or len(notes) > 5000:
            flash("Choose a valid status and keep notes within 5,000 characters.", "error")
        else:
            case.set_status(status)
            case.notes = notes
            db.session.commit()
            flash("Case updated.", "success")
            return redirect(url_for("main.case_detail", case_id=case_id))
    feedback = AnalystFeedback.query.filter_by(investigation_id=case.id).order_by(
        AnalystFeedback.created_at.desc()).all()
    return render_template("case_detail.html", case=case, statuses=sorted(CASE_STATUSES),
                           findings=json.loads(case.findings_json), feedback=feedback,
                           feedback_types=sorted(AnalystFeedback.FEEDBACK_TYPES))


@bp.post("/cases/<case_id>/feedback")
def add_feedback(case_id):
    case = Investigation.query.filter_by(case_id=case_id).first_or_404()
    feedback_type = request.form.get("feedback_type", "")
    comment = request.form.get("comment", "")
    if feedback_type not in AnalystFeedback.FEEDBACK_TYPES or len(comment) > 2000:
        flash("Choose a valid feedback label and keep comments within 2,000 characters.", "error")
    else:
        db.session.add(AnalystFeedback(
            investigation_id=case.id,
            feedback_type=feedback_type,
            comment=comment,
        ))
        db.session.commit()
        flash("Feedback recorded separately; it does not retrain the model.", "success")
    return redirect(url_for("main.case_detail", case_id=case_id))


@bp.get("/history")
def history():
    return redirect(url_for("main.cases"))


@bp.get("/reports")
def reports():
    return render_template("reports.html")


@bp.get("/reports/<case_id>.<format>")
def export_case(case_id, format):
    case = Investigation.query.filter_by(case_id=case_id).first_or_404()
    if format == "json":
        response = make_response(report_generator.json_report(case))
        response.mimetype = "application/json"
    elif format == "html":
        response = make_response(report_generator.html_report(case))
        response.mimetype = "text/html"
    else:
        abort(404)
    response.headers["Content-Disposition"] = f'attachment; filename="case-{case.case_id}.{format}"'
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@bp.get("/reports/cases.csv")
def export_cases():
    response = make_response(report_generator.csv_report(Investigation.query.order_by(
        Investigation.created_at.desc()).limit(5000).all()))
    response.mimetype = "text/csv"
    response.headers["Content-Disposition"] = 'attachment; filename="phishguard-cases.csv"'
    return response


@bp.get("/analytics")
def analytics():
    totals = db.session.query(Investigation.analysis_type, func.count(Investigation.id)).group_by(
        Investigation.analysis_type).all()
    categories = db.session.query(Investigation.risk_category, func.count(Investigation.id)).group_by(
        Investigation.risk_category).all()
    all_cases = Investigation.query.order_by(Investigation.created_at.desc()).limit(5000).all()
    daily = {}
    indicators = {}
    for case in all_cases:
        day = case.created_at.strftime("%Y-%m-%d")
        daily[day] = daily.get(day, 0) + 1
        for finding in json.loads(case.findings_json):
            name = finding.get("indicator", "Unknown")
            indicators[name] = indicators.get(name, 0) + 1
    trends = sorted(daily.items(), reverse=True)[:30]
    top_indicators = sorted(indicators.items(), key=lambda item: (-item[1], item[0]))[:10]
    return render_template("analytics.html", totals=totals, categories=categories,
                           trends=trends, top_indicators=top_indicators)


@bp.get("/settings")
def settings():
    return render_template("settings.html", intel=intelligence.status(), model_status=model_status())


@bp.get("/health")
def health():
    return jsonify({"status": "ok", "time": datetime.now(timezone.utc).isoformat()})
