from datetime import datetime, timezone

from .extensions import db

CASE_STATUSES = {"New", "Under investigation", "Confirmed suspicious", "Confirmed benign", "Closed"}


class Investigation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    analysis_type = db.Column(db.String(16), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    risk_category = db.Column(db.String(32), nullable=False)
    status = db.Column(db.String(32), nullable=False, default="New")
    input_fingerprint = db.Column(db.String(64), nullable=False)
    findings_json = db.Column(db.Text, nullable=False)
    notes = db.Column(db.String(5000), nullable=False, default="")

    def set_status(self, status):
        if status not in CASE_STATUSES:
            raise ValueError("Unsupported case status.")
        self.status = status


class AnalystFeedback(db.Model):
    FEEDBACK_TYPES = {"Useful detection", "False positive", "Missed suspicious behavior", "Inconclusive"}

    id = db.Column(db.Integer, primary_key=True)
    investigation_id = db.Column(db.Integer, db.ForeignKey("investigation.id"), nullable=False, index=True)
    feedback_type = db.Column(db.String(40), nullable=False)
    comment = db.Column(db.String(2000), nullable=False, default="")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
