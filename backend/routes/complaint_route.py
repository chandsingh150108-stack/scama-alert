"""GET /api/reports/<id>/complaint — binary DOCX download."""
import io

from flask import Blueprint, jsonify, send_file

from backend import db
from backend.complaint import generate_complaint

bp = Blueprint("complaint", __name__)


@bp.get("/api/reports/<rid>/complaint")
def download_complaint(rid):
    try:
        report = db.query_one(
            "SELECT fr.title, fr.description, fr.target_brand, fr.amount_lost, fr.currency, "
            "fr.incident_date, fr.is_anonymous, u.name AS reporter_name, u.email AS reporter_email, "
            "c.name AS category_name, w.normalized_url AS website "
            "FROM fraud_reports fr JOIN users u ON u.id = fr.reporter_id "
            "JOIN categories c ON c.id = fr.category_id "
            "JOIN website_urls w ON w.id = fr.website_url_id "
            "WHERE fr.id = UUID_TO_BIN(%s)", (rid,))
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    if not report:
        return jsonify({"error": "Report not found"}), 404
    try:
        ev = db.query("SELECT file_name FROM report_evidence WHERE report_id = UUID_TO_BIN(%s)", (rid,)) or []
        payload = {
            "reporterName": report.get("reporter_name", ""),
            "reporterEmail": report.get("reporter_email", ""),
            "website": report.get("website", ""),
            "category": report.get("category_name", ""),
            "title": report.get("title", ""),
            "description": report.get("description", ""),
            "amountLost": float(report.get("amount_lost")) if report.get("amount_lost") is not None else None,
            "currency": report.get("currency", "INR"),
            "incidentDate": str(report.get("incident_date")) if report.get("incident_date") else None,
            "targetBrand": report.get("target_brand"),
            "evidenceSummary": [r.get("file_name", "") for r in ev],
            # Anonymous reports must not leak reporter identity into the DOCX.
            "isAnonymous": bool(report.get("is_anonymous")),
        }
        data = generate_complaint(payload)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return send_file(io.BytesIO(data),
                     mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                     as_attachment=True, download_name=f"complaint-{rid}.docx")
