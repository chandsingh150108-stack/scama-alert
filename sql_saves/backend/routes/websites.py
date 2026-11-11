"""GET /api/websites/<id>."""
from flask import Blueprint, jsonify

from backend import db
from backend.utils import error_response

bp = Blueprint("websites", __name__)


@bp.get("/api/websites/<wid>")
def website_detail(wid):
    try:
        website = db.query_one("SELECT * FROM v_website_risk_dashboard WHERE website_id = %s", (wid,))
        if not website:
            # Fallback when view exposes raw BIN id differently: try direct table.
            website = db.query_one("SELECT *, BIN_TO_UUID(id) AS website_id FROM website_urls WHERE id = UUID_TO_BIN(%s)", (wid,))
        if not website:
            return error_response("Website not found", 404)
        breakdown = db.query_one(
            "SELECT * FROM risk_score_breakdowns WHERE website_url_id = UUID_TO_BIN(%s) "
            "ORDER BY calculated_at DESC LIMIT 1", (wid,))
        reports = db.query(
            "SELECT fr.*, BIN_TO_UUID(fr.id) AS id, u.name AS reporter_name "
            "FROM fraud_reports fr JOIN users u ON u.id = fr.reporter_id "
            "WHERE fr.website_url_id = UUID_TO_BIN(%s) ORDER BY fr.created_at DESC LIMIT 10", (wid,)) or []
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"website": website, "riskBreakdown": breakdown, "reports": reports})
