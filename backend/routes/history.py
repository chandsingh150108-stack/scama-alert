"""GET /api/reports/<id>/history. No 404 — empty array (mirror TS)."""
from flask import Blueprint, jsonify

from backend import db
from backend.utils import error_response

bp = Blueprint("history", __name__)


@bp.get("/api/reports/<rid>/history")
def get_history(rid):
    try:
        rows = db.query(
            "SELECT rh.*, BIN_TO_UUID(rh.id) AS id, u.name AS actor_name "
            "FROM report_history rh LEFT JOIN users u ON u.id = rh.actor_id "
            "WHERE rh.report_id = UUID_TO_BIN(%s) ORDER BY rh.created_at ASC", (rid,)) or []
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"history": rows})
