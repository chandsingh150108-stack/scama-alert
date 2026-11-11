"""GET /api/users + GET /api/users/<id>."""
from flask import Blueprint, jsonify, request

from backend import db
from backend.utils import error_response

bp = Blueprint("users", __name__)


@bp.get("/api/users")
def leaderboard():
    limit = db.parse_int(request.args.get("limit"), 20)
    try:
        rows = db.query(
            "SELECT * FROM v_user_reputation_leaderboard ORDER BY reputation_score DESC LIMIT %s", (limit,))
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"users": rows})


@bp.get("/api/users/<uid>")
def profile(uid):
    try:
        user = db.query_one(
            "SELECT BIN_TO_UUID(id) AS id, email, name, role, reputation_score, reputation_tier, "
            "total_reports, verified_reports, total_votes_cast, accurate_votes "
            "FROM users WHERE id = UUID_TO_BIN(%s)", (uid,))
    except Exception as e:
        return error_response(str(e), 500)
    if not user:
        return error_response("User not found", 404)
    reports = db.query(
        "SELECT fr.*, BIN_TO_UUID(fr.id) AS id, c.name AS category_name, w.domain AS domain "
        "FROM fraud_reports fr JOIN categories c ON c.id = fr.category_id "
        "JOIN website_urls w ON w.id = fr.website_url_id "
        "WHERE fr.reporter_id = UUID_TO_BIN(%s) ORDER BY fr.created_at DESC LIMIT 20", (uid,)) or []
    events = db.query(
        "SELECT *, BIN_TO_UUID(id) AS id FROM reputation_events "
        "WHERE user_id = UUID_TO_BIN(%s) ORDER BY created_at DESC LIMIT 20", (uid,)) or []
    return jsonify({"user": user, "reports": reports, "reputationEvents": events})
