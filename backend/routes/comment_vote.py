"""POST /api/reports/<id>/comments/<cid>/vote. Comment upvote/downvote."""
from flask import Blueprint, jsonify, request

from backend import audit, auth_guard, db, rate_limit
from backend.utils import error_response

bp = Blueprint("comment_vote", __name__)


@bp.post("/api/reports/<rid>/comments/<cid>/vote")
def vote_comment(rid, cid):
    sess = auth_guard.current_user()
    if not sess:
        return error_response("Authentication required to vote", 401)

    body = request.get_json(silent=True) or {}
    vote_value = body.get("vote_value")

    if vote_value is None:
        return error_response("Missing required field: vote_value", 400)

    try:
        vote_value = int(vote_value)
    except Exception:
        return error_response("Invalid vote_value. Must be -1 or 1", 400)

    if vote_value not in (-1, 1):
        return error_response("Invalid vote_value. Must be -1 or 1", 400)

    # Verify comment exists and belongs to report
    try:
        comment = db.query_one(
            "SELECT id FROM report_comments WHERE id = UUID_TO_BIN(%s) AND report_id = UUID_TO_BIN(%s)",
            (cid, rid)
        )
        if not comment:
            return error_response("Comment not found", 404)
    except Exception as e:
        return error_response(str(e), 500)

    # Rate limit: 30/hour (same as comments)
    check = rate_limit.check_rate_limit(sess["id"], "comment")
    if not check["allowed"]:
        return error_response("Rate limit exceeded. Please try again later.", 429)

    try:
        vid = auth_guard.new_uuid()
        db.query(
            "INSERT INTO comment_votes (id, user_id, comment_id, vote_value) "
            "VALUES (UUID_TO_BIN(%s), UUID_TO_BIN(%s), UUID_TO_BIN(%s), %s) "
            "ON DUPLICATE KEY UPDATE vote_value = VALUES(vote_value)",
            (vid, sess["id"], cid, vote_value)
        )

        # Get updated counts
        agg = db.query_one(
            "SELECT SUM(CASE WHEN vote_value = 1 THEN 1 ELSE 0 END) AS up, "
            "SUM(CASE WHEN vote_value = -1 THEN 1 ELSE 0 END) AS down "
            "FROM comment_votes WHERE comment_id = UUID_TO_BIN(%s)",
            (cid,)
        )
        up = int((agg or {}).get("up", 0) or 0)
        down = int((agg or {}).get("down", 0) or 0)

        audit.log_audit_event(sess["id"], "comment_vote", "report_comments", cid,
                              {"vote_value": vote_value})

    except Exception as e:
        msg = str(e)
        if "Insufficient reputation" in msg:
            return error_response("Insufficient reputation to vote on comments (minimum tier: trusted)", 403)
        if "Daily vote limit" in msg:
            return error_response("Daily vote limit reached (50 votes per day)", 429)
        return error_response(msg, 500)

    return jsonify({"success": True, "upvotes": up, "downvotes": down, "user_vote": vote_value})