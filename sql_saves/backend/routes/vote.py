"""POST /api/reports/<id>/vote. Mirror of vote/route.ts."""
from flask import Blueprint, jsonify, request

from backend import audit, auth_guard, db, email, rate_limit
from backend.utils import error_response

bp = Blueprint("vote", __name__)


@bp.post("/api/reports/<rid>/vote")
def cast_vote(rid):
    sess = auth_guard.current_user()
    if not sess:
        return error_response("Authentication required to vote", 401)
    body = request.get_json(silent=True) or {}
    vote_type = body.get("vote_type")
    if not vote_type:
        return error_response("Missing required field: vote_type", 400)
    if vote_type not in ("confirm", "deny", "inconclusive"):
        return error_response("Invalid vote_type. Must be: confirm, deny, or inconclusive", 400)
    try:
        check = rate_limit.check_rate_limit(sess["id"], "vote")
        if not check["allowed"]:
            return error_response("Rate limit exceeded. Please try again later.", 429)
        result = db.query(
            "CALL sp_process_verification_vote(UUID_TO_BIN(%s), UUID_TO_BIN(%s), %s, %s, %s)",
            (rid, sess["id"], vote_type, body.get("confidence") or 1.0, body.get("comment") or None),
        )
        audit.log_audit_event(sess["id"], "vote_cast", "verification_votes", rid,
                              {"vote_type": vote_type, "confidence": body.get("confidence")})
        try:
            report = db.query_one(
                "SELECT BIN_TO_UUID(reporter_id) AS reporter_id, title FROM fraud_reports WHERE id = UUID_TO_BIN(%s)", (rid,))
            if report and report.get("reporter_id") != sess["id"]:
                reporter = db.query_one("SELECT email FROM users WHERE id = UUID_TO_BIN(%s)", (report["reporter_id"],))
                if reporter and reporter.get("email"):
                    tpl = email.vote_notification_email(report.get("title", ""), vote_type)
                    email.send_notification(reporter["email"], tpl["subject"], tpl["html"])
        except Exception:
            pass
        return jsonify({"success": True, "result": result})
    except Exception as e:
        return error_response(str(e), 500)
