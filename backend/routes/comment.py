"""POST /api/reports/<id>/comment. Mirror of comment/route.ts."""
import uuid

from flask import Blueprint, jsonify, request

from backend import audit, auth_guard, db, email, rate_limit
from backend.utils import error_response

bp = Blueprint("comment", __name__)


@bp.post("/api/reports/<rid>/comment")
def add_comment(rid):
    sess = auth_guard.current_user()
    if sess:
        author_id = sess["id"]
        anonymous = False
    else:
        # Guest comments attribute to the Anonymous sentinel user; the
        # response's user_name ("Anonymous") comes from that row via JOIN.
        author_id = auth_guard.anonymous_id()
        anonymous = True
    body = request.get_json(silent=True) or {}
    text = (body.get("body") or "")
    if not text.strip():
        return error_response("Comment body is required", 400)
    try:
        report = db.query_one("SELECT id, title FROM fraud_reports WHERE id = UUID_TO_BIN(%s)", (rid,))
        if not report:
            return error_response("Report not found", 404)
        parent_id = body.get("parent_id")
        if parent_id:
            parent = db.query_one(
                "SELECT id FROM report_comments WHERE id = UUID_TO_BIN(%s) AND report_id = UUID_TO_BIN(%s)",
                (parent_id, rid))
            if not parent:
                return error_response("Parent comment not found", 404)
        check = rate_limit.check_rate_limit(
            author_id, "comment", ip=(request.remote_addr if anonymous else None))
        if not check["allowed"]:
            return error_response("Rate limit exceeded. Please try again later.", 429)
        cid = str(uuid.uuid4())
        if parent_id:
            db.query(
                "INSERT INTO report_comments (id, report_id, user_id, parent_id, body) "
                "VALUES (UUID_TO_BIN(%s), UUID_TO_BIN(%s), UUID_TO_BIN(%s), UUID_TO_BIN(%s), %s)",
                (cid, rid, author_id, parent_id, text.strip()))
        else:
            db.query(
                "INSERT INTO report_comments (id, report_id, user_id, body) "
                "VALUES (UUID_TO_BIN(%s), UUID_TO_BIN(%s), UUID_TO_BIN(%s), %s)",
                (cid, rid, author_id, text.strip()))
        row = db.query_one(
            "SELECT BIN_TO_UUID(rc.id) AS id, rc.body, u.name AS user_name, "
            "u.reputation_tier AS user_tier, rc.created_at FROM report_comments rc "
            "JOIN users u ON u.id = rc.user_id WHERE rc.id = UUID_TO_BIN(%s)", (cid,))
        if not anonymous:
            audit.log_audit_event(author_id, "comment_added", "report_comments", cid, {"report_id": rid})
        try:
            full = db.query_one(
                "SELECT BIN_TO_UUID(fr.reporter_id) AS reporter_id, fr.title, u.email "
                "FROM fraud_reports fr JOIN users u ON u.id = fr.reporter_id WHERE fr.id = UUID_TO_BIN(%s)", (rid,))
            if full and full.get("reporter_id") != author_id and full.get("email"):
                tpl = email.comment_notification_email(full.get("title", ""), text.strip())
                email.send_notification(full["email"], tpl["subject"], tpl["html"])
        except Exception:
            pass
        return jsonify({"success": True, "comment": {
            "id": (row or {}).get("id", cid), "body": text.strip(),
            "user_name": (row or {}).get("user_name"), "user_tier": (row or {}).get("user_tier"),
            "created_at": str((row or {}).get("created_at", ""))}}), 201
    except Exception as e:
        return error_response(str(e), 500)
