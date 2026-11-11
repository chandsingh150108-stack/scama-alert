"""Discussion forum: list/create, replies, votes."""
import uuid

from flask import Blueprint, jsonify, request

from backend import audit, auth_guard, db, rate_limit
from backend.utils import error_response

bp = Blueprint("discussions", __name__)


@bp.get("/api/discussions")
def list_discussions():
    website_id = request.args.get("website_id")
    limit = db.parse_int(request.args.get("limit"), 20)
    try:
        if website_id:
            rows = db.query(
                "SELECT d.*, BIN_TO_UUID(d.id) AS id, u.name AS author_name, w.domain AS domain "
                "FROM website_discussions d JOIN users u ON u.id = d.author_id "
                "JOIN website_urls w ON w.id = d.website_url_id "
                "WHERE d.website_url_id = UUID_TO_BIN(%s) LIMIT %s", (website_id, limit))
        else:
            rows = db.query(
                "SELECT d.*, BIN_TO_UUID(d.id) AS id, u.name AS author_name, w.domain AS domain "
                "FROM website_discussions d JOIN users u ON u.id = d.author_id "
                "JOIN website_urls w ON w.id = d.website_url_id LIMIT %s", (limit,))
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"discussions": rows or []})


@bp.post("/api/discussions")
def create_discussion():
    sess = auth_guard.current_user()
    if not sess:
        return error_response("Authentication required", 401)
    body = request.get_json(silent=True) or {}
    if not body.get("website_url_id") or not body.get("title") or not body.get("body"):
        return error_response("Missing required fields: website_url_id, title, body", 400)
    check = rate_limit.check_rate_limit(sess["id"], "discussion")
    if not check["allowed"]:
        return error_response("Rate limit exceeded. Please try again later.", 429)
    did = str(uuid.uuid4())
    try:
        db.query(
            "INSERT INTO website_discussions (id, website_url_id, author_id, title, body) "
            "VALUES (UUID_TO_BIN(%s), UUID_TO_BIN(%s), UUID_TO_BIN(%s), %s, %s)",
            (did, body["website_url_id"], sess["id"], body["title"], body["body"]))
        audit.log_audit_event(sess["id"], "discussion_created", "website_discussions", did, {"title": body["title"]})
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"success": True, "discussion_id": did}), 201


@bp.get("/api/discussions/<did>/replies")
def list_replies(did):
    try:
        rows = db.query(
            "SELECT r.*, BIN_TO_UUID(r.id) AS id, u.name AS author_name, u.reputation_tier AS author_tier "
            "FROM discussion_replies r JOIN users u ON u.id = r.author_id "
            "WHERE r.discussion_id = UUID_TO_BIN(%s) ORDER BY r.created_at ASC", (did,)) or []
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"replies": rows})


@bp.post("/api/discussions/<did>/replies")
def add_reply(did):
    sess = auth_guard.current_user()
    if not sess:
        return error_response("Authentication required", 401)
    body = request.get_json(silent=True) or {}
    text = (body.get("body") or "")
    if not text.strip():
        return error_response("Reply body is required", 400)
    parent_id = body.get("parent_id")
    depth = 0
    try:
        if parent_id:
            parent = db.query_one("SELECT depth FROM discussion_replies WHERE id = UUID_TO_BIN(%s)", (parent_id,))
            if not parent:
                return error_response("Parent reply not found", 400)
            depth = int(parent.get("depth", 0) or 0) + 1
        if depth > 5:
            return error_response("Maximum reply depth exceeded", 400)
        rid = str(uuid.uuid4())
        if parent_id:
            db.query(
                "INSERT INTO discussion_replies (id, discussion_id, author_id, parent_id, body, depth) "
                "VALUES (UUID_TO_BIN(%s), UUID_TO_BIN(%s), UUID_TO_BIN(%s), UUID_TO_BIN(%s), %s, %s)",
                (rid, did, sess["id"], parent_id, text.strip(), depth))
        else:
            db.query(
                "INSERT INTO discussion_replies (id, discussion_id, author_id, body, depth) "
                "VALUES (UUID_TO_BIN(%s), UUID_TO_BIN(%s), UUID_TO_BIN(%s), %s, %s)",
                (rid, did, sess["id"], text.strip(), depth))
        db.query("UPDATE website_discussions SET reply_count = reply_count + 1, last_activity_at = NOW() "
                 "WHERE id = UUID_TO_BIN(%s)", (did,))
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"success": True, "reply_id": rid}), 201


@bp.post("/api/discussions/vote")
def vote_target():
    sess = auth_guard.current_user()
    if not sess:
        return error_response("Authentication required", 401)
    body = request.get_json(silent=True) or {}
    target_type = body.get("target_type")
    target_id = body.get("target_id")
    vote_value = body.get("vote_value")
    if not target_type or not target_id or vote_value is None:
        return error_response("Missing required fields: target_type, target_id, vote_value", 400)
    if target_type not in ("discussion", "reply"):
        return error_response("Invalid target_type. Must be: discussion or reply", 400)
    try:
        vote_value = int(vote_value)
    except Exception:
        return error_response("Invalid vote_value. Must be -1 or 1", 400)
    if vote_value not in (-1, 1):
        return error_response("Invalid vote_value. Must be -1 or 1", 400)
    try:
        vid = str(uuid.uuid4())
        db.query(
            "INSERT INTO discussion_votes (id, user_id, target_type, target_id, vote_value) "
            "VALUES (UUID_TO_BIN(%s), UUID_TO_BIN(%s), %s, UUID_TO_BIN(%s), %s) "
            "ON DUPLICATE KEY UPDATE vote_value = VALUES(vote_value)",
            (vid, sess["id"], target_type, target_id, vote_value))
        agg = db.query_one(
            "SELECT SUM(CASE WHEN vote_value = 1 THEN 1 ELSE 0 END) AS up, "
            "SUM(CASE WHEN vote_value = -1 THEN 1 ELSE 0 END) AS down "
            "FROM discussion_votes WHERE target_type = %s AND target_id = UUID_TO_BIN(%s)",
            (target_type, target_id))
        up = int((agg or {}).get("up", 0) or 0)
        down = int((agg or {}).get("down", 0) or 0)
        if target_type == "discussion":
            db.query("UPDATE website_discussions SET upvotes = %s, downvotes = %s WHERE id = UUID_TO_BIN(%s)",
                     (up, down, target_id))
        else:
            db.query("UPDATE discussion_replies SET upvotes = %s, downvotes = %s WHERE id = UUID_TO_BIN(%s)",
                     (up, down, target_id))
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"success": True})
