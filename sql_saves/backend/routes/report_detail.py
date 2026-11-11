"""GET/PUT/DELETE /api/reports/<id>. Mirror of api/reports/[id]/route.ts."""
from flask import Blueprint, jsonify, request

from backend import auth_guard, db
from backend.utils import error_response

bp = Blueprint("report_detail", __name__)


@bp.get("/api/reports/<rid>")
def get_report(rid):
    try:
        report = db.query_one(
            "SELECT fr.*, BIN_TO_UUID(fr.id) AS id, BIN_TO_UUID(fr.reporter_id) AS reporter_id, "
            "BIN_TO_UUID(fr.website_url_id) AS website_url_id, BIN_TO_UUID(fr.category_id) AS category_id, "
            "u.name AS reporter_name, u.reputation_tier AS reporter_tier, c.name AS category_name, "
            "c.slug AS category_slug, w.domain AS domain, w.risk_level AS website_risk_level "
            "FROM fraud_reports fr JOIN users u ON u.id = fr.reporter_id "
            "JOIN categories c ON c.id = fr.category_id "
            "JOIN website_urls w ON w.id = fr.website_url_id "
            "WHERE fr.id = UUID_TO_BIN(%s)", (rid,))
    except Exception as e:
        return error_response(str(e), 500)
    if not report:
        return error_response("Report not found", 404)
    try:
        evidence = db.query(
            "SELECT re.*, BIN_TO_UUID(re.id) AS id FROM report_evidence re "
            "WHERE re.report_id = UUID_TO_BIN(%s)", (rid,)) or []
        votes = db.query(
            "SELECT vv.*, BIN_TO_UUID(vv.id) AS id FROM verification_votes vv "
            "WHERE vv.report_id = UUID_TO_BIN(%s)", (rid,)) or []
        comments = db.query(
            "SELECT rc.*, BIN_TO_UUID(rc.id) AS id, u.name AS user_name, "
            "u.reputation_tier AS user_tier FROM report_comments rc "
            "JOIN users u ON u.id = rc.user_id "
            "WHERE rc.report_id = UUID_TO_BIN(%s) ORDER BY rc.created_at ASC", (rid,)) or []
        tags = db.query(
            "SELECT t.*, BIN_TO_UUID(t.id) AS id FROM report_tags rt "
            "JOIN tags t ON t.id = rt.tag_id WHERE rt.report_id = UUID_TO_BIN(%s)", (rid,)) or []
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"report": report, "evidence": evidence, "votes": votes,
                    "comments": comments, "tags": tags})


@bp.put("/api/reports/<rid>")
def update_report(rid):
    body = request.get_json(silent=True) or {}
    try:
        existing = db.query_one("SELECT BIN_TO_UUID(reporter_id) AS reporter_id FROM fraud_reports WHERE id = UUID_TO_BIN(%s)", (rid,))
    except Exception as e:
        return error_response(str(e), 500)
    if not existing:
        return error_response("Report not found", 404)
    try:
        auth_guard.owner_or_roles(existing.get("reporter_id"), ["admin", "moderator"])
    except auth_guard.Unauthorized:
        return error_response("Authentication required", 401)
    except auth_guard.Forbidden:
        return error_response("Forbidden", 403)
    allowed = {k: body.get(k) for k in ("title", "description", "target_brand", "amount_lost") if body.get(k) is not None}
    if not allowed:
        return error_response("Missing fields to update", 400)
    sets, params = [], []
    for k, v in allowed.items():
        sets.append(f"{k} = %s")
        params.append(v)
    params.append(rid)
    try:
        db.query(f"UPDATE fraud_reports SET {', '.join(sets)} WHERE id = UUID_TO_BIN(%s)", params)
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"success": True})


@bp.delete("/api/reports/<rid>")
def delete_report(rid):
    try:
        existing = db.query_one("SELECT id FROM fraud_reports WHERE id = UUID_TO_BIN(%s)", (rid,))
    except Exception as e:
        return error_response(str(e), 500)
    if not existing:
        return error_response("Report not found", 404)
    try:
        auth_guard.require_role(["admin"])
    except auth_guard.Unauthorized:
        return error_response("Authentication required", 401)
    except auth_guard.Forbidden:
        return error_response("Forbidden", 403)
    try:
        db.query("UPDATE fraud_reports SET status = 'archived' WHERE id = UUID_TO_BIN(%s)", (rid,))
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"success": True})
