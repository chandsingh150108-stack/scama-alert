"""Admin APIs: queue, appeals resolve, config, recalc. Role-gated."""
from flask import Blueprint, jsonify, request

from backend import audit, auth_guard, db
from backend.utils import error_response

bp = Blueprint("admin", __name__)


def _role_error(e):
    if isinstance(e, auth_guard.Forbidden):
        return error_response("Forbidden", 403)
    return error_response("Authentication required", 401)


@bp.get("/api/admin/reports")
def admin_queue():
    try:
        auth_guard.require_role(["admin", "moderator"])
    except (auth_guard.Unauthorized, auth_guard.Forbidden) as e:
        return _role_error(e)
    limit = db.parse_int(request.args.get("limit"), 50)
    try:
        rows = db.query("SELECT * FROM v_pending_review_queue ORDER BY hours_waiting DESC LIMIT %s", (limit,))
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"reports": rows or []})


@bp.put("/api/admin/reports")
def admin_bulk():
    try:
        sess = auth_guard.require_role(["admin", "moderator"])
    except (auth_guard.Unauthorized, auth_guard.Forbidden) as e:
        return _role_error(e)
    body = request.get_json(silent=True) or {}
    ids = body.get("report_ids")
    status = body.get("status")
    if not isinstance(ids, list) or not status:
        return error_response("Missing required fields: report_ids (array), status", 400)
    if status not in ("active", "archived", "disputed"):
        return error_response("Invalid status", 400)
    updated = 0
    try:
        for rid in ids:
            db.query("UPDATE fraud_reports SET status = %s WHERE id = UUID_TO_BIN(%s)", (status, rid))
            updated += 1
        audit.log_audit_event(sess["id"], "admin_bulk_status_update", "fraud_reports", ids[0] if ids else "",
                              {"status": status, "count": updated})
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"success": True, "updated": updated})


@bp.get("/api/admin/appeals")
def admin_appeals_list():
    try:
        auth_guard.require_role(["admin", "moderator"])
    except (auth_guard.Unauthorized, auth_guard.Forbidden) as e:
        return _role_error(e)
    status = request.args.get("status")
    try:
        if status:
            rows = db.query("SELECT * FROM v_appeal_resolution_tracker WHERE appeal_status = %s ORDER BY days_pending DESC", (status,))
        else:
            rows = db.query("SELECT * FROM v_appeal_resolution_tracker ORDER BY days_pending DESC")
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"appeals": rows or []})


@bp.post("/api/admin/appeals")
def admin_appeal_resolve():
    try:
        sess = auth_guard.require_role(["admin"])
    except (auth_guard.Unauthorized, auth_guard.Forbidden) as e:
        return _role_error(e)
    body = request.get_json(silent=True) or {}
    if not body.get("appeal_id") or not body.get("new_status"):
        return error_response("Missing required fields: appeal_id, new_status", 400)
    try:
        result = db.query(
            "CALL sp_resolve_appeal(UUID_TO_BIN(%s), UUID_TO_BIN(%s), %s)",
            (body["appeal_id"], sess["id"], body["new_status"]))
        audit.log_audit_event(sess["id"], "appeal_resolved", "appeals", body["appeal_id"],
                              {"new_status": body["new_status"]})
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"success": True, "result": result})


@bp.get("/api/admin/config")
def admin_config_list():
    try:
        auth_guard.require_role(["admin"])
    except (auth_guard.Unauthorized, auth_guard.Forbidden) as e:
        return _role_error(e)
    try:
        rows = db.query("SELECT * FROM platform_config")
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"configs": rows or []})


@bp.put("/api/admin/config")
def admin_config_upsert():
    try:
        sess = auth_guard.require_role(["admin"])
    except (auth_guard.Unauthorized, auth_guard.Forbidden) as e:
        return _role_error(e)
    body = request.get_json(silent=True) or {}
    if not body.get("key") or body.get("value") is None:
        return error_response("Missing required fields: key, value", 400)
    import json as _json
    val = body["value"] if isinstance(body["value"], str) else _json.dumps(body["value"])
    try:
        db.query(
            "INSERT INTO platform_config (`key`, value, description) VALUES (%s, CAST(%s AS JSON), %s) "
            "ON DUPLICATE KEY UPDATE value = CAST(%s AS JSON), description = VALUES(description)",
            (body["key"], val, body.get("description"), val))
        audit.log_audit_event(sess["id"], "admin_config_update", "platform_config", body["key"], None)
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"success": True})


@bp.post("/api/admin/recalculate-risk")
def admin_recalc():
    try:
        auth_guard.require_role(["admin"])
    except (auth_guard.Unauthorized, auth_guard.Forbidden) as e:
        return _role_error(e)
    try:
        results = db.query("CALL sp_recalculate_all_risk_scores()")
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"success": True, "results": results})
