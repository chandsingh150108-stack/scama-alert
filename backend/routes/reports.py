"""GET /api/reports + POST /api/reports. Mirror of api/reports/route.ts."""
import threading

from flask import Blueprint, jsonify, request

from backend import audit, auth_guard, db, rate_limit
from backend.utils import error_response

bp = Blueprint("reports", __name__)


def _enrich_async(report_id):
    """Best-effort live intel refresh; never fails the request."""
    try:
        from backend.intelligence import enrich
        row = db.query_one(
            "SELECT BIN_TO_UUID(website_url_id) AS wid FROM fraud_reports "
            "WHERE id = UUID_TO_BIN(%s)", (report_id,))
        if row and row.get("wid"):
            enrich.enrich_website(website_id=row["wid"])
    except Exception:
        pass


@bp.get("/api/reports")
def list_reports():
    page = db.parse_int(request.args.get("page"), 1)
    limit = db.parse_int(request.args.get("limit"), 20)
    category = request.args.get("category")
    status = request.args.get("status")
    if page < 1:
        page = 1
    if limit < 1:
        limit = 20
    offset = (page - 1) * limit
    sql = "SELECT * FROM v_report_full_details"
    conds, params = [], []
    if category:
        conds.append("category_slug = %s")
        params.append(category)
    if status:
        conds.append("status = %s")
        params.append(status)
    if conds:
        sql += " WHERE " + " AND ".join(conds)
    sql += " ORDER BY reported_at DESC LIMIT %s OFFSET %s"
    params.extend([limit, offset])
    try:
        reports = db.query(sql, params)
        if reports:
            report_ids = [r["report_id"] for r in reports if r.get("report_id")]
            if report_ids:
                placeholders = ",".join(["UUID_TO_BIN(%s)"] * len(report_ids))
                ev_rows = db.query(
                    f"SELECT BIN_TO_UUID(report_id) AS rid, file_path, evidence_type "
                    f"FROM report_evidence WHERE report_id IN ({placeholders}) "
                    f"ORDER BY uploaded_at ASC",
                    report_ids,
                )
                thumbs = {}
                for ev in (ev_rows or []):
                    rid = ev.get("rid")
                    if rid and rid not in thumbs and ev.get("file_path"):
                        thumbs[rid] = ev.get("file_path")
                for r in reports:
                    r["thumbnail_url"] = thumbs.get(r.get("report_id"))
    except Exception as e:
        return error_response(str(e), 500)
    count_sql = "SELECT COUNT(*) as total FROM v_report_full_details"
    count_params = []
    if conds:
        count_sql += " WHERE " + " AND ".join(conds)
        count_params = params[: len(conds)]
    try:
        row = db.query_one(count_sql, count_params)
    except Exception:
        row = {"total": 0}
    total = int((row or {}).get("total", 0) or 0)
    return jsonify({"reports": reports, "pagination": {
        "page": page, "limit": limit, "total": total,
        "totalPages": (total + limit - 1) // limit if limit else 0}})


@bp.post("/api/reports")
def create_report():
    body = request.get_json(silent=True) or {}
    url = body.get("url")
    category_slug = body.get("category_slug")
    title = body.get("title")
    description = body.get("description")
    if not url or not category_slug or not title or not description:
        return error_response("Missing required fields: url, category_slug, title, description", 400)
    sess = auth_guard.current_user()
    if not sess:
        return error_response("Authentication required to submit a report", 401)
    # Fail fast on unknown category (400) before touching the rate window,
    # so typos never burn tokens.
    try:
        cat = db.query_one(
            "SELECT id FROM categories WHERE slug = %s AND is_active = TRUE", (category_slug,))
    except Exception as e:
        return error_response(str(e), 500)
    if not cat:
        return error_response("Invalid category slug", 400)
    if body.get("is_anonymous"):
        reporter_id = auth_guard.anonymous_id()
        anonymous = True
    else:
        reporter_id = sess["id"]
        anonymous = False
    # Check-only: sp_submit_fraud_report records the rate event itself on
    # success (and rolls it back on failure). Recording here too would
    # double-count and burn tokens on failed attempts.
    check = rate_limit.check_rate_limit(sess["id"], "report_new", record=False)
    if not check["allowed"]:
        return error_response("Rate limit exceeded. Please try again later.", 429)
    try:
        amount = body.get("amount_lost")
        try:
            amount = float(amount) if amount not in (None, "") else None
        except Exception:
            amount = None
        result = db.call_procedure_first_row(
            "CALL sp_submit_fraud_report(UUID_TO_BIN(%s), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (reporter_id, url, category_slug, title, description,
             body.get("target_brand") or None, amount,
             body.get("currency") or "INR", body.get("incident_date") or None,
             body.get("country_code") or None, anonymous),
        )
    except Exception as e:
        msg = str(e)
        # Surface known stored-procedure rejections with their proper codes
        # instead of a generic 500.
        if "Invalid category slug" in msg:
            return error_response("Invalid category slug", 400)
        if "Rate limit exceeded" in msg:
            return error_response("Rate limit exceeded. Please try again later.", 429)
        return error_response(msg, 500)
    if not anonymous:
        try:
            audit.log_audit_event(reporter_id, "report_created", "fraud_reports",
                                   (result or {}).get("report_id", ""), {"title": title, "url": url})
        except Exception:
            pass
    # Refresh live technical intel in the background (DNS/TLS/WHOIS into
    # website_urls + rescore). Daemon thread so the 201 stays fast; all
    # enrichment errors are swallowed inside _enrich_async.
    try:
        report_id = (result or {}).get("report_id", "")
        if report_id:
            threading.Thread(target=_enrich_async, args=(report_id,),
                             daemon=True).start()
    except Exception:
        pass
    return jsonify({"success": True, "report_id": (result or {}).get("report_id")}), 201
