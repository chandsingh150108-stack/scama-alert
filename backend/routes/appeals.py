"""GET /api/appeals + GET/POST /api/appeals/<id>/evidence."""
from flask import Blueprint, jsonify, request

from backend import auth_guard, db
from backend.evidence import handler as evh
from backend.utils import error_response

bp = Blueprint("appeals", __name__)

ALLOWED_APPEAL_TYPES = {"business_registration", "dns_verification", "html_verification",
                        "legal_document", "other"}


@bp.get("/api/appeals")
def list_appeals():
    report_id = request.args.get("report_id")
    limit = db.parse_int(request.args.get("limit"), 50)
    try:
        if report_id:
            rows = db.query(
                "SELECT a.*, BIN_TO_UUID(a.id) AS id, fr.title AS report_title "
                "FROM appeals a JOIN fraud_reports fr ON fr.id = a.report_id "
                "LEFT JOIN users u ON u.id = a.resolved_by "
                "WHERE a.report_id = UUID_TO_BIN(%s) LIMIT %s", (report_id, limit))
        else:
            rows = db.query(
                "SELECT a.*, BIN_TO_UUID(a.id) AS id, fr.title AS report_title "
                "FROM appeals a JOIN fraud_reports fr ON fr.id = a.report_id "
                "LEFT JOIN users u ON u.id = a.resolved_by LIMIT %s", (limit,))
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"appeals": rows or []})


@bp.get("/api/appeals/<aid>/evidence")
def appeal_evidence_list(aid):
    try:
        rows = db.query("SELECT *, BIN_TO_UUID(id) AS id FROM appeal_evidence WHERE appeal_id = UUID_TO_BIN(%s)", (aid,)) or []
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"evidence": rows})


@bp.post("/api/appeals/<aid>/evidence")
def appeal_evidence_add(aid):
    sess = auth_guard.current_user()
    if not sess:
        return error_response("Authentication required", 401)
    f = request.files.get("file")
    if f is None:
        return error_response("Missing required field: file", 400)
    try:
        exists = db.query_one("SELECT id FROM appeals WHERE id = UUID_TO_BIN(%s)", (aid,))
    except Exception as e:
        return error_response(str(e), 500)
    if not exists:
        return error_response("Appeal not found", 404)
    etype = (request.form.get("evidence_type") or "other").strip()
    if etype not in ALLOWED_APPEAL_TYPES:
        return error_response("Invalid evidence_type", 400)
    description = request.form.get("description")
    try:
        data = f.read()
        meta = evh.store_evidence(aid, f.filename or "upload.bin",
                                  f.mimetype or "application/octet-stream",
                                  data, sess["id"], description)
    except ValueError as e:
        return error_response(str(e), 500)
    except Exception as e:
        return error_response(str(e), 500)
    import uuid as _uuid
    eid = str(_uuid.uuid4())
    try:
        db.query(
            "INSERT INTO appeal_evidence (id, appeal_id, evidence_type, file_path, sha256_hash, description) "
            "VALUES (UUID_TO_BIN(%s), UUID_TO_BIN(%s), %s, %s, %s, %s)",
            (eid, aid, etype, meta["filePath"], meta["sha256Hash"], description))
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"success": True, "evidence": {
        "id": eid, "file_path": meta["filePath"], "evidence_type": etype}}), 201
