"""GET /api/evidence + POST /api/evidence/upload."""
import logging

from flask import Blueprint, jsonify, request

from backend import auth_guard, db
from backend.evidence import handler as evh
from backend.utils import error_response

bp = Blueprint("evidence", __name__)
log = logging.getLogger(__name__)


@bp.get("/api/evidence")
def list_evidence():
    report_id = request.args.get("report_id")
    limit = db.parse_int(request.args.get("limit"), 50)
    try:
        if report_id:
            rows = db.query(
                "SELECT re.*, BIN_TO_UUID(re.id) AS id, u.name AS uploader_name, fr.title AS report_title "
                "FROM report_evidence re LEFT JOIN users u ON u.id = re.uploaded_by "
                "JOIN fraud_reports fr ON fr.id = re.report_id "
                "WHERE re.report_id = UUID_TO_BIN(%s) LIMIT %s", (report_id, limit))
        else:
            rows = db.query(
                "SELECT re.*, BIN_TO_UUID(re.id) AS id, u.name AS uploader_name, fr.title AS report_title "
                "FROM report_evidence re LEFT JOIN users u ON u.id = re.uploaded_by "
                "JOIN fraud_reports fr ON fr.id = re.report_id LIMIT %s", (limit,))
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"evidence": rows or []})


@bp.post("/api/evidence/upload")
def upload_evidence():
    sess = auth_guard.current_user()
    if not sess:
        return error_response("Authentication required", 401)
    f = request.files.get("file")
    report_id = request.form.get("report_id")
    description = request.form.get("description")
    if f is None or not report_id:
        return error_response("Missing required fields: file, report_id", 400)
    try:
        exists = db.query_one("SELECT id FROM fraud_reports WHERE id = UUID_TO_BIN(%s)", (report_id,))
    except Exception as e:
        return error_response(str(e), 500)
    if not exists:
        return error_response("Report not found", 404)
    try:
        data = f.read()
        meta = evh.store_evidence(report_id, f.filename or "upload.bin",
                                  f.mimetype or "application/octet-stream",
                                  data, sess["id"], description)
    except ValueError as e:
        log.warning("evidence upload rejected: report=%s file=%s reason=%s",
                    report_id, (f.filename if f else "?"), e)
        return error_response(str(e), 400)
    except Exception as e:
        log.warning("evidence upload failed: report=%s file=%s reason=%s",
                    report_id, (f.filename if f else "?"), e)
        return error_response(str(e), 500)
    try:
        db.query(
            "INSERT INTO report_evidence (id, report_id, uploaded_by, evidence_type, file_name, "
            "file_path, mime_type, file_size_bytes, sha256_hash, description) "
            "VALUES (UUID_TO_BIN(%s), UUID_TO_BIN(%s), UUID_TO_BIN(%s), %s, %s, %s, %s, %s, %s, %s)",
            (meta["id"], report_id, sess["id"], meta["evidenceType"], meta["fileName"],
             meta["filePath"], meta["mimeType"], meta["fileSizeBytes"], meta["sha256Hash"],
             meta.get("description")))
    except Exception as e:
        log.warning("evidence upload DB insert failed: report=%s file=%s reason=%s",
                    report_id, (f.filename if f else "?"), e)
        return error_response(str(e), 500)
    return jsonify({"success": True, "evidence": {
        "id": meta["id"], "file_name": meta["fileName"], "evidence_type": meta["evidenceType"],
        "file_size_bytes": meta["fileSizeBytes"], "file_path": meta["filePath"]}}), 201
