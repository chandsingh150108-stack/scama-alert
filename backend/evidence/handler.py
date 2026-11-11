"""Evidence validation/storage. Verbatim port of src/lib/evidence/handler.ts."""
import hashlib
import os
import uuid

EVIDENCE_TYPES = {
    "screenshot": 6, "email_file": 5, "text_message": 3, "document": 8,
    "video": 4, "audio": 3, "url_archive": 7, "other": 2,
}
MAX_FILE_SIZE = 10 * 1024 * 1024
ALLOWED_MIME_TYPES = {
    "image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf",
    "text/plain", "text/html", "video/mp4", "video/webm", "audio/mpeg", "audio/wav",
}


def validate_evidence(filename: str, mime_type: str, size: int) -> dict:
    if size > MAX_FILE_SIZE:
        return {"valid": False, "error": f"File size exceeds {MAX_FILE_SIZE / 1024 / 1024:.0f}MB limit"}
    if mime_type not in ALLOWED_MIME_TYPES:
        return {"valid": False, "error": f"File type {mime_type} is not allowed"}
    return {"valid": True}


def compute_file_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def get_evidence_type(mime_type: str) -> str:
    if (mime_type or "").startswith("image/"):
        return "screenshot"
    if mime_type == "application/pdf":
        return "document"
    if mime_type == "text/plain":
        return "text_message"
    if mime_type == "text/html":
        return "url_archive"
    if (mime_type or "").startswith("video/"):
        return "video"
    if (mime_type or "").startswith("audio/"):
        return "audio"
    return "other"


def store_evidence(report_id: str, filename: str, mime_type: str, data: bytes,
                   uploaded_by: str, description=None, upload_root=None) -> dict:
    if not report_id or not str(report_id).strip():
        raise ValueError("Missing report_id")
    check = validate_evidence(filename, mime_type, len(data))
    if not check["valid"]:
        raise ValueError(check["error"])
    # UUID-guard against path traversal (mirrors server-side report existence check at routes).
    try:
        uuid.UUID(str(report_id))
    except Exception:
        raise ValueError("Invalid report_id")
    ext = os.path.splitext(filename or "")[1] or ".bin"
    unique = f"{uuid.uuid4()}{ext}"
    root = upload_root or os.path.join(os.getcwd(), "uploads")
    dest_dir = os.path.join(root, "evidence", str(report_id))
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, unique)
    with open(dest, "wb") as f:
        f.write(data)
    return {
        "id": str(uuid.uuid4()),
        "reportId": str(report_id),
        "uploadedBy": uploaded_by,
        "evidenceType": get_evidence_type(mime_type),
        "fileName": filename,
        "filePath": f"/uploads/evidence/{report_id}/{unique}",
        "mimeType": mime_type,
        "fileSizeBytes": len(data),
        "sha256Hash": compute_file_hash(data),
        "description": description,
    }


def verify_evidence_integrity(file_path: str, expected_hash: str) -> bool:
    try:
        with open(file_path, "rb") as f:
            return compute_file_hash(f.read()) == expected_hash
    except Exception:
        return False
