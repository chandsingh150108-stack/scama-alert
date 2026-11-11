"""13 cases mirroring evidence/handler.test.ts."""
import hashlib

from backend.evidence import handler as h


def test_sha256():
    assert h.compute_file_hash(b"hello") == hashlib.sha256(b"hello").hexdigest()


def test_weights():
    assert h.EVIDENCE_TYPES["document"] == 8
    assert h.EVIDENCE_TYPES["other"] == 2
    assert max(h.EVIDENCE_TYPES, key=h.EVIDENCE_TYPES.get) == "document"


def test_size_cap():
    assert h.validate_evidence("a.png", "image/png", 10 * 1024 * 1024)["valid"] is True
    bad = h.validate_evidence("a.png", "image/png", 10 * 1024 * 1024 + 1)
    assert bad["valid"] is False and "10MB" in bad["error"]


def test_mime_allowlist():
    assert h.validate_evidence("a.png", "image/png", 10)["valid"] is True
    assert h.validate_evidence("a.exe", "application/x-msdownload", 10)["valid"] is False


def test_type_mapping():
    assert h.get_evidence_type("image/png") == "screenshot"
    assert h.get_evidence_type("application/pdf") == "document"
    assert h.get_evidence_type("text/plain") == "text_message"
    assert h.get_evidence_type("text/html") == "url_archive"
    assert h.get_evidence_type("video/mp4") == "video"
    assert h.get_evidence_type("audio/mpeg") == "audio"
    assert h.get_evidence_type("weird/x") == "other"


def test_store_roundtrip(tmp_path):
    meta = h.store_evidence("11111111-1111-1111-1111-111111111111", "shot.png", "image/png",
                            b"data", "u1", "desc", upload_root=str(tmp_path))
    assert meta["evidenceType"] == "screenshot"
    assert meta["filePath"].startswith("/uploads/evidence/11111111")
    assert h.verify_evidence_integrity(str(tmp_path / "evidence" / "11111111-1111-1111-1111-111111111111" / meta["filePath"].rsplit("/", 1)[-1]), meta["sha256Hash"]) is True


def test_store_rejects(tmp_path):
    try:
        h.store_evidence("not-a-uuid", "a.png", "image/png", b"x", "u", None, upload_root=str(tmp_path))
        assert False
    except ValueError:
        pass


def test_verify_missing():
    assert h.verify_evidence_integrity("/nonexistent/file.bin", "abc") is False
