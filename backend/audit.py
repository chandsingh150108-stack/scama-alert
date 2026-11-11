"""Audit logging. Python mirror of src/lib/audit.ts (never throws)."""
import json
import uuid

from backend import db


def log_audit_event(actor_id, action, entity_type, entity_id, metadata=None, ip_address=None):
    try:
        eid = str(uuid.uuid4())
        meta = json.dumps(metadata) if metadata is not None else None
        if actor_id:
            db.query(
                "INSERT INTO audit_events (id, actor_id, action, entity_type, entity_id, metadata, ip_address) "
                "VALUES (UUID_TO_BIN(%s), UUID_TO_BIN(%s), %s, %s, UUID_TO_BIN(%s), CAST(%s AS JSON), %s)",
                (eid, actor_id, action, entity_type, entity_id, meta, ip_address),
            )
        else:
            db.query(
                "INSERT INTO audit_events (id, actor_id, action, entity_type, entity_id, metadata, ip_address) "
                "VALUES (UUID_TO_BIN(%s), NULL, %s, %s, UUID_TO_BIN(%s), CAST(%s AS JSON), %s)",
                (eid, action, entity_type, entity_id, meta, ip_address),
            )
    except Exception:
        pass
