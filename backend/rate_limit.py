"""Rate limiting. Python mirror of src/lib/rate-limit.ts.

Defaults: report_new 5 / vote 20 / comment 30 / discussion 10 per hour.
Overridable via platform_config `rate_limit.<action>` (number or {limit}).
Writes rate_limit_events on allowance. Never raises on config-read failure.
"""
import json
import uuid

from backend import db

DEFAULT_LIMITS = {
    "report_new": 5,
    "vote": 20,
    "comment": 30,
    "discussion": 10,
}


def _get_limit(action: str) -> int:
    try:
        row = db.query_one(
            "SELECT value FROM platform_config WHERE `key` = %s",
            (f"rate_limit.{action}",),
        )
        if row and row.get("value") is not None:
            val = row["value"]
            if isinstance(val, (bytes, bytearray)):
                val = val.decode("utf-8", errors="ignore")
            if isinstance(val, str):
                try:
                    val = json.loads(val)
                except Exception:
                    val = None
            limit = None
            if isinstance(val, (int, float)):
                limit = int(val)
            elif isinstance(val, dict) and "limit" in val:
                try:
                    limit = int(val["limit"])
                except Exception:
                    limit = None
            if limit is not None and limit > 0:
                return limit
    except Exception:
        pass
    return DEFAULT_LIMITS.get(action, 10)


def check_rate_limit(user_id: str, action: str, ip: str | None = None,
                     record: bool = True) -> dict:
    """Sliding 1-hour window. When ip is given (anonymous callers sharing one
    user id), the window is scoped to (user_id, ip) so guests don't share a
    single global bucket; logged-in callers omit ip (per-user bucket).
    With record=False the window is only inspected, no event is written --
    for paths where a downstream procedure records the event itself on
    success (avoids double-counting and burning tokens on failed attempts)."""
    limit = _get_limit(action)
    try:
        if ip:
            row = db.query_one(
                "SELECT COUNT(*) AS cnt FROM rate_limit_events "
                "WHERE user_id = UUID_TO_BIN(%s) AND ip_address = %s AND action_type = %s "
                "AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)",
                (user_id, ip, action),
            )
        else:
            row = db.query_one(
                "SELECT COUNT(*) AS cnt FROM rate_limit_events "
                "WHERE user_id = UUID_TO_BIN(%s) AND action_type = %s "
                "AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)",
                (user_id, action),
            )
    except Exception:
        return {"allowed": True, "remaining": limit}
    count = int(row.get("cnt", 0) or 0) if row else 0
    if count >= limit:
        return {"allowed": False, "remaining": 0}
    if not record:
        return {"allowed": True, "remaining": limit - count}
    try:
        db.query(
            "INSERT INTO rate_limit_events (id, user_id, action_type, ip_address) "
            "VALUES (UUID_TO_BIN(%s), UUID_TO_BIN(%s), %s, %s)",
            (str(uuid.uuid4()), user_id, action, ip),
        )
    except Exception:
        pass
    return {"allowed": True, "remaining": limit - count - 1}
