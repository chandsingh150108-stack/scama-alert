"""MySQL pool + query helpers. Python mirror of src/lib/db.ts.

Conventions (see 4.3):
- Placeholders are %s (never f-string interpolation).
- UUID columns: filter with UUID_TO_BIN(%s), select with BIN_TO_UUID(col) AS alias.
- JSON columns: CAST(%s AS JSON) with json.dumps() payload.
"""
import json
from contextlib import contextmanager
from typing import Any, Optional

import mysql.connector.pooling

from backend.config import parse_db_url

_pool = None


def get_pool():
    global _pool
    if _pool is None:
        cfg = parse_db_url()
        _pool = mysql.connector.pooling.MySQLConnectionPool(
            pool_name="scamalert",
            pool_size=5,
            charset="utf8mb4",
            collation="utf8mb4_unicode_ci",
            autocommit=True,
            **cfg,
        )
    return _pool


@contextmanager
def get_connection():
    conn = get_pool().get_connection()
    try:
        yield conn
        try:
            conn.commit()
        except Exception:
            pass
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass


def query(sql: str, params: Optional[tuple | list] = None) -> list[dict]:
    """Mirror of lib/db.ts query<T>(). Returns list of dicts."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute(sql, params or ())
            try:
                rows = cur.fetchall()
            except Exception:
                rows = []
            return rows or []
        finally:
            cur.close()


def query_one(sql: str, params: Optional[tuple | list] = None) -> Optional[dict]:
    """Mirror of lib/db.ts queryOne<T>(). First row or None."""
    rows = query(sql, params)
    return rows[0] if rows else None


def call_procedure_first_row(call_sql: str, params: Optional[tuple | list] = None) -> Optional[dict]:
    """Execute a CALL ... statement and return the first row of the first result set.

    mysql-connector returns multiple result sets for CALL; Next.js mysql2
    surfaces the first SELECT inside the procedure. This helper replicates that.
    """
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute(call_sql, params or ())
            try:
                rows = cur.fetchall()
                if rows:
                    return rows[0]
            except Exception:
                pass
            # Drain remaining result sets
            try:
                for _ in cur.stored_results():
                    pass
            except Exception:
                pass
            return None
        finally:
            cur.close()


def to_json(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return json.dumps(value)


def parse_int(value: Any, default: int) -> int:
    """Mirror of parseInt(searchParams.get(...) || \"<default>\") with no clamp."""
    try:
        if value is None or value == "":
            return default
        return int(str(value).strip())
    except (ValueError, TypeError):
        return default
