"""Frozen-SQL bootstrap. Python port of scripts/db-setup.js (port fixed to 3307).

Reads sql/01..06 in order with multi-statement execution, aborts on
01/02 failure, then verifies tables/views/procedures/functions/triggers/counts.
Never modifies sql/ files.
"""
import os
import sys

# Allow direct invocation (python scripts/db_setup.py) from the project root:
# ensure the root (parent of scripts/) is on sys.path for `backend` imports.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import mysql.connector

from backend.config import Config, parse_db_url

SQL_FILES = [
    "sql/01_schema.sql",
    "sql/02_seed_data.sql",
    "sql/03_views.sql",
    "sql/04_functions.sql",
    "sql/05_triggers.sql",
    "sql/06_procedures.sql",
]


def _split_sql(sql: str) -> list:
    """Split a script honoring DELIMITER directives (mysql-connector v26
    removed cursor multi=True, so statements run one at a time)."""
    import re

    statements = []
    delimiter = ";"
    buf: list[str] = []
    for raw in sql.splitlines():
        line = raw.strip()
        m = re.match(r"^DELIMITER\s+(\S+)\s*$", line, re.IGNORECASE)
        if m:
            delimiter = m.group(1)
            continue
        buf.append(raw)
        if line.endswith(delimiter):
            text = "\n".join(buf)
            # Strip the trailing delimiter (only the final occurrence).
            idx = text.rstrip().rfind(delimiter)
            stmt = (text[:idx] if idx != -1 else text).strip()
            # Skip empties and comment-only chunks.
            code = "\n".join(
                ln for ln in stmt.splitlines()
                if ln.strip() and not ln.strip().startswith(("--", "#"))
            ).strip()
            if code and not code.startswith("/*"):
                statements.append(stmt)
            buf = []
    tail = "\n".join(buf).strip()
    if tail:
        statements.append(tail)
    return statements


def run():
    cfg = parse_db_url(os.environ.get("DATABASE_URL") or Config.DATABASE_URL)
    print("Connecting to MySQL...", flush=True)
    conn = mysql.connector.connect(**cfg, use_pure=True)
    print("Connected!\n", flush=True)
    root = os.path.join(os.path.dirname(__file__), "..")
    only = [a for a in sys.argv[1:] if a.endswith(".sql")]
    files = [f for f in SQL_FILES if not only or any(f.endswith(o) for o in only)]
    for rel in files:
        path = os.path.join(root, rel)
        print(f"=== {rel} ===", flush=True)
        if not os.path.exists(path):
            print(f"  File not found: {path}\n")
            continue
        with open(path, "r", encoding="utf-8") as f:
            sql = f.read()
        try:
            cur = conn.cursor()
            for stmt in _split_sql(sql):
                cur.execute(stmt)
            cur.close()
            conn.commit()
            print("  OK\n")
        except Exception as e:
            print(f"  FAILED: {e}\n")
            if "01_schema" in rel or "02_seed" in rel:
                print("  Critical file failed. Aborting.")
                conn.close()
                sys.exit(1)
    print("=== Verification ===")
    try:
        cur = conn.cursor()
        cur.execute("SHOW TABLES")
        print(f"Tables: {len(cur.fetchall())}")
        cur.execute('SHOW FULL TABLES WHERE Table_type = "VIEW"')
        print(f"Views: {len(cur.fetchall())}")
        cur.execute("SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = 'scamalert' AND ROUTINE_TYPE = 'PROCEDURE'")
        print(f"Procedures: {cur.fetchone()[0]}")
        cur.execute("SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = 'scamalert' AND ROUTINE_TYPE = 'FUNCTION'")
        print(f"Functions: {cur.fetchone()[0]}")
        cur.execute("SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = 'scamalert'")
        print(f"Triggers: {cur.fetchone()[0]}")
        for t in ("users", "fraud_reports", "verification_votes"):
            try:
                cur.execute(f"SELECT COUNT(*) FROM {t}")
                print(f"{t}: {cur.fetchone()[0]}")
            except Exception as e:
                print(f"{t}: error {e}")
        cur.close()
    except Exception as e:
        print(f"Verification error: {e}")
    conn.close()
    print("\nDone!")


if __name__ == "__main__":
    run()
