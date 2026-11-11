"""Central configuration. Mirrors .env / docker-compose / APP_URL usage.

Defaults standardize on port 3307 (docker-compose + .env.example).
scripts/db-setup.js used 3306 by mistake; scripts/db_setup.py uses this config.
"""
import os
from datetime import timedelta
from urllib.parse import urlparse, unquote


def _get(key: str, default: str) -> str:
    return os.environ.get(key, default)


DATABASE_URL = _get(
    "DATABASE_URL",
    "mysql://scamalert_user:scamalert_pass@localhost:3308/scamalert",
)
SECRET_KEY = _get("FLASK_SECRET", _get("BETTER_AUTH_SECRET", "change-me-to-a-random-secret"))
APP_URL = _get("APP_URL", _get("NEXT_PUBLIC_APP_URL", "http://localhost:5000"))
UPLOAD_DIR = _get("UPLOAD_DIR", os.path.join(os.getcwd(), "uploads"))
PERMANENT_SESSION_LIFETIME = timedelta(days=7)


class Config:
    DATABASE_URL = DATABASE_URL
    SECRET_KEY = SECRET_KEY
    APP_URL = APP_URL
    UPLOAD_DIR = UPLOAD_DIR
    PERMANENT_SESSION_LIFETIME = PERMANENT_SESSION_LIFETIME
    SESSION_TYPE = "filesystem"
    SESSION_PERMANENT = True
    SESSION_USE_SIGNER = True


def parse_db_url(url: str = DATABASE_URL) -> dict:
    """Split mysql://user:pass@host:port/db into connector kwargs."""
    p = urlparse(url)
    return {
        "host": p.hostname or "localhost",
        "port": p.port or 3307,
        "user": unquote(p.username or "scamalert_user"),
        "password": unquote(p.password or ""),
        "database": (p.path or "/scamalert").lstrip("/"),
    }
