"""Credential service. Replaces Better Auth (src/lib/auth.ts) for Python.

- bcrypt cost 12, `users.password` column holds the hash.
- Auto-creates app row semantics live in auth_guard (first-login insert).
"""
import uuid

import bcrypt

from backend import db

BCRYPT_ROUNDS = 12


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(BCRYPT_ROUNDS)).decode("utf-8")


def verify_password(password: str, hashed: str | None) -> bool:
    if not hashed:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def find_by_email(email: str) -> dict | None:
    return db.query_one(
        "SELECT BIN_TO_UUID(id) AS id, email, name, password, role, reputation_score, reputation_tier "
        "FROM users WHERE email = %s",
        (email,),
    )


def find_by_id(user_id: str) -> dict | None:
    return db.query_one(
        "SELECT BIN_TO_UUID(id) AS id, email, name, role, reputation_score, reputation_tier "
        "FROM users WHERE id = UUID_TO_BIN(%s)",
        (user_id,),
    )


def create_user(name: str, email: str, password_hash: str) -> dict | None:
    new_id = str(uuid.uuid4())
    db.query(
        "INSERT INTO users (id, email, name, password, role, emailVerified, is_active) "
        "VALUES (UUID_TO_BIN(%s), %s, %s, %s, 'user', TRUE, TRUE)",
        (new_id, email, name, password_hash),
    )
    return find_by_id(new_id)
