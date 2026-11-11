"""Request identity + RBAC. Python mirror of src/lib/auth-guard.ts.

- current_user(): Flask session -> users row (auto-creates user/newcomer
  if session valid but app row missing, mirroring auth-guard.ts:33-38).
- anonymous_id(): sentinel for public submissions.
- require_role([...]): raises Unauthorized/Forbidden with UNAUTHORIZED/FORBIDDEN
  markers so routes map to 401/403 exactly like the TS code.
"""
import uuid

from flask import session

from backend import auth as auth_service
from backend import db

ANONYMOUS_ID = "00000000-0000-0000-0000-000000000001"


class Unauthorized(Exception):
    pass


class Forbidden(Exception):
    pass


def anonymous_id() -> str:
    return ANONYMOUS_ID


def current_user() -> dict | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    try:
        row = auth_service.find_by_id(user_id)
    except Exception:
        return None
    if row:
        return {
            "id": row["id"],
            "email": row.get("email", ""),
            "name": row.get("name") or row.get("email", ""),
            "role": row.get("role", "user"),
            "reputation_score": row.get("reputation_score", 0),
            "reputation_tier": row.get("reputation_tier", "newcomer"),
        }
    # Session valid but app row missing -> auto-create (mirror TS behavior).
    email = session.get("email", "")
    name = session.get("name", email)
    if not email:
        return None
    try:
        created = db.query_one(
            "INSERT INTO users (id, email, name, password, role, emailVerified, is_active) "
            "VALUES (UUID_TO_BIN(%s), %s, %s, NULL, 'user', TRUE, TRUE) "
            "RETURNING BIN_TO_UUID(id) AS id",
            (user_id, email, name),
        )
    except Exception:
        # MySQL variants without RETURNING: fall back to plain insert + select.
        try:
            db.query(
                "INSERT INTO users (id, email, name, password, role, emailVerified, is_active) "
                "VALUES (UUID_TO_BIN(%s), %s, %s, NULL, 'user', TRUE, TRUE)",
                (user_id, email, name),
            )
        except Exception:
            return None
        created = {"id": user_id}
    if not created:
        return None
    return {
        "id": created.get("id", user_id),
        "email": email,
        "name": name,
        "role": "user",
        "reputation_score": 0,
        "reputation_tier": "newcomer",
    }


def login_session(user_id: str, email: str, name: str) -> None:
    session["user_id"] = user_id
    session["email"] = email
    session["name"] = name
    session.permanent = True


def logout_session() -> None:
    session.clear()


def require_role(allowed_roles: list[str]) -> dict:
    user = current_user()
    if not user:
        raise Unauthorized("UNAUTHORIZED")
    if user.get("role") not in allowed_roles:
        raise Forbidden("FORBIDDEN")
    return user


def owner_or_roles(owner_id: str | None, roles: list[str]) -> dict:
    """401 when anonymous; 403 when neither owner nor allowed role."""
    user = current_user()
    if not user:
        raise Unauthorized("UNAUTHORIZED")
    if owner_id and str(owner_id) == str(user["id"]):
        return user
    if user.get("role") in roles:
        return user
    raise Forbidden("FORBIDDEN")


def new_uuid() -> str:
    return str(uuid.uuid4())
