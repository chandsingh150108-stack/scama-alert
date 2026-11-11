"""Auth endpoints. Replaces api/auth/[...all] + api/me."""
from flask import Blueprint, jsonify, request

from backend import auth as auth_service
from backend import auth_guard
from backend.utils import error_response

bp = Blueprint("auth", __name__)


def _public_user(u: dict) -> dict:
    return {"id": u["id"], "email": u.get("email"), "name": u.get("name"),
            "role": u.get("role"), "reputation_score": u.get("reputation_score", 0),
            "reputation_tier": u.get("reputation_tier", "newcomer")}


@bp.post("/api/auth/signup")
def signup():
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    email = (body.get("email") or "").strip()
    password = body.get("password") or ""
    if not name or not email or not password:
        return error_response("Missing required fields: name, email, password", 400)
    if len(password) < 8:
        return error_response("Password must be at least 8 characters", 400)
    if auth_service.find_by_email(email):
        return error_response("Email already registered", 400)
    user = auth_service.create_user(name, email, auth_service.hash_password(password))
    if not user:
        return error_response("Signup failed", 500)
    auth_guard.login_session(user["id"], user["email"], user.get("name") or email)
    return jsonify({"user": _public_user({**user, "name": user.get("name") or name})})


@bp.post("/api/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip()
    password = body.get("password") or ""
    if not email or not password:
        return error_response("Missing required fields: email, password", 400)
    user = auth_service.find_by_email(email)
    if not user or not auth_service.verify_password(password, user.get("password")):
        return error_response("Invalid email or password", 401)
    auth_guard.login_session(user["id"], user["email"], user.get("name") or email)
    return jsonify({"user": _public_user(user)})


@bp.post("/api/auth/logout")
def logout():
    auth_guard.logout_session()
    return jsonify({"success": True})


@bp.get("/api/me")
def me():
    user = auth_guard.current_user()
    if not user:
        return jsonify({"user": None}), 401
    return jsonify({"user": _public_user(user)})
