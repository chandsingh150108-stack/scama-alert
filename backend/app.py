"""Flask application factory. Serves /api/* + static frontend/."""
import datetime
import decimal
import logging
import os
import uuid

from flask import Flask, jsonify, redirect, request, send_from_directory, session
from flask.json.provider import DefaultJSONProvider
from flask_session import Session

from backend.config import Config

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


class _SafeJSONProvider(DefaultJSONProvider):
    """Serialize MySQL driver types: BINARY(16) UUIDs, Decimals, datetimes.

    Raw BINARY columns (fr.*, d.*, etc.) come back as bytes; views alias
    UUIDs as strings but base-table SELECTs still carry byte columns.
    """

    @staticmethod
    def default(o):
        if isinstance(o, (bytes, bytearray)):
            b = bytes(o)
            if len(b) == 16:
                try:
                    return str(uuid.UUID(bytes=b))
                except Exception:
                    pass
            try:
                return b.decode("utf-8")
            except Exception:
                return b.hex()
        if isinstance(o, decimal.Decimal):
            return float(o)
        if isinstance(o, (datetime.datetime, datetime.date)):
            return o.isoformat()
        return super().default(o)


def create_app():
    root = os.path.join(os.path.dirname(__file__), "..")
    frontend_dir = os.path.join(root, "frontend")
    app = Flask(__name__, static_folder=frontend_dir, static_url_path="")
    app.json_provider_class = _SafeJSONProvider
    app.json = _SafeJSONProvider(app)
    app.config.from_object(Config)
    app.secret_key = Config.SECRET_KEY
    app.permanent_session_lifetime = Config.PERMANENT_SESSION_LIFETIME
    Session(app)

    @app.errorhandler(400)
    def _400(e):
        return jsonify({"error": "Bad request"}), 400

    @app.errorhandler(401)
    def _401(e):
        return jsonify({"error": "Unauthorized"}), 401

    @app.errorhandler(403)
    def _403(e):
        return jsonify({"error": "Forbidden"}), 403

    @app.errorhandler(404)
    def _404(e):
        if (request.path or "").startswith(("/api/", "/uploads/")):
            return jsonify({"error": "Not found"}), 404
        index = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index):
            return app.send_static_file("index.html")
        return jsonify({"error": "Not found"}), 404

    @app.before_request
    def _admin_gate():
        # Mirror src/middleware.ts: /admin* HTML pages redirect to login when
        # no session cookie. API paths return JSON 401 instead (handled per-route).
        path = request.path or ""
        if path.startswith("/api/"):
            return None
        if path.startswith("/admin"):
            if not session.get("user_id"):
                return redirect(f"/login?callbackUrl={path}", code=302)
        return None

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/uploads/<path:filename>")
    def _uploads(filename):
        # Serve evidence files written by backend/evidence/handler.py
        # (upload root <cwd>/uploads). send_from_directory confines access
        # to that dir; missing files 404 instead of falling through to the
        # SPA index.html fallback below.
        upload_dir = os.path.join(os.getcwd(), "uploads")
        return send_from_directory(upload_dir, filename)

    # Blueprint registration (all /api/* routes).
    from backend.routes import (
        admin,
        appeals,
        auth_routes,
        comment,
        comment_vote,
        complaint_route,
        discussions,
        evidence,
        history,
        report_detail,
        reports,
        search,
        users,
        vote,
        websites,
    )

    app.register_blueprint(auth_routes.bp)
    app.register_blueprint(reports.bp)
    app.register_blueprint(report_detail.bp)
    app.register_blueprint(vote.bp)
    app.register_blueprint(comment.bp)
    app.register_blueprint(comment_vote.bp)
    app.register_blueprint(history.bp)
    app.register_blueprint(complaint_route.bp)
    app.register_blueprint(search.bp)
    app.register_blueprint(users.bp)
    app.register_blueprint(websites.bp)
    app.register_blueprint(evidence.bp)
    app.register_blueprint(appeals.bp)
    app.register_blueprint(discussions.bp)
    app.register_blueprint(admin.bp)

    # Static page routes (Flask-serves-static).
    @app.get("/")
    def _index():
        return app.send_static_file("index.html")

    # Pretty URLs mirroring the original Next.js routes (/reports/<id>, etc.).
    # Detail-page JS reads the id from either the path or ?id=.
    @app.get("/reports")
    def _reports():
        return app.send_static_file("reports.html")

    @app.get("/reports/new")
    def _report_new():
        return app.send_static_file("report-new.html")

    @app.get("/reports/<rid>")
    def _report_page(rid):
        return app.send_static_file("report-detail.html")

    @app.get("/search")
    def _search():
        return app.send_static_file("search.html")

    @app.get("/discussions")
    def _discussions():
        return app.send_static_file("discussions.html")

    @app.get("/discussions/<did>")
    def _discussion_page(did):
        return app.send_static_file("discussion-detail.html")

    @app.get("/users")
    def _users():
        return app.send_static_file("users.html")

    @app.get("/users/<uid>")
    def _user_page(uid):
        return app.send_static_file("user-detail.html")

    @app.get("/websites/<wid>")
    def _website_page(wid):
        return app.send_static_file("website-detail.html")

    @app.get("/login")
    def _login():
        return app.send_static_file("login.html")

    @app.get("/signup")
    def _signup():
        return app.send_static_file("signup.html")

    @app.get("/help")
    def _help():
        return app.send_static_file("help.html")

    @app.get("/admin")
    @app.get("/admin/<section>")
    def _admin(section="reports"):
        mapping = {"reports": "admin-reports.html", "appeals": "admin-appeals.html",
                   "config": "admin-config.html"}
        target = mapping.get(section)
        if not target:
            return jsonify({"error": "Not found"}), 404
        return app.send_static_file(target)

    @app.get("/<page>.html")
    def _page(page):
        allowed = {
            "index", "reports", "report-detail", "report-new", "search",
            "discussions", "discussion-detail", "users", "user-detail",
            "website-detail", "login", "signup", "help",
            "admin-reports", "admin-appeals", "admin-config",
        }
        if page not in allowed:
            return jsonify({"error": "Not found"}), 404
        return app.send_static_file(f"{page}.html")

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
