"""GET /api/search. Mirror of search/route.ts.

Normalizes raw user input (e.g. pasted URLs like https://suspicious-site.example)
into safe BOOLEAN MODE terms, and falls back to LIKE across title/description/
domain when FULLTEXT yields nothing (covers site-name searches).
"""
import re

from flask import Blueprint, jsonify, request

from backend import db
from backend.utils import error_response

bp = Blueprint("search", __name__)

_BASE_SELECT = (
    "SELECT fr.*, BIN_TO_UUID(fr.id) AS id, u.name AS reporter_name, "
    "c.name AS category_name, w.domain AS domain, w.risk_level AS risk_level, "
    "CASE WHEN fr.title LIKE %s THEN 1 ELSE 0 END AS title_rank "
    "FROM fraud_reports fr JOIN users u ON u.id = fr.reporter_id "
    "JOIN categories c ON c.id = fr.category_id "
    "JOIN website_urls w ON w.id = fr.website_url_id "
)


def _normalize_query(q: str) -> str:
    text = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", q.strip())
    text = re.sub(r"[+\-<>()~*\"@]", " ", text)
    words = [w for w in re.split(r"[^A-Za-z0-9_]+", text) if w]
    return " ".join(words)


@bp.get("/api/search")
def search():
    q = request.args.get("q", "")
    if not q.strip():
        return error_response("Missing required query parameter: q", 400)
    limit = db.parse_int(request.args.get("limit"), 20)
    terms = _normalize_query(q)
    if not terms:
        return error_response("Missing required query parameter: q", 400)
    try:
        # 1. FULLTEXT over title/description (relevance-ranked).
        rows = db.query(
            _BASE_SELECT
            + "WHERE MATCH(fr.title, fr.description) AGAINST(%s IN BOOLEAN MODE) "
            "ORDER BY title_rank DESC LIMIT %s",
            (f"%{q}%", terms, limit))
        # 2. Always also match title/description/domain via LIKE so reports
        # that only match by domain (e.g. a fresh report whose title has no
        # search words) are included even when FULLTEXT found other rows.
        seen = {r.get("id") for r in (rows or [])}
        like = f"%{q.strip()}%"
        words = terms.split()
        domain_conds = " OR ".join(["w.domain LIKE %s"] * len(words))
        extra = db.query(
            _BASE_SELECT
            + "WHERE fr.title LIKE %s OR fr.description LIKE %s OR " + domain_conds + " "
            "ORDER BY title_rank DESC LIMIT %s",
            (f"%{q}%", like, like, *[f"%{w}%" for w in words], limit))
        for r in extra or []:
            if r.get("id") not in seen:
                rows.append(r)
                seen.add(r.get("id"))
    except Exception as e:
        return error_response(str(e), 500)
    return jsonify({"query": q, "results": rows, "count": len(rows)})
