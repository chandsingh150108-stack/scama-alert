"""Live technical-intelligence enrichment for website_urls.

Before this module, the automated sub-score ran purely on stored columns that
nothing ever refreshed (seed/hand-written values plus NULLs). enrich_website()
closes that gap: it runs the real DNS / TLS / WHOIS checks from
backend.intelligence, writes the measurements into website_urls, and rescores
the site with the frozen fn_calculate_risk_score using the same level bands as
sp_recalculate_all_risk_scores.

Best-effort by design: every lookup is guarded and the function never raises,
so report submission succeeds even when the network or WHOIS is unavailable.

Known gaps (documented, not solved here):
- blacklist_matches has no keyless live source wired; it keeps its stored value.
- whois_fetched_at doubles as the enrichment freshness marker (24h TTL).
"""
from datetime import datetime, timedelta

from backend import db
from backend.intelligence.dns import check_dns
from backend.intelligence.ssl import inspect_ssl
from backend.intelligence.whois import lookup_whois

ENRICH_TTL = timedelta(hours=24)

_SSL_DATE_FMT = "%b %d %H:%M:%S %Y %Z"


def _parse_whois_dt(value):
    """WHOIS dates arrive as datetime or its str(); return a date or None."""
    if value is None:
        return None
    if hasattr(value, "date"):
        try:
            return value.date()
        except Exception:
            return None
    try:
        return datetime.fromisoformat(str(value).strip()[:19]).date()
    except Exception:
        return None


def _parse_ssl_dt(value):
    if not value:
        return None
    try:
        return datetime.strptime(str(value), _SSL_DATE_FMT)
    except Exception:
        return None


def _fetched_at(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value)[:19])
    except Exception:
        return None


def _clean_domain(domain):
    return (domain or "").strip().lower().split(":")[0].split("/")[0]


def _rescore(wid):
    """Single-site rescore mirroring sp_recalculate_all_risk_scores."""
    row = db.query_one(
        "SELECT fn_calculate_risk_score(UUID_TO_BIN(%s)) AS score", (wid,))
    try:
        score = float((row or {}).get("score") or 0)
    except Exception:
        score = 0.0
    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 40:
        level = "medium"
    elif score >= 20:
        level = "low"
    else:
        level = "safe"
    db.query("UPDATE website_urls SET risk_score = %s, risk_level = %s "
             "WHERE id = UUID_TO_BIN(%s)", (score, level, wid))
    db.query("INSERT INTO risk_score_breakdowns (id, website_url_id, final_score, "
             "calculated_at) VALUES (UUID_TO_BIN(UUID()), UUID_TO_BIN(%s), %s, NOW())",
             (wid, score))
    return score, level


def enrich_website(website_id=None, domain=None, force=False, max_age_hours=24):
    """Measure + store intel for one website, then rescore. Never raises."""
    try:
        return _enrich(website_id=website_id, domain=domain, force=force,
                       max_age_hours=max_age_hours)
    except Exception as e:
        return {"enriched": False, "reason": f"error: {e}"}


def _enrich(website_id=None, domain=None, force=False, max_age_hours=24):
    if website_id:
        site = db.query_one(
            "SELECT *, BIN_TO_UUID(id) AS website_id FROM website_urls "
            "WHERE id = UUID_TO_BIN(%s)", (website_id,))
    elif domain:
        site = db.query_one(
            "SELECT *, BIN_TO_UUID(id) AS website_id FROM website_urls "
            "WHERE domain = %s LIMIT 1", (_clean_domain(domain),))
    else:
        return {"enriched": False, "reason": "no-target"}
    if not site:
        return {"enriched": False, "reason": "not-found"}

    wid = site.get("website_id")
    dom = _clean_domain(site.get("domain"))
    if not dom:
        return {"enriched": False, "reason": "no-domain"}

    if not force:
        try:
            ttl = timedelta(hours=max_age_hours)
        except Exception:
            ttl = ENRICH_TTL
        fetched = _fetched_at(site.get("whois_fetched_at"))
        if fetched and (datetime.now() - fetched) < ttl:
            return {"enriched": False, "reason": "fresh", "website_id": wid}

    try:
        dns = check_dns(dom) or {}
    except Exception:
        dns = {}
    try:
        tls = inspect_ssl(dom) or {}
    except Exception:
        tls = {}
    try:
        who = lookup_whois(dom) or {}
    except Exception:
        who = {}

    sets, params = [], []

    # DNS booleans are real answers even when False (record genuinely absent).
    sets.append("dmarc_exists = %s")
    params.append(bool(dns.get("dmarcExists")))
    sets.append("spf_exists = %s")
    params.append(bool(dns.get("spfExists")))

    # TLS: only overwrite when the handshake actually answered; a timeout or
    # DNS failure is "unknown", not "invalid".
    if not tls.get("error"):
        sets.append("ssl_valid = %s")
        params.append(bool(tls.get("valid")))
        if tls.get("issuer"):
            sets.append("ssl_issuer = %s")
            params.append(str(tls["issuer"])[:255])
        expiry = _parse_ssl_dt(tls.get("validTo"))
        if expiry:
            sets.append("ssl_expiry_date = %s")
            params.append(expiry)

    # WHOIS registrar + dates when the lookup returned them.
    if who.get("registrar"):
        sets.append("registrar = %s")
        params.append(str(who["registrar"])[:255])
    reg = _parse_whois_dt(who.get("creationDate"))
    if reg:
        sets.append("registration_date = %s")
        params.append(reg)
    exp = _parse_whois_dt(who.get("expirationDate"))
    if exp:
        sets.append("expiration_date = %s")
        params.append(exp)
    if who:
        sets.append("whois_data = CAST(%s AS JSON)")
        params.append(db.to_json(who))

    # Always stamp the attempt (negative caching for dead domains).
    sets.append("whois_fetched_at = NOW()")

    db.query("UPDATE website_urls SET " + ", ".join(sets) +
             " WHERE id = UUID_TO_BIN(%s)", tuple(params) + (wid,))

    score, level = _rescore(wid)
    return {"enriched": True, "website_id": wid, "domain": dom,
            "signals": {"dmarc": bool(dns.get("dmarcExists")),
                        "spf": bool(dns.get("spfExists")),
                        "ssl": bool(tls.get("valid")) if not tls.get("error") else None,
                        "registrar": who.get("registrar")},
            "score": score, "level": level}
