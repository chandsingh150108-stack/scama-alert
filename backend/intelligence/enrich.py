"""Live technical-intelligence enrichment for website_urls."""
from datetime import datetime, timedelta
import math

from backend import db
from backend.intelligence.dns import check_dns
from backend.intelligence.ssl import inspect_ssl
from backend.intelligence.threat_intel import evaluate_threat_intel
from backend.intelligence.tld import get_tld_reputation_score
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
        return value.replace(tzinfo=None)
    try:
        return datetime.fromisoformat(str(value)[:19])
    except Exception:
        return None


def _clean_domain(domain):
    return (domain or "").strip().lower().split("://")[-1].split("/")[0].split(":")[0]


def _sql_style_subscores(wid, threat_meta=None):
    """Recompute community/automated/severity mirroring fn_calculate_risk_score,
    while enriching the stored JSON `signals` breakdown with threat-intelligence
    and heuristic provenance.
    """
    try:
        r = db.query_one(
            "SELECT COUNT(*) AS n FROM fraud_reports WHERE website_url_id = UUID_TO_BIN(%s)",
            (wid,)) or {}
        report_count = int(r.get("n", 0) or 0)
    except Exception:
        report_count = 0
    try:
        v = db.query_one(
            "SELECT COALESCE(SUM(confirm_votes),0) AS c, COALESCE(SUM(deny_votes),0) AS d "
            "FROM fraud_reports WHERE website_url_id = UUID_TO_BIN(%s)", (wid,)) or {}
        confirm_votes = int(v.get("c", 0) or 0)
        deny_part = int(v.get("d", 0) or 0)
        total_votes = confirm_votes + deny_part
    except Exception:
        confirm_votes, total_votes = 0, 0
    try:
        s = db.query_one(
            "SELECT COALESCE(AVG(c.severity_weight),0) AS avg_sev FROM fraud_reports fr "
            "JOIN categories c ON c.id = fr.category_id "
            "WHERE fr.website_url_id = UUID_TO_BIN(%s)", (wid,)) or {}
        sev_avg = float(s.get("avg_sev", 0) or 0)
    except Exception:
        sev_avg = 0.0
    try:
        dc = db.query_one(
            "SELECT COUNT(DISTINCT reporter_id) AS n FROM fraud_reports "
            "WHERE website_url_id = UUID_TO_BIN(%s)", (wid,)) or {}
        distinct_reporters = int(dc.get("n", 0) or 0)
    except Exception:
        distinct_reporters = 0
    try:
        dd = db.query_one(
            "SELECT DATEDIFF(NOW(), MIN(created_at)) AS d FROM fraud_reports "
            "WHERE website_url_id = UUID_TO_BIN(%s)", (wid,)) or {}
        days = dd.get("d")
        days = int(days) if days is not None else None
    except Exception:
        days = None
    try:
        w = db.query_one(
            "SELECT domain, full_url, ssl_valid, dmarc_exists, spf_exists, blacklist_matches, registration_date "
            "FROM website_urls WHERE id = UUID_TO_BIN(%s)", (wid,)) or {}
    except Exception:
        w = {}

    # --- community (mirrors fn: log count max 25 + consensus 15 + corroboration + recency) ---
    community = min(25, math.log(max(report_count, 1) + 1) * 5.4)
    if total_votes > 0:
        community += (confirm_votes / total_votes) * 15
    if distinct_reporters >= 3:
        community += 10
    if days is None:
        community += 2.5
    elif days <= 7:
        community += 10
    elif days <= 30:
        community += 7.5
    elif days <= 90:
        community += 5
    else:
        community += 2.5
    community = min(100, community)

    # --- automated (NULL contributes 0, only explicit FALSE scores — like `= FALSE` in SQL) ---
    automated = 0.0
    if w.get("ssl_valid") == 0:
        automated += 10
    if w.get("dmarc_exists") == 0:
        automated += 5
    if w.get("spf_exists") == 0:
        automated += 5
    try:
        automated += min(20, int(w.get("blacklist_matches", 0) or 0) * 4)
    except Exception:
        pass
    automated = min(100, automated)

    dom = str(w.get("domain") or "")
    signals = {
        "report_count": report_count,
        "confirm_votes": confirm_votes,
        "total_votes": total_votes,
        "distinct_reporters": distinct_reporters,
        "days_since_first": days,
        "ssl_valid": w.get("ssl_valid"),
        "dmarc_exists": w.get("dmarc_exists"),
        "spf_exists": w.get("spf_exists"),
        "blacklist_matches": w.get("blacklist_matches", 0),
        "tld_reputation_score": get_tld_reputation_score(dom),
    }
    if threat_meta:
        signals["matched_threat_sources"] = threat_meta.get("matchedSources", [])
        signals["impersonation_score"] = threat_meta.get("impersonationScore", 0)
        signals["heuristic_reasons"] = threat_meta.get("heuristicReasons", [])
        signals["impersonated_brand"] = threat_meta.get("impersonatedBrand")
    return round(community, 2), round(automated, 2), round(sev_avg, 2), signals


def _rescore(wid, threat_meta=None):
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
    community, automated, sev_avg, signals = _sql_style_subscores(wid, threat_meta=threat_meta)
    db.query("INSERT INTO risk_score_breakdowns (id, website_url_id, community_sub_score, "
             "automated_sub_score, category_severity_avg, final_score, signals, calculated_at) "
             "VALUES (UUID_TO_BIN(UUID()), UUID_TO_BIN(%s), %s, %s, %s, %s, CAST(%s AS JSON), NOW())",
             (wid, community, automated, sev_avg, score, db.to_json(signals)))
    return score, level


def rescore_website(website_id):
    """Recompute risk_score/level + breakdown row. Never raises."""
    try:
        score, level = _rescore(website_id)
        return {"rescored": True, "website_id": website_id,
                "score": score, "level": level}
    except Exception as e:
        return {"rescored": False, "reason": f"error: {e}"}


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
            try:
                score, level = _rescore(wid)
                return {"enriched": False, "reason": "fresh",
                        "website_id": wid, "rescored": True,
                        "score": score, "level": level}
            except Exception:
                return {"enriched": False, "reason": "fresh",
                        "website_id": wid, "rescored": False}

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

    target_url = site.get("full_url") or dom
    existing_bl = int(site.get("blacklist_matches", 0) or 0)
    try:
        threat_meta = evaluate_threat_intel(
            target_url,
            existing_db_matches=existing_bl,
            refresh_feeds_if_stale=True,
            check_live_dns_api=True,
        )
    except Exception:
        threat_meta = {"effectiveBlacklistMatches": existing_bl, "matchedSources": [], "heuristicReasons": []}

    sets, params = [], []

    # DNS booleans: only overwrite when lookup actually answered (not None).
    if dns.get("dmarcExists") is not None:
        sets.append("dmarc_exists = %s")
        params.append(bool(dns.get("dmarcExists")))
    if dns.get("spfExists") is not None:
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

    # Threat intelligence / effective blacklist matches
    eff_bl = threat_meta.get("effectiveBlacklistMatches")
    if eff_bl is not None:
        sets.append("blacklist_matches = %s")
        params.append(int(eff_bl))

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
    if who and not who.get("error"):
        who_payload = dict(who)
        if threat_meta.get("matchedSources") or threat_meta.get("heuristicReasons"):
            who_payload["threatIntel"] = {
                "matchedSources": threat_meta.get("matchedSources", []),
                "heuristicReasons": threat_meta.get("heuristicReasons", []),
                "impersonatedBrand": threat_meta.get("impersonatedBrand"),
            }
        sets.append("whois_data = CAST(%s AS JSON)")
        params.append(db.to_json(who_payload))

    # Always stamp the attempt (negative caching for dead domains).
    sets.append("whois_fetched_at = NOW()")

    db.query("UPDATE website_urls SET " + ", ".join(sets) +
             " WHERE id = UUID_TO_BIN(%s)", tuple(params) + (wid,))

    score, level = _rescore(wid, threat_meta=threat_meta)
    return {
        "enriched": True,
        "website_id": wid,
        "domain": dom,
        "signals": {
            "dmarc": dns.get("dmarcExists"),
            "spf": dns.get("spfExists"),
            "ssl": bool(tls.get("valid")) if not tls.get("error") else None,
            "registrar": who.get("registrar"),
            "blacklistMatches": eff_bl,
            "matchedSources": threat_meta.get("matchedSources", []),
            "heuristicReasons": threat_meta.get("heuristicReasons", []),
        },
        "score": score,
        "level": level,
    }
