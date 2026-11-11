"""Unit tests for backend.intelligence.enrich (mocked network + mocked DB)."""
from datetime import datetime, timedelta

from backend.intelligence import enrich


SITE = {"id": b"\x00" * 16, "website_id": "w1", "domain": "evil.example",
        "ssl_valid": None, "dmarc_exists": None, "spf_exists": None,
        "blacklist_matches": 0, "whois_fetched_at": None}


def _patch_all(monkeypatch, site=None, dns=None, tls=None, who=None,
               score=42.5):
    monkeypatch.setattr(enrich, "check_dns",
                        lambda domain: dict(dns if dns is not None else {}))
    monkeypatch.setattr(enrich, "inspect_ssl",
                        lambda domain: dict(tls if tls is not None else {}))
    monkeypatch.setattr(enrich, "lookup_whois",
                        lambda domain: dict(who if who is not None else {}))
    calls = {"updates": [], "selects": []}

    def fake_query_one(sql, params=None):
        calls["selects"].append(sql)
        if "FROM website_urls" in sql:
            return dict(site if site is not None else {})
        if "fn_calculate_risk_score" in sql:
            return {"score": score}
        return None

    def fake_query(sql, params=None):
        calls["updates"].append((sql, params))
        return []

    monkeypatch.setattr(enrich.db, "query_one", fake_query_one)
    monkeypatch.setattr(enrich.db, "query", fake_query)
    return calls


def test_missing_target():
    out = enrich.enrich_website()
    assert out == {"enriched": False, "reason": "no-target"}


def test_unknown_website(monkeypatch):
    _patch_all(monkeypatch, site=None)
    assert enrich.enrich_website(website_id="w9")["reason"] == "not-found"


def test_fresh_skip(monkeypatch):
    site = dict(SITE, whois_fetched_at=datetime.now())
    _patch_all(monkeypatch, site=site)
    out = enrich.enrich_website(website_id="w1")
    assert out == {"enriched": False, "reason": "fresh", "website_id": "w1"}


def test_force_ignores_freshness(monkeypatch):
    site = dict(SITE, whois_fetched_at=datetime.now())
    calls = _patch_all(monkeypatch, site=site)
    out = enrich.enrich_website(website_id="w1", force=True)
    assert out["enriched"] is True
    assert any("UPDATE website_urls" in sql for sql, _ in calls["updates"])


def test_stale_enriches_and_maps_signals(monkeypatch):
    site = dict(SITE, whois_fetched_at=datetime.now() - timedelta(days=3))
    calls = _patch_all(
        monkeypatch, site=site,
        dns={"dmarcExists": False, "spfExists": True},
        tls={"valid": True, "issuer": "Lets Encrypt", "validTo": "Nov  1 12:00:00 2027 GMT"},
        who={"registrar": "Example Registrar",
             "creationDate": "2020-05-01 10:00:00",
             "expirationDate": "2027-05-01 10:00:00"})
    out = enrich.enrich_website(website_id="w1")
    assert out["enriched"] is True
    assert out["signals"] == {"dmarc": False, "spf": True, "ssl": True,
                              "registrar": "Example Registrar"}
    update_sql = " ".join(sql for sql, _ in calls["updates"])
    for col in ("dmarc_exists", "spf_exists", "ssl_valid", "ssl_issuer",
                "ssl_expiry_date", "registrar", "registration_date",
                "expiration_date", "whois_data", "whois_fetched_at"):
        assert col in update_sql, col
    assert out["score"] == 42.5 and out["level"] == "medium"


def test_tls_error_leaves_ssl_untouched(monkeypatch):
    calls = _patch_all(monkeypatch, site=dict(SITE),
                       tls={"valid": False, "error": "timeout"})
    enrich.enrich_website(domain="evil.example")
    update_sql = " ".join(sql for sql, _ in calls["updates"])
    assert "ssl_valid" not in update_sql
    assert "dmarc_exists" in update_sql  # DNS answers still stored


def test_lookup_exceptions_never_raise(monkeypatch):
    monkeypatch.setattr(enrich.db, "query_one", lambda *a, **k: 1 / 0)
    monkeypatch.setattr(enrich.db, "query", lambda *a, **k: [])
    out = enrich.enrich_website(website_id="w1")
    assert out["enriched"] is False


def test_rescore_bands(monkeypatch):
    site = dict(SITE)
    for score, level in [(95, "critical"), (70, "high"), (50, "medium"),
                         (25, "low"), (10, "safe")]:
        calls = _patch_all(monkeypatch, site=site, score=score)
        out = enrich.enrich_website(website_id="w1", force=True)
        assert out["level"] == level, score


def test_whois_date_parsing():
    from datetime import date
    assert enrich._parse_whois_dt(datetime(2021, 3, 4, 5, 6)) == date(2021, 3, 4)
    assert enrich._parse_whois_dt("2021-03-04 05:06:07") == date(2021, 3, 4)
    assert enrich._parse_whois_dt(None) is None
    assert enrich._parse_whois_dt("garbage") is None


def test_domain_cleaning():
    assert enrich._clean_domain("  Evil.Example:443/x ") == "evil.example"
