"""14 cases mirroring risk/calculator.test.ts (mocked DB)."""
from backend.risk import calculator as calc

BASE_SITE = {"id": "w1", "domain": "evil.xyz", "ssl_valid": True, "dmarc_exists": True,
             "spf_exists": True, "blacklist_matches": 0, "registration_date": None}


def _patch(monkeypatch, site=None, reports=None, evidence=0, avg_rep=0):
    monkeypatch.setattr(calc.db, "query_one", lambda sql, params=None: (
        dict(site or BASE_SITE) if "website_urls WHERE id" in sql
        else ({"count": evidence} if "report_evidence" in sql
              else ({"avg_rep": avg_rep} if "AVG" in sql else None))))
    monkeypatch.setattr(calc.db, "query", lambda sql, params=None: list(reports or []))


def test_missing_website(monkeypatch):
    monkeypatch.setattr(calc.db, "query_one", lambda *a, **k: None)
    try:
        calc.calculate_risk_score("nope")
        assert False
    except ValueError:
        pass


def test_empty_reports_defaults(monkeypatch):
    _patch(monkeypatch)
    out = calc.calculate_risk_score("w1")
    assert 0 <= out["finalScore"] <= 100
    assert out["riskLevel"] in ("safe", "low", "medium", "high", "critical")
    assert out["categorySeverityAvg"] == 4.0


def test_bounds_and_shape(monkeypatch):
    reps = [{"confirm_votes": 5, "deny_votes": 1, "total_votes": 6, "reporter_id": f"u{i}",
             "created_at": "2026-01-01T00:00:00", "severity_weight": 9.0} for i in range(5)]
    _patch(monkeypatch, reports=reps, evidence=3, avg_rep=80,
           site=dict(BASE_SITE, ssl_valid=False, dmarc_exists=False, spf_exists=False,
                     blacklist_matches=3, domain="evil.xin"))
    out = calc.calculate_risk_score("w1")
    assert out["finalScore"] <= 100
    assert out["blacklistScore"] == 12
    assert out["sslScore"] == 10
    assert out["dmarcSpfScore"] == 10
    assert out["tldReputationScore"] == 100
    for k in ("websiteId", "domain", "communitySubScore", "automatedSubScore",
              "finalScore", "riskLevel"):
        assert k in out


def test_ssl_response(monkeypatch):
    _patch(monkeypatch, site=dict(BASE_SITE, ssl_valid=True))
    assert calc.calculate_risk_score("w1")["sslScore"] == 0
    _patch(monkeypatch, site=dict(BASE_SITE, ssl_valid=False))
    assert calc.calculate_risk_score("w1")["sslScore"] == 10


def test_blacklist_cap(monkeypatch):
    _patch(monkeypatch, site=dict(BASE_SITE, blacklist_matches=99))
    assert calc.calculate_risk_score("w1")["blacklistScore"] == 20


def test_vote_consensus_zero(monkeypatch):
    _patch(monkeypatch, reports=[{"confirm_votes": 0, "deny_votes": 0, "total_votes": 0,
                                   "reporter_id": "u1", "created_at": "2026-01-01T00:00:00",
                                   "severity_weight": 5.0}])
    assert calc.calculate_risk_score("w1")["voteConsensusScore"] == 0


def test_null_intel_scores_zero_like_sql(monkeypatch):
    """Unmeasured (NULL) signals contribute 0, matching fn_calculate_risk_score
    where `IF v_ssl_valid = FALSE` is not true for NULL."""
    _patch(monkeypatch, site=dict(BASE_SITE, ssl_valid=None, dmarc_exists=None,
                                  spf_exists=None, blacklist_matches=None))
    out = calc.calculate_risk_score("w1")
    assert out["sslScore"] == 0
    assert out["dmarcSpfScore"] == 0
    assert out["blacklistScore"] == 0
