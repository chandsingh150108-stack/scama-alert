"""26 cases mirroring src/lib/intelligence/tld.test.ts."""
from backend.intelligence.tld import get_tld_reputation, get_tld_reputation_score

CASES = [
    ("evil.xin", "critical"), ("evil.bond", "critical"), ("evil.buzz", "critical"),
    ("evil.sbs", "critical"), ("evil.cfd", "critical"),
    ("evil.xyz", "high"), ("evil.top", "high"), ("evil.tk", "critical"), ("evil.cc", "high"),
    ("evil.zip", "high"), ("evil.ml", "critical"),
    ("evil.info", "medium"), ("evil.click", "medium"), ("evil.online", "medium"),
    ("evil.site", "medium"), ("evil.store", "medium"),
    ("evil.shop", "low"), ("evil.io", "low"), ("evil.co", "low"),
    ("evil.com", "safe"), ("evil.org", "safe"), ("evil.in", "safe"),
    ("dept.gov.in", "safe"), ("univ.edu.in", "safe"),
    ("evil.unknowntld", "safe"), ("nodot", "safe"),
]


def test_tld_levels():
    for domain, level in CASES:
        assert get_tld_reputation(domain)["riskLevel"] == level, domain


def test_compound_priority():
    assert get_tld_reputation("dept.gov.in")["tld"] == ".gov.in"


def test_scores():
    assert get_tld_reputation_score("a.xin") == 15
    assert get_tld_reputation_score("a.xyz") == 10
    assert get_tld_reputation_score("a.info") == 6
    assert get_tld_reputation_score("a.io") == 2
    assert get_tld_reputation_score("a.com") == 0
