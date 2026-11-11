"""Unit, edge-case, and benchmark tests for ScamAlert's threat intelligence module."""
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import unittest

from backend.intelligence.tld import get_tld_reputation_score
from backend.intelligence.threat_intel import (
    _memory_index,
    analyze_domain_heuristics,
    canonicalize_url,
    evaluate_threat_intel,
    parse_feed_lines,
)
from backend.risk.calculator import calculate_risk_score


class TestThreatIntelAndScoring(unittest.TestCase):

    def setUp(self):
        _memory_index["loaded_at"] = 0.0
        _memory_index["urls"] = {}
        _memory_index["hosts"] = {}
        _memory_index["domains"] = {}

    def test_url_canonicalization_and_idn_punycode(self):
        canon, host, reg = canonicalize_url("HTTPS://Sub.SBI.CO.IN:443//login//index.php#frag")
        self.assertEqual(host, "sub.sbi.co.in")
        self.assertEqual(reg, "sbi.co.in")
        self.assertEqual(canon, "http://sub.sbi.co.in/login/index.php")

        # IDN Unicode -> ASCII Punycode
        _, idn_host, _ = canonicalize_url("https://सबीआई.भारत/login")
        self.assertTrue(idn_host.startswith("xn--"))

    def test_shared_host_multi_tenant_isolation(self):
        """A phishing path on docs.google.com or github.io must NOT blacklist google.com or github.io."""
        feed_text = (
            "https://docs.google.com/forms/d/e/1FAIpQLScamForm/viewform\n"
            "https://evil-phish-kit.xyz/sbi/login.php\n"
        )
        parsed = parse_feed_lines(feed_text, "openphish", "phish_feed", 0.90)
        _memory_index["urls"] = parsed["urls"]
        _memory_index["hosts"] = parsed["hosts"]
        _memory_index["domains"] = parsed["domains"]

        # Exact scam Google Form URL matches
        exact_hit = evaluate_threat_intel("https://docs.google.com/forms/d/e/1FAIpQLScamForm/viewform")
        self.assertGreater(exact_hit["blacklistScore"], 20)

        # Benign Google Form URL or google.com root does NOT match
        benign_google = evaluate_threat_intel("https://docs.google.com/forms/d/e/BenignForm/viewform")
        self.assertEqual(benign_google["blacklistScore"], 0)
        root_google = evaluate_threat_intel("https://google.com")
        self.assertEqual(root_google["blacklistScore"], 0)

        # Dedicated malicious domain matches across paths on that domain
        other_path = evaluate_threat_intel("https://evil-phish-kit.xyz/other-page")
        self.assertGreater(other_path["blacklistScore"], 20)

    def test_cross_source_deduplication(self):
        """Duplicate feeds from the same source_family must not double-count, while independent families corroborate."""
        p1 = parse_feed_lines("http://scam-bank.top/login", "openphish", "phish_feed", 0.90)
        p2 = parse_feed_lines("http://scam-bank.top/login", "phishtank_mirror", "phish_feed", 0.85)
        p3 = parse_feed_lines("http://scam-bank.top/login", "urlhaus", "abuse_ch", 0.90)

        _memory_index["urls"] = p1["urls"]
        single_fam = evaluate_threat_intel("http://scam-bank.top/login")

        # Add duplicate within same family -> score must remain identical
        _memory_index["urls"]["http://scam-bank.top/login"].extend(p2["urls"]["http://scam-bank.top/login"])
        dup_fam = evaluate_threat_intel("http://scam-bank.top/login")
        self.assertEqual(single_fam["blacklistScore"], dup_fam["blacklistScore"])
        self.assertEqual(dup_fam["independentFamilies"], 1)

        # Add independent family -> score increases with corroboration
        _memory_index["urls"]["http://scam-bank.top/login"].extend(p3["urls"]["http://scam-bank.top/login"])
        multi_fam = evaluate_threat_intel("http://scam-bank.top/login")
        self.assertGreater(multi_fam["blacklistScore"], single_fam["blacklistScore"])
        self.assertEqual(multi_fam["independentFamilies"], 2)

    def test_malformed_feed_rejection(self):
        with self.assertRaises(ValueError):
            parse_feed_lines("<html><body>502 Bad Gateway</body></html>", "broken_feed", "phish_feed", 0.9)
        with self.assertRaises(ValueError):
            parse_feed_lines("# comment only\n\n", "empty_feed", "phish_feed", 0.9)

    def test_indian_brand_impersonation_vs_official_domains(self):
        # Official Indian domains must score 0 on impersonation
        for official in ("sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com", "uidai.gov.in", "irctc.co.in"):
            res = analyze_domain_heuristics(official)
            self.assertEqual(res["score"], 0, f"False positive on official domain {official}")

        # Impersonating domains must be detected
        for scam in ("sbi-kyc-update.xyz", "hdfcbank-netbanking.top", "paytm-reward-claim.sbs", "amaz0n.in"):
            res = analyze_domain_heuristics(scam)
            self.assertGreaterEqual(res["score"], 14, f"Missed brand impersonation on {scam}")

    def test_tld_normalization_and_indian_tlds(self):
        self.assertEqual(get_tld_reputation_score("sbi.co.in"), 0)
        self.assertEqual(get_tld_reputation_score("uidai.gov.in"), 0)
        self.assertEqual(get_tld_reputation_score("iitb.ac.in"), 0)
        self.assertEqual(get_tld_reputation_score("example.com"), 0)
        self.assertEqual(get_tld_reputation_score("startup.xyz"), 10)
        self.assertEqual(get_tld_reputation_score("scam.sbs"), 15)

    @patch("backend.risk.calculator.db")
    def test_calculator_benign_startup_vs_phishing_site(self, mock_db):
        """Verify that a legitimate startup on .xyz with GDPR WHOIS redaction and
        unmeasured/missing email records is no longer scored 99/100.
        """
        old_reg = datetime.now(timezone.utc) - timedelta(days=400)
        mock_db.query.return_value = []
        mock_db.query_one.side_effect = [
            {
                "id": b"1" * 16,
                "domain": "cleanstartup.xyz",
                "full_url": "https://cleanstartup.xyz",
                "registration_date": old_reg,
                "ssl_valid": 1,
                "dmarc_exists": None,  # Unmeasured
                "spf_exists": None,    # Unmeasured
                "blacklist_matches": 0,
                "whois_data": '{"privacyEnabled": false, "gdprRedacted": true}',
            },
            {"count": 0},
        ]
        res = calculate_risk_score("00000000-0000-0000-0000-000000000001")
        self.assertEqual(res["domainAgeScore"], 0)
        self.assertEqual(res["whoisPrivacyScore"], 0)
        self.assertEqual(res["dmarcSpfScore"], 0)
        self.assertEqual(res["tldReputationScore"], 10)
        self.assertEqual(res["automatedSubScore"], 10)
        self.assertEqual(res["riskLevel"], "safe")


if __name__ == "__main__":
    unittest.main()