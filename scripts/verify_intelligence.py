#!/usr/bin/env python3
"""Manual verification script for SSL/WHOIS/DNS intelligence modules.

Run after docker compose up + db_setup.py:
    python scripts/verify_intelligence.py

Tests against seeded domains + known good/bad domains.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.intelligence.ssl import inspect_ssl
from backend.intelligence.whois import lookup_whois
from backend.intelligence.dns import check_dns
from backend.intelligence.tld import get_tld_reputation_score, get_tld_reputation
from backend.intelligence import enrich
from backend import db


SEED_DOMAINS = [
    "investquick.xyz",
    "cheapdeals.shop",
    "bankofindia-secure.xyz",
    "jobfresher.com",
    "payeazy.in",
    "flipkart-sale.com",
    "legitmart.com",
    "knowngood.in",
]

KNOWN_GOOD = [
    "google.com",
    "github.com",
    "microsoft.com",
]

KNOWN_BAD_SSL = [
    "expired.badssl.com",
    "self-signed.badssl.com",
    "wrong.host.badssl.com",
]


def print_header(title: str):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")


def print_subheader(title: str):
    print(f"\n--- {title} ---")


def test_ssl(domains: list, label: str):
    print_header(f"SSL INSPECTION: {label}")
    for domain in domains:
        print_subheader(domain)
        try:
            result = inspect_ssl(domain)
            print(f"  valid: {result.get('valid')}")
            if result.get("valid"):
                print(f"  issuer: {result.get('issuer')}")
                print(f"  subject: {result.get('subject')}")
                print(f"  validTo: {result.get('validTo')}")
                print(f"  daysUntilExpiry: {result.get('daysUntilExpiry')}")
                print(f"  selfSigned: {result.get('selfSigned')}")
            else:
                print(f"  error: {result.get('error')}")
                print(f"  reason: {result.get('reason')}")
        except Exception as e:
            print(f"  EXCEPTION: {e}")


def test_whois(domains: list, label: str):
    print_header(f"WHOIS LOOKUP: {label}")
    for domain in domains:
        print_subheader(domain)
        try:
            result = lookup_whois(domain)
            print(f"  registrar: {result.get('registrar')}")
            print(f"  creationDate: {result.get('creationDate')}")
            print(f"  expirationDate: {result.get('expirationDate')}")
            print(f"  domainAge: {result.get('domainAge')}")
            print(f"  nameServers: {result.get('nameServers')}")
            print(f"  registrantOrganization: {result.get('registrantOrganization')}")
            print(f"  registrantCountry: {result.get('registrantCountry')}")
            print(f"  privacyEnabled: {result.get('privacyEnabled')}")
        except Exception as e:
            print(f"  EXCEPTION: {e}")


def test_dns(domains: list, label: str):
    print_header(f"DNS CHECKS: {label}")
    for domain in domains:
        print_subheader(domain)
        try:
            result = check_dns(domain)
            print(f"  dmarcExists: {result.get('dmarcExists')}")
            print(f"  dmarcPolicy: {result.get('dmarcPolicy')}")
            print(f"  spfExists: {result.get('spfExists')}")
            print(f"  spfRecord: {result.get('spfRecord')}")
            print(f"  mxExists: {result.get('mxExists')}")
            print(f"  mxRecords: {result.get('mxRecords')}")
        except Exception as e:
            print(f"  EXCEPTION: {e}")


def test_tld(domains: list, label: str):
    print_header(f"TLD REPUTATION: {label}")
    for domain in domains:
        print_subheader(domain)
        try:
            rep = get_tld_reputation(domain)
            score = get_tld_reputation_score(domain)
            print(f"  tld: {rep.get('tld')}")
            print(f"  riskLevel: {rep.get('riskLevel')}")
            print(f"  reason: {rep.get('reason')}")
            print(f"  score: {score}")
        except Exception as e:
            print(f"  EXCEPTION: {e}")


def test_enrich():
    print_header("FULL ENRICHMENT (enrich_website)")
    print("Querying seeded websites from DB...")
    sites = db.query("SELECT BIN_TO_UUID(id) as website_id, domain FROM website_urls")
    if not sites:
        print("  No websites found in DB. Run db_setup.py first.")
        return

    for site in sites:
        wid = site["website_id"]
        domain = site["domain"]
        print_subheader(f"{domain} ({wid})")

        # Show before state
        before = db.query_one(
            "SELECT ssl_valid, dmarc_exists, spf_exists, blacklist_matches, "
            "registrar, registration_date, expiration_date, whois_fetched_at, "
            "risk_score, risk_level FROM website_urls WHERE id = UUID_TO_BIN(%s)",
            (wid,)
        )
        print("  BEFORE:")
        print(f"    ssl_valid: {before.get('ssl_valid')}")
        print(f"    dmarc_exists: {before.get('dmarc_exists')}")
        print(f"    spf_exists: {before.get('spf_exists')}")
        print(f"    blacklist_matches: {before.get('blacklist_matches')}")
        print(f"    registrar: {before.get('registrar')}")
        print(f"    registration_date: {before.get('registration_date')}")
        print(f"    expiration_date: {before.get('expiration_date')}")
        print(f"    whois_fetched_at: {before.get('whois_fetched_at')}")
        print(f"    risk_score: {before.get('risk_score')}")
        print(f"    risk_level: {before.get('risk_level')}")

        # Run enrichment
        print("  Running enrich_website(force=True)...")
        result = enrich.enrich_website(website_id=wid, force=True)
        print(f"  Result: {result}")

        # Show after state
        after = db.query_one(
            "SELECT ssl_valid, dmarc_exists, spf_exists, blacklist_matches, "
            "registrar, registration_date, expiration_date, whois_fetched_at, "
            "risk_score, risk_level FROM website_urls WHERE id = UUID_TO_BIN(%s)",
            (wid,)
        )
        print("  AFTER:")
        print(f"    ssl_valid: {after.get('ssl_valid')}")
        print(f"    dmarc_exists: {after.get('dmarc_exists')}")
        print(f"    spf_exists: {after.get('spf_exists')}")
        print(f"    blacklist_matches: {after.get('blacklist_matches')}")
        print(f"    registrar: {after.get('registrar')}")
        print(f"    registration_date: {after.get('registration_date')}")
        print(f"    expiration_date: {after.get('expiration_date')}")
        print(f"    whois_fetched_at: {after.get('whois_fetched_at')}")
        print(f"    risk_score: {after.get('risk_score')}")
        print(f"    risk_level: {after.get('risk_level')}")

        # Show breakdown
        breakdown = db.query_one(
            "SELECT community_sub_score, automated_sub_score, category_severity_avg, "
            "final_score, signals, calculated_at FROM risk_score_breakdowns "
            "WHERE website_url_id = UUID_TO_BIN(%s) ORDER BY calculated_at DESC LIMIT 1",
            (wid,)
        )
        if breakdown:
            print("  LATEST BREAKDOWN:")
            print(f"    community_sub_score: {breakdown.get('community_sub_score')}")
            print(f"    automated_sub_score: {breakdown.get('automated_sub_score')}")
            print(f"    category_severity_avg: {breakdown.get('category_severity_avg')}")
            print(f"    final_score: {breakdown.get('final_score')}")
            print(f"    signals: {breakdown.get('signals')}")
            print(f"    calculated_at: {breakdown.get('calculated_at')}")


def main():
    print("ScamAlert Intelligence Verification")
    print("====================================")

    # Test individual modules
    test_ssl(SEED_DOMAINS, "Seeded Domains")
    test_ssl(KNOWN_GOOD, "Known Good Domains")
    test_ssl(KNOWN_BAD_SSL, "Known Bad SSL Domains")

    test_whois(SEED_DOMAINS, "Seeded Domains")
    test_whois(KNOWN_GOOD, "Known Good Domains")

    test_dns(SEED_DOMAINS, "Seeded Domains")
    test_dns(KNOWN_GOOD, "Known Good Domains")

    test_tld(SEED_DOMAINS + KNOWN_GOOD, "All Test Domains")

    # Test full enrichment (requires DB)
    test_enrich()

    print_header("VERIFICATION COMPLETE")


if __name__ == "__main__":
    main()