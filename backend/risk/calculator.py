"""Risk score calculator. Normalizes all automated intelligence signals onto a
calibrated 0-100 scale, honors the NULL=0 convention for unmeasured signals,
reads actual WHOIS privacy data instead of hardcoding +10, and integrates
source-confidence-weighted threat intelligence and brand impersonation checks.
"""
from datetime import datetime, timezone
import json
import math

from backend import db
from backend.intelligence.threat_intel import evaluate_threat_intel
from backend.intelligence.tld import get_tld_reputation_score


def _extract_whois_privacy_score(whois_raw) -> int:
    """Return 2 points if explicit commercial WHOIS proxy privacy is enabled,
    0 if False, GDPR-redacted only, or NULL (unmeasured).
    """
    if not whois_raw:
        return 0
    try:
        data = json.loads(whois_raw) if isinstance(whois_raw, (str, bytes)) else whois_raw
        if isinstance(data, dict) and data.get("privacyEnabled") is True:
            return 2
    except Exception:
        pass
    return 0


def _calculate_domain_age_score(reg_value) -> int:
    """Return 0-15 points for newly registered domains.

    NULL (unmeasured) registration_date contributes 0 points, matching the
    frozen SQL NULL semantics. Established domains (>= 180 days) score 0.
    """
    if not reg_value:
        return 0
    try:
        reg_dt = reg_value if hasattr(reg_value, "timestamp") else datetime.fromisoformat(str(reg_value))
        if reg_dt.tzinfo is None:
            reg_dt = reg_dt.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - reg_dt).days
        if age < 0:
            return 0
        if age < 30:
            return 15
        if age < 90:
            return 10
        if age < 180:
            return 5
        return 0
    except Exception:
        return 0


def calculate_risk_score(website_id: str) -> dict:
    website = db.query_one("SELECT * FROM website_urls WHERE id = UUID_TO_BIN(%s)", (website_id,))
    if not website:
        raise ValueError("Website not found")

    reports = db.query(
        "SELECT fr.confirm_votes, fr.deny_votes, fr.total_votes, fr.reporter_id, fr.created_at, c.severity_weight "
        "FROM fraud_reports fr JOIN categories c ON c.id = fr.category_id "
        "WHERE fr.website_url_id = UUID_TO_BIN(%s)",
        (website_id,),
    ) or []
    ev = db.query_one(
        "SELECT COUNT(*) as count FROM report_evidence re "
        "JOIN fraud_reports fr ON fr.id = re.report_id "
        "WHERE fr.website_url_id = UUID_TO_BIN(%s)",
        (website_id,),
    )
    evidence_count = int((ev or {}).get("count", 0) or 0)

    report_count_score = min(25, math.log(len(reports) + 1) * 5.4)
    evidence_quality_score = min(20, evidence_count * 4)

    avg_rep = 0
    if reports:
        rep = db.query_one(
            "SELECT AVG(u.reputation_score) as avg_rep FROM fraud_reports fr "
            "JOIN users u ON u.id = fr.reporter_id WHERE fr.website_url_id = UUID_TO_BIN(%s)",
            (website_id,),
        )
        try:
            avg_rep = float((rep or {}).get("avg_rep") or 0)
        except Exception:
            avg_rep = 0
    reporter_reputation_score = min(15, (avg_rep / 100) * 15)

    unique_reporters = len({str(r.get("reporter_id")) for r in reports})
    corroboration_score = 15 if unique_reporters >= 3 else (10 if unique_reporters >= 2 else 0)

    recency_score = 2.5
    if reports:
        def _dt(r):
            v = r.get("created_at")
            try:
                return v if hasattr(v, "timestamp") else datetime.fromisoformat(str(v))
            except Exception:
                return datetime.now(timezone.utc)
        oldest = min(reports, key=_dt)
        try:
            first = _dt(oldest)
            if first.tzinfo is None:
                first = first.replace(tzinfo=timezone.utc)
            days = (datetime.now(timezone.utc) - first).days
            if days <= 7:
                recency_score = 10
            elif days <= 30:
                recency_score = 7.5
            elif days <= 90:
                recency_score = 5
        except Exception:
            pass

    total_confirm = sum(int(r.get("confirm_votes", 0) or 0) for r in reports)
    total_deny = sum(int(r.get("deny_votes", 0) or 0) for r in reports)
    total_votes = total_confirm + total_deny
    vote_consensus_score = (total_confirm / total_votes) * 15 if total_votes > 0 else 0

    community = min(100, report_count_score + evidence_quality_score + reporter_reputation_score
                    + corroboration_score + recency_score + vote_consensus_score)

    # --- Automated Intelligence Sub-Score ---
    domain_str = str(website.get("domain") or "")
    target_url = str(website.get("full_url") or domain_str)

    domain_age_score = _calculate_domain_age_score(website.get("registration_date"))
    ssl_score = 10 if website.get("ssl_valid") == 0 else 0
    whois_privacy_score = _extract_whois_privacy_score(website.get("whois_data"))

    try:
        db_bl_matches = int(website.get("blacklist_matches", 0) or 0)
    except Exception:
        db_bl_matches = 0

    intel = evaluate_threat_intel(
        target_url,
        existing_db_matches=db_bl_matches,
        refresh_feeds_if_stale=False,
        check_live_dns_api=False,
    )
    blacklist_score = intel["blacklistScore"]
    impersonation_score = intel["impersonationScore"]

    # NULL (unmeasured) contributes 0; only explicit FALSE (0) scores.
    dmarc_spf = ((5 if website.get("dmarc_exists") == 0 else 0) +
                 (5 if website.get("spf_exists") == 0 else 0))
    tld_score = get_tld_reputation_score(domain_str)

    # Weak configuration/metadata heuristics (WHOIS privacy, missing SPF/DMARC, TLD, domain age)
    # are capped at 35 points when there is neither blacklist evidence nor brand impersonation,
    # preventing benign startups from being misclassified as high risk.
    metadata_heuristic_score = domain_age_score + ssl_score + whois_privacy_score + dmarc_spf + tld_score
    if blacklist_score == 0 and impersonation_score == 0:
        metadata_heuristic_score = min(35, metadata_heuristic_score)

    automated = min(100, metadata_heuristic_score + blacklist_score + impersonation_score)

    if reports:
        try:
            sev_avg = sum(float(r.get("severity_weight", 4.0) or 4.0) for r in reports) / len(reports)
        except Exception:
            sev_avg = 4.0
    else:
        sev_avg = 4.0

    final = round(community * 0.4 + automated * 0.4 + sev_avg * 10 * 0.2)
    if final >= 80:
        level = "critical"
    elif final >= 60:
        level = "high"
    elif final >= 40:
        level = "medium"
    elif final >= 20:
        level = "low"
    else:
        level = "safe"

    return {
        "websiteId": website_id,
        "domain": website.get("domain"),
        "communitySubScore": round(community, 2),
        "reportCountScore": round(report_count_score, 2),
        "evidenceQualityScore": round(evidence_quality_score, 2),
        "reporterReputationScore": round(reporter_reputation_score, 2),
        "corroborationScore": corroboration_score,
        "recencyScore": recency_score,
        "voteConsensusScore": round(vote_consensus_score, 2),
        "automatedSubScore": round(automated, 2),
        "domainAgeScore": domain_age_score,
        "sslScore": ssl_score,
        "whoisPrivacyScore": whois_privacy_score,
        "blacklistScore": blacklist_score,
        "impersonationScore": impersonation_score,
        "dmarcSpfScore": dmarc_spf,
        "tldReputationScore": tld_score,
        "matchedThreatSources": intel["matchedSources"],
        "heuristicReasons": intel["heuristicReasons"],
        "categorySeverityAvg": round(sev_avg, 2),
        "finalScore": min(100, max(0, final)),
        "riskLevel": level,
    }
