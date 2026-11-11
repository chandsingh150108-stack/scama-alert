"""Risk score calculator. Verbatim port of src/lib/risk/calculator.ts, except
that unknown (NULL) intel signals score 0 to match the frozen
fn_calculate_risk_score: in SQL, `IF v_ssl_valid = FALSE` is not true for NULL,
so unmeasured columns contribute nothing. (mysql-connector returns booleans as
0/1, hence the `== 0` checks below which also catch False.)

Remaining intentional divergences from the SQL function (Python-only extras):
corroboration tiers 15/10/0 vs SQL flat +10, plus domain-age, WHOIS-privacy,
TLD, evidence-quality, and reporter-reputation signals that SQL does not have.
"""
import math
from datetime import datetime, timezone

from backend import db
from backend.intelligence.tld import get_tld_reputation_score


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

    domain_age_score = 5
    if website.get("registration_date"):
        try:
            reg = website["registration_date"]
            reg_dt = reg if hasattr(reg, "timestamp") else datetime.fromisoformat(str(reg))
            if reg_dt.tzinfo is None:
                reg_dt = reg_dt.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - reg_dt).days
            if age < 30:
                domain_age_score = 15
            elif age < 90:
                domain_age_score = 10
            elif age < 180:
                domain_age_score = 7
            elif age < 365:
                domain_age_score = 4
            else:
                domain_age_score = 2
        except Exception:
            pass
    ssl_score = 10 if website.get("ssl_valid") == 0 else 0
    whois_privacy_score = 10
    try:
        blacklist_score = min(20, int(website.get("blacklist_matches", 0) or 0) * 4)
    except Exception:
        blacklist_score = 0
    # NULL (unmeasured) matches SQL: contributes 0, only explicit FALSE scores.
    dmarc_spf = ((5 if website.get("dmarc_exists") == 0 else 0) +
                 (5 if website.get("spf_exists") == 0 else 0))
    tld_score = get_tld_reputation_score(str(website.get("domain", "")))
    automated = min(100, domain_age_score + ssl_score + whois_privacy_score + blacklist_score + dmarc_spf + tld_score)

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
        "dmarcSpfScore": dmarc_spf,
        "tldReputationScore": tld_score,
        "categorySeverityAvg": round(sev_avg, 2),
        "finalScore": min(100, max(0, final)),
        "riskLevel": level,
    }
