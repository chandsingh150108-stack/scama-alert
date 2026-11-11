-- ============================================================
-- ScamAlert — Views v1.0
-- 10 views demonstrating multi-table JOINs, subqueries,
-- GROUP_CONCAT, window functions, LEFT JOINs
-- ============================================================

USE scamalert;

-- ------------------------------------------------------------
-- 1. v_report_full_details
-- 4-table JOIN with GROUP_CONCAT for tags
-- ------------------------------------------------------------
CREATE OR REPLACE VIEW v_report_full_details AS
SELECT
  BIN_TO_UUID(fr.id) AS report_id,
  fr.title,
  fr.description,
  fr.status,
  fr.verification_stage,
  fr.amount_lost,
  fr.currency,
  fr.incident_date,
  fr.confirm_votes,
  fr.deny_votes,
  fr.total_votes,
  fr.is_anonymous,
  fr.created_at AS reported_at,
  -- Reporter info
  BIN_TO_UUID(u.id) AS reporter_id,
  u.name AS reporter_name,
  u.reputation_score AS reporter_reputation,
  u.reputation_tier AS reporter_tier,
  -- Category info
  c.name AS category_name,
  c.slug AS category_slug,
  c.severity_weight,
  c.icon AS category_icon,
  -- Website info
  wu.domain,
  wu.risk_score AS website_risk_score,
  wu.risk_level AS website_risk_level,
  -- Tags (aggregated)
  (SELECT GROUP_CONCAT(t.name ORDER BY t.name SEPARATOR ', ')
   FROM report_tags rt
   JOIN tags t ON t.id = rt.tag_id
   WHERE rt.report_id = fr.id) AS tags,
  -- Evidence count
  (SELECT COUNT(*) FROM report_evidence re WHERE re.report_id = fr.id) AS evidence_count
FROM fraud_reports fr
JOIN users u ON u.id = fr.reporter_id
JOIN categories c ON c.id = fr.category_id
JOIN website_urls wu ON wu.id = fr.website_url_id;

-- ------------------------------------------------------------
-- 2. v_website_risk_dashboard
-- Subqueries, GROUP BY for aggregated risk view
-- ------------------------------------------------------------
CREATE OR REPLACE VIEW v_website_risk_dashboard AS
SELECT
  BIN_TO_UUID(wu.id) AS website_id,
  wu.domain,
  wu.risk_score,
  wu.risk_level,
  wu.total_reports,
  wu.confirmed_reports,
  wu.active_reports,
  wu.first_reported_at,
  wu.last_reported_at,
  -- Technical signals
  wu.ssl_valid,
  wu.ssl_issuer,
  wu.dmarc_exists,
  wu.spf_exists,
  wu.blacklist_matches,
  wu.registration_date,
  -- Report breakdown by status
  (SELECT COUNT(*) FROM fraud_reports fr WHERE fr.website_url_id = wu.id AND fr.status = 'active') AS active_report_count,
  (SELECT COUNT(*) FROM fraud_reports fr WHERE fr.website_url_id = wu.id AND fr.status = 'archived') AS archived_report_count,
  (SELECT COUNT(*) FROM fraud_reports fr WHERE fr.website_url_id = wu.id AND fr.status = 'disputed') AS disputed_report_count,
  -- Category breakdown
  (SELECT GROUP_CONCAT(DISTINCT c.name ORDER BY c.name SEPARATOR ', ')
   FROM fraud_reports fr
   JOIN categories c ON c.id = fr.category_id
   WHERE fr.website_url_id = wu.id) AS categories,
  -- Vote consensus
  (SELECT COALESCE(SUM(fr.confirm_votes), 0) FROM fraud_reports fr WHERE fr.website_url_id = wu.id) AS total_confirm_votes,
  (SELECT COALESCE(SUM(fr.deny_votes), 0) FROM fraud_reports fr WHERE fr.website_url_id = wu.id) AS total_deny_votes,
  -- Latest risk breakdown
  (SELECT rsb.final_score FROM risk_score_breakdowns rsb WHERE rsb.website_url_id = wu.id ORDER BY rsb.calculated_at DESC LIMIT 1) AS latest_score,
  (SELECT rsb.community_sub_score FROM risk_score_breakdowns rsb WHERE rsb.website_url_id = wu.id ORDER BY rsb.calculated_at DESC LIMIT 1) AS community_score,
  (SELECT rsb.automated_sub_score FROM risk_score_breakdowns rsb WHERE rsb.website_url_id = wu.id ORDER BY rsb.calculated_at DESC LIMIT 1) AS automated_score
FROM website_urls wu;

-- ------------------------------------------------------------
-- 3. v_user_reputation_leaderboard
-- Multi-table aggregation for user rankings
-- ------------------------------------------------------------
CREATE OR REPLACE VIEW v_user_reputation_leaderboard AS
SELECT
  BIN_TO_UUID(u.id) AS user_id,
  u.name,
  u.reputation_score,
  u.reputation_tier,
  u.role,
  u.total_reports,
  u.verified_reports,
  u.total_votes_cast,
  u.accurate_votes,
  u.created_at AS joined_at,
  -- Recent report count (last 30 days)
  (SELECT COUNT(*)
   FROM fraud_reports fr
   WHERE fr.reporter_id = u.id
     AND fr.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) AS reports_last_30d,
  -- Recent vote count (last 30 days)
  (SELECT COUNT(*)
   FROM verification_votes vv
   WHERE vv.voter_id = u.id
     AND vv.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) AS votes_last_30d,
  -- Accuracy rate
  CASE
    WHEN u.total_votes_cast > 0
    THEN ROUND((u.accurate_votes / u.total_votes_cast) * 100, 1)
    ELSE 0
  END AS accuracy_rate,
  -- Rank by reputation
  RANK() OVER (ORDER BY u.reputation_score DESC) AS reputation_rank
FROM users u
WHERE u.is_active = TRUE;

-- ------------------------------------------------------------
-- 4. v_pending_review_queue
-- LEFT JOIN for optional evidence
-- ------------------------------------------------------------
CREATE OR REPLACE VIEW v_pending_review_queue AS
SELECT
  BIN_TO_UUID(fr.id) AS report_id,
  fr.title,
  fr.status,
  fr.verification_stage,
  fr.created_at AS reported_at,
  -- Reporter
  u.name AS reporter_name,
  u.reputation_score AS reporter_reputation,
  u.reputation_tier AS reporter_tier,
  -- Category
  c.name AS category_name,
  c.severity_weight,
  -- Website
  wu.domain,
  wu.risk_score,
  -- Evidence (LEFT JOIN — may be NULL)
  BIN_TO_UUID(re.id) AS evidence_id,
  re.file_name,
  re.evidence_type,
  re.is_approved,
  re.uploaded_at AS evidence_uploaded_at,
  -- Time waiting
  TIMESTAMPDIFF(HOUR, fr.created_at, NOW()) AS hours_waiting
FROM fraud_reports fr
JOIN users u ON u.id = fr.reporter_id
JOIN categories c ON c.id = fr.category_id
JOIN website_urls wu ON wu.id = fr.website_url_id
LEFT JOIN report_evidence re ON re.report_id = fr.id AND re.is_approved IS NULL
WHERE fr.status = 'active'
  AND fr.verification_stage IN ('reported', 'under_review')
ORDER BY fr.created_at ASC;

-- ------------------------------------------------------------
-- 5. v_category_fraud_statistics
-- Window functions, RANK() for category comparison
-- ------------------------------------------------------------
CREATE OR REPLACE VIEW v_category_fraud_statistics AS
SELECT
  BIN_TO_UUID(c.id) AS category_id,
  c.name AS category_name,
  c.slug AS category_slug,
  c.severity_weight,
  c.icon,
  -- Counts
  COUNT(DISTINCT fr.id) AS total_reports,
  COUNT(DISTINCT CASE WHEN fr.status = 'active' THEN fr.id END) AS active_reports,
  COUNT(DISTINCT CASE WHEN fr.verification_stage = 'confirmed_malicious' THEN fr.id END) AS confirmed_reports,
  -- Financial impact
  COALESCE(SUM(CASE WHEN fr.amount_lost IS NOT NULL THEN fr.amount_lost ELSE 0 END), 0) AS total_amount_lost,
  COALESCE(AVG(CASE WHEN fr.amount_lost IS NOT NULL THEN fr.amount_lost END), 0) AS avg_amount_lost,
  -- Unique websites
  COUNT(DISTINCT fr.website_url_id) AS unique_websites,
  -- Vote consensus
  COALESCE(SUM(fr.confirm_votes), 0) AS total_confirm_votes,
  COALESCE(SUM(fr.deny_votes), 0) AS total_deny_votes,
  -- Rank by report count
  RANK() OVER (ORDER BY COUNT(DISTINCT fr.id) DESC) AS report_count_rank,
  RANK() OVER (ORDER BY COALESCE(SUM(CASE WHEN fr.amount_lost IS NOT NULL THEN fr.amount_lost ELSE 0 END), 0) DESC) AS financial_impact_rank
FROM categories c
LEFT JOIN fraud_reports fr ON fr.category_id = c.id
WHERE c.is_active = TRUE
GROUP BY c.id, c.name, c.slug, c.severity_weight, c.icon;

-- ------------------------------------------------------------
-- 6. v_vote_consensus_detail
-- Self-join for voter reputation comparison
-- ------------------------------------------------------------
CREATE OR REPLACE VIEW v_vote_consensus_detail AS
SELECT
  BIN_TO_UUID(vv.id) AS vote_id,
  vv.vote_type,
  vv.confidence,
  vv.comment,
  vv.created_at AS voted_at,
  -- Voter info
  voter.name AS voter_name,
  voter.reputation_score AS voter_reputation,
  voter.reputation_tier AS voter_tier,
  voter.total_votes_cast AS voter_total_votes,
  -- Report info
  BIN_TO_UUID(fr.id) AS report_id,
  fr.title AS report_title,
  fr.confirm_votes,
  fr.deny_votes,
  fr.total_votes,
  -- Reporter info (for comparison)
  reporter.name AS reporter_name,
  reporter.reputation_score AS reporter_reputation,
  -- Reputation comparison
  CASE
    WHEN voter.reputation_score > reporter.reputation_score THEN 'voter_higher'
    WHEN voter.reputation_score < reporter.reputation_score THEN 'voter_lower'
    ELSE 'equal'
  END AS reputation_comparison,
  -- Consensus percentage
  CASE
    WHEN fr.total_votes > 0
    THEN ROUND((fr.confirm_votes / fr.total_votes) * 100, 1)
    ELSE 0
  END AS consensus_percentage
FROM verification_votes vv
JOIN users voter ON voter.id = vv.voter_id
JOIN fraud_reports fr ON fr.id = vv.report_id
JOIN users reporter ON reporter.id = fr.reporter_id;

-- ------------------------------------------------------------
-- 7. v_evidence_chain_of_custody
-- Audit trail JOIN for evidence tracking
-- ------------------------------------------------------------
CREATE OR REPLACE VIEW v_evidence_chain_of_custody AS
SELECT
  BIN_TO_UUID(re.id) AS evidence_id,
  re.evidence_type,
  re.file_name,
  re.file_size_bytes,
  re.sha256_hash,
  re.is_approved,
  re.uploaded_at,
  -- Report info
  BIN_TO_UUID(fr.id) AS report_id,
  fr.title AS report_title,
  fr.status AS report_status,
  -- Uploader
  uploader.name AS uploader_name,
  uploader.reputation_score AS uploader_reputation,
  -- Approver (if approved)
  approver.name AS approved_by_name,
  -- History entries
  (SELECT COUNT(*)
   FROM report_history rh
   WHERE rh.report_id = fr.id
     AND rh.action = 'evidence_uploaded'
     AND rh.new_value->>'$.evidence_id' = BIN_TO_UUID(re.id)) AS history_entries,
  -- Report status changes after upload
  (SELECT COUNT(*)
   FROM report_history rh
   WHERE rh.report_id = fr.id
     AND rh.action = 'status_changed'
     AND rh.created_at >= re.uploaded_at) AS status_changes_after_upload
FROM report_evidence re
JOIN fraud_reports fr ON fr.id = re.report_id
JOIN users uploader ON uploader.id = re.uploaded_by
LEFT JOIN users approver ON approver.id = (
  SELECT rh.actor_id
  FROM report_history rh
  WHERE rh.report_id = fr.id
    AND rh.action = 'evidence_uploaded'
    AND rh.new_value->>'$.evidence_id' = BIN_TO_UUID(re.id)
  ORDER BY rh.created_at DESC
  LIMIT 1
);

-- ------------------------------------------------------------
-- 8. v_appeal_resolution_tracker
-- LEFT JOIN for optional resolution info
-- ------------------------------------------------------------
CREATE OR REPLACE VIEW v_appeal_resolution_tracker AS
SELECT
  BIN_TO_UUID(a.id) AS appeal_id,
  a.appellant_email,
  a.status AS appeal_status,
  a.domain_owner_verified,
  a.reason,
  a.submitted_at,
  a.resolved_at,
  -- Time to resolve
  CASE
    WHEN a.resolved_at IS NOT NULL
    THEN TIMESTAMPDIFF(DAY, a.submitted_at, a.resolved_at)
    ELSE TIMESTAMPDIFF(DAY, a.submitted_at, NOW())
  END AS days_pending,
  -- Report info
  BIN_TO_UUID(fr.id) AS report_id,
  fr.title AS report_title,
  fr.status AS report_status,
  fr.verification_stage,
  -- Reporter
  reporter.name AS reporter_name,
  -- Resolver
  resolver.name AS resolved_by_name,
  -- Appeal evidence count
  (SELECT COUNT(*) FROM appeal_evidence ae WHERE ae.appeal_id = a.id) AS evidence_count
FROM appeals a
JOIN fraud_reports fr ON fr.id = a.report_id
JOIN users reporter ON reporter.id = fr.reporter_id
LEFT JOIN users resolver ON resolver.id = a.resolved_by;

-- ------------------------------------------------------------
-- 9. v_daily_report_trends
-- Date truncation, window functions for trend analysis
-- ------------------------------------------------------------
CREATE OR REPLACE VIEW v_daily_report_trends AS
SELECT
  DATE(fr.created_at) AS report_date,
  -- Daily counts
  COUNT(*) AS reports_count,
  COUNT(DISTINCT fr.reporter_id) AS unique_reporters,
  COUNT(DISTINCT fr.website_url_id) AS unique_websites,
  -- Financial
  COALESCE(SUM(CASE WHEN fr.amount_lost IS NOT NULL THEN fr.amount_lost ELSE 0 END), 0) AS daily_amount_lost,
  -- Category breakdown
  COUNT(DISTINCT CASE WHEN c.severity_weight >= 8.0 THEN fr.id END) AS high_severity_reports,
  -- Cumulative (window function)
  SUM(COUNT(*)) OVER (ORDER BY DATE(fr.created_at)) AS cumulative_reports,
  -- Day-over-day change
  COUNT(*) - LAG(COUNT(*)) OVER (ORDER BY DATE(fr.created_at)) AS day_over_day_change
FROM fraud_reports fr
JOIN categories c ON c.id = fr.category_id
GROUP BY DATE(fr.created_at);

-- ------------------------------------------------------------
-- 10. v_high_risk_websites
-- Complex subqueries, HAVING for high-risk filtering
-- ------------------------------------------------------------
CREATE OR REPLACE VIEW v_high_risk_websites AS
SELECT
  BIN_TO_UUID(wu.id) AS website_id,
  wu.domain,
  wu.risk_score,
  wu.risk_level,
  wu.total_reports,
  wu.confirmed_reports,
  -- Risk signals
  wu.ssl_valid,
  wu.dmarc_exists,
  wu.spf_exists,
  wu.blacklist_matches,
  -- Community signals
  (SELECT COUNT(DISTINCT fr.reporter_id)
   FROM fraud_reports fr
   WHERE fr.website_url_id = wu.id) AS independent_reporters,
  (SELECT COUNT(DISTINCT c.id)
   FROM fraud_reports fr
   JOIN categories c ON c.id = fr.category_id
   WHERE fr.website_url_id = wu.id) AS unique_categories,
  -- Evidence quality
  (SELECT COUNT(*)
   FROM report_evidence re
   JOIN fraud_reports fr ON fr.id = re.report_id
   WHERE fr.website_url_id = wu.id
     AND re.is_approved = TRUE) AS approved_evidence_count,
  -- Vote consensus
  (SELECT COALESCE(SUM(fr.confirm_votes), 0)
   FROM fraud_reports fr
   WHERE fr.website_url_id = wu.id) AS total_confirm_votes,
  (SELECT COALESCE(SUM(fr.deny_votes), 0)
   FROM fraud_reports fr
   WHERE fr.website_url_id = wu.id) AS total_deny_votes,
  -- Verification stage summary
  (SELECT GROUP_CONCAT(DISTINCT fr.verification_stage ORDER BY fr.verification_stage)
   FROM fraud_reports fr
   WHERE fr.website_url_id = wu.id) AS verification_stages,
  -- Appeal status
  (SELECT a.status
   FROM appeals a
   WHERE a.report_id IN (SELECT fr.id FROM fraud_reports fr WHERE fr.website_url_id = wu.id)
   ORDER BY a.submitted_at DESC
   LIMIT 1) AS latest_appeal_status
FROM website_urls wu
WHERE wu.risk_score >= 50.00
  AND wu.total_reports >= 2
ORDER BY wu.risk_score DESC;
