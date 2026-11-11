-- ============================================================
-- ScamAlert — Views
-- 5 views used by the Flask app: multi-table JOINs, subqueries,
-- GROUP_CONCAT, window functions, LEFT JOINs
-- ============================================================

USE scamalert;

-- ------------------------------------------------------------
-- 1. v_report_full_details
-- 4-table JOIN with LEFT JOINs for tags and evidence (avoids correlated subqueries)
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
  -- Tags (aggregated via LEFT JOIN + GROUP_CONCAT)
  tags_agg.tags AS tags,
  -- Evidence count (aggregated via LEFT JOIN)
  COALESCE(evidence_agg.cnt, 0) AS evidence_count
FROM fraud_reports fr
JOIN users u ON u.id = fr.reporter_id
JOIN categories c ON c.id = fr.category_id
JOIN website_urls wu ON wu.id = fr.website_url_id
LEFT JOIN (
  SELECT rt.report_id, GROUP_CONCAT(t.name ORDER BY t.name SEPARATOR ', ') AS tags
  FROM report_tags rt
  JOIN tags t ON t.id = rt.tag_id
  GROUP BY rt.report_id
) tags_agg ON tags_agg.report_id = fr.id
LEFT JOIN (
  SELECT report_id, COUNT(*) AS cnt
  FROM report_evidence
  GROUP BY report_id
) evidence_agg ON evidence_agg.report_id = fr.id;

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
-- 5. v_appeal_resolution_tracker
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

