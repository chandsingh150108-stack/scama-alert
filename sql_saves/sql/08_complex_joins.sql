-- ============================================================
-- ScamAlert — Complex JOIN Showcase Queries
-- Demonstrating different JOIN patterns for DBMS course
-- ============================================================

USE scamalert;

-- ============================================================
-- 1. INNER JOIN — Reports with full context
-- Shows only reports that have all required relationships
-- ============================================================
SELECT '--- 1. INNER JOIN: Reports with full context ---' AS demo;

SELECT
  fr.title AS report_title,
  u.name AS reporter,
  u.reputation_tier AS reporter_tier,
  c.name AS category,
  c.severity_weight,
  wu.domain,
  wu.risk_level
FROM fraud_reports fr
INNER JOIN users u ON u.id = fr.reporter_id
INNER JOIN categories c ON c.id = fr.category_id
INNER JOIN website_urls wu ON wu.id = fr.website_url_id
WHERE fr.status = 'active'
ORDER BY fr.created_at DESC
LIMIT 10;

-- ============================================================
-- 2. LEFT JOIN — Reports with optional evidence
-- Shows ALL reports, even those without evidence
-- ============================================================
SELECT '--- 2. LEFT JOIN: Reports with optional evidence ---' AS demo;

SELECT
  fr.title AS report_title,
  fr.status,
  re.file_name AS evidence_file,
  re.evidence_type,
  re.is_approved,
  CASE
    WHEN re.id IS NULL THEN 'No evidence'
    WHEN re.is_approved IS NULL THEN 'Pending approval'
    WHEN re.is_approved = TRUE THEN 'Approved'
    ELSE 'Rejected'
  END AS evidence_status
FROM fraud_reports fr
LEFT JOIN report_evidence re ON re.report_id = fr.id
WHERE fr.verification_stage IN ('reported', 'under_review')
ORDER BY fr.created_at;

-- ============================================================
-- 3. SELF JOIN — Threaded comments (parent-child)
-- Shows comment hierarchy
-- ============================================================
SELECT '--- 3. SELF JOIN: Threaded comments ---' AS demo;

SELECT
  parent.body AS parent_comment,
  parent_user.name AS parent_author,
  child.body AS reply,
  child_user.name AS reply_author,
  child.created_at AS reply_time
FROM report_comments parent
INNER JOIN report_comments child ON child.parent_id = parent.id
INNER JOIN users parent_user ON parent_user.id = parent.user_id
INNER JOIN users child_user ON child_user.id = child.user_id
WHERE parent.parent_id IS NULL  -- Top-level comments only
ORDER BY parent.created_at, child.created_at
LIMIT 10;

-- ============================================================
-- 4. MULTI-TABLE AGGREGATION — User reputation leaderboard
-- Shows aggregated stats across multiple tables
-- ============================================================
SELECT '--- 4. MULTI-TABLE AGGREGATION: User leaderboard ---' AS demo;

SELECT
  u.name,
  u.reputation_score,
  u.reputation_tier,
  COUNT(DISTINCT fr.id) AS total_reports,
  COUNT(DISTINCT CASE WHEN fr.verification_stage = 'confirmed_malicious' THEN fr.id END) AS confirmed_reports,
  COUNT(DISTINCT vv.id) AS votes_cast,
  COALESCE(SUM(re_event.delta), 0) AS reputation_change_30d
FROM users u
LEFT JOIN fraud_reports fr ON fr.reporter_id = u.id
LEFT JOIN verification_votes vv ON vv.voter_id = u.id
LEFT JOIN reputation_events re_event ON re_event.user_id = u.id
  AND re_event.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
WHERE u.is_active = TRUE
GROUP BY u.id, u.name, u.reputation_score, u.reputation_tier
ORDER BY u.reputation_score DESC
LIMIT 10;

-- ============================================================
-- 5. SUBQUERY + JOIN — High-risk websites with details
-- Subquery in FROM clause with JOIN
-- ============================================================
SELECT '--- 5. SUBQUERY + JOIN: High-risk websites ---' AS demo;

SELECT
  wu.domain,
  wu.risk_score,
  wu.risk_level,
  wu.total_reports,
  risk_data.community_score,
  risk_data.automated_score,
  risk_data.category_severity,
  latest_report.title AS latest_report_title,
  latest_report.created_at AS latest_report_date
FROM website_urls wu
INNER JOIN (
  SELECT
    website_url_id,
    community_sub_score AS community_score,
    automated_sub_score AS automated_score,
    category_severity_avg AS category_severity
  FROM risk_score_breakdowns
  WHERE calculated_at = (
    SELECT MAX(calculated_at)
    FROM risk_score_breakdowns rsb2
    WHERE rsb2.website_url_id = risk_score_breakdowns.website_url_id
  )
) risk_data ON risk_data.website_url_id = wu.id
LEFT JOIN fraud_reports latest_report ON latest_report.website_url_id = wu.id
  AND latest_report.created_at = (
    SELECT MAX(fr2.created_at)
    FROM fraud_reports fr2
    WHERE fr2.website_url_id = wu.id
  )
WHERE wu.risk_score >= 40
ORDER BY wu.risk_score DESC;

-- ============================================================
-- 6. GROUP BY + HAVING — Category statistics
-- Shows categories with significant activity
-- ============================================================
SELECT '--- 6. GROUP BY + HAVING: Category statistics ---' AS demo;

SELECT
  c.name AS category,
  c.severity_weight,
  COUNT(DISTINCT fr.id) AS report_count,
  COUNT(DISTINCT fr.website_url_id) AS unique_websites,
  ROUND(AVG(fr.amount_lost), 2) AS avg_amount_lost,
  ROUND(
    (SELECT COUNT(*)
     FROM verification_votes vv
     WHERE vv.vote_type = 'confirm'
       AND vv.report_id IN (SELECT fr2.id FROM fraud_reports fr2 WHERE fr2.category_id = c.id)
    ) / GREATEST(
      (SELECT COUNT(*)
       FROM verification_votes vv
       WHERE vv.report_id IN (SELECT fr2.id FROM fraud_reports fr2 WHERE fr2.category_id = c.id)
      ), 1
    ) * 100, 1
  ) AS confirm_rate_pct
FROM categories c
INNER JOIN fraud_reports fr ON fr.category_id = c.id
GROUP BY c.id, c.name, c.severity_weight
HAVING COUNT(DISTINCT fr.id) >= 1
ORDER BY report_count DESC;

-- ============================================================
-- 7. WINDOW FUNCTIONS — Rank reports by financial impact
-- ROW_NUMBER, RANK, DENSE_RANK
-- ============================================================
SELECT '--- 7. WINDOW FUNCTIONS: Financial impact ranking ---' AS demo;

SELECT
  fr.title,
  wu.domain,
  c.name AS category,
  fr.amount_lost,
  fr.currency,
  RANK() OVER (ORDER BY fr.amount_lost DESC) AS financial_rank,
  ROW_NUMBER() OVER (PARTITION BY c.id ORDER BY fr.amount_lost DESC) AS rank_within_category,
  DENSE_RANK() OVER (ORDER BY fr.amount_lost DESC) AS dense_rank
FROM fraud_reports fr
INNER JOIN website_urls wu ON wu.id = fr.website_url_id
INNER JOIN categories c ON c.id = fr.category_id
WHERE fr.amount_lost IS NOT NULL
ORDER BY fr.amount_lost DESC;

-- ============================================================
-- 8. COMPLEX SUBQUERY — Vote consensus with voter reputation
-- Correlated subquery for voter quality analysis
-- ============================================================
SELECT '--- 8. COMPLEX SUBQUERY: Vote consensus analysis ---' AS demo;

SELECT
  fr.title AS report_title,
  wu.domain,
  fr.confirm_votes,
  fr.deny_votes,
  fr.total_votes,
  ROUND((fr.confirm_votes / GREATEST(fr.total_votes, 1)) * 100, 1) AS consensus_pct,
  -- Average reputation of confirm voters
  (SELECT ROUND(AVG(voter.reputation_score), 1)
   FROM verification_votes vv
   JOIN users voter ON voter.id = vv.voter_id
   WHERE vv.report_id = fr.id AND vv.vote_type = 'confirm'
  ) AS avg_confirm_voter_rep,
  -- Average reputation of deny voters
  (SELECT ROUND(AVG(voter.reputation_score), 1)
   FROM verification_votes vv
   JOIN users voter ON voter.id = vv.voter_id
   WHERE vv.report_id = fr.id AND vv.vote_type = 'deny'
  ) AS avg_deny_voter_rep,
  -- Number of independent reporters
  (SELECT COUNT(DISTINCT fr2.reporter_id)
   FROM fraud_reports fr2
   WHERE fr2.website_url_id = fr.website_url_id
  ) AS independent_reporters
FROM fraud_reports fr
INNER JOIN website_urls wu ON wu.id = fr.website_url_id
WHERE fr.total_votes > 0
ORDER BY consensus_pct DESC;

-- ============================================================
-- 9. MULTI-LEVEL JOIN — Full evidence chain
-- 4-table JOIN for complete evidence tracking
-- ============================================================
SELECT '--- 9. MULTI-LEVEL JOIN: Evidence chain of custody ---' AS demo;

SELECT
  re.file_name,
  re.evidence_type,
  re.sha256_hash,
  re.uploaded_at,
  -- Report
  fr.title AS report_title,
  fr.status AS report_status,
  -- Uploader
  uploader.name AS uploaded_by,
  uploader.reputation_tier AS uploader_tier,
  -- Report history entries
  (SELECT COUNT(*)
   FROM report_history rh
   WHERE rh.report_id = fr.id
     AND rh.action = 'evidence_uploaded'
  ) AS evidence_history_count,
  -- Verification votes on this report
  (SELECT COUNT(*)
   FROM verification_votes vv
   WHERE vv.report_id = fr.id
  ) AS total_votes_on_report
FROM report_evidence re
INNER JOIN fraud_reports fr ON fr.id = re.report_id
INNER JOIN users uploader ON uploader.id = re.uploaded_by
ORDER BY re.uploaded_at DESC
LIMIT 10;

-- ============================================================
-- 10. CROSS JOIN + FILTER — Category × Website risk matrix
-- Cross join with WHERE for matrix analysis
-- ============================================================
SELECT '--- 10. CROSS JOIN: Category × Website risk matrix ---' AS demo;

SELECT
  c.name AS category,
  wu.domain,
  wu.risk_level,
  COUNT(fr.id) AS reports_in_category,
  c.severity_weight
FROM categories c
CROSS JOIN website_urls wu
LEFT JOIN fraud_reports fr ON fr.category_id = c.id AND fr.website_url_id = wu.id
WHERE c.is_active = TRUE
  AND wu.is_active = TRUE
GROUP BY c.id, c.name, c.severity_weight, wu.id, wu.domain, wu.risk_level
HAVING COUNT(fr.id) > 0
ORDER BY wu.risk_score DESC, c.severity_weight DESC;
