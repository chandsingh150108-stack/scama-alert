-- ============================================================
-- ScamAlert — Stored Functions v1.0
-- 6 functions: risk scoring, reputation, URL normalization,
-- rate limiting, domain age, verification stage
-- ============================================================

USE scamalert;


DELIMITER //

DROP FUNCTION IF EXISTS fn_calculate_risk_score //
DROP FUNCTION IF EXISTS fn_get_reputation_tier //
DROP FUNCTION IF EXISTS fn_normalize_url //
DROP FUNCTION IF EXISTS fn_check_rate_limit //
DROP FUNCTION IF EXISTS fn_calculate_domain_age //
DROP FUNCTION IF EXISTS fn_determine_verification_stage //

-- ------------------------------------------------------------
-- 1. fn_calculate_risk_score
-- Multi-signal calculation with subqueries
-- Returns: DECIMAL(5,2) — final risk score 0-100
-- ------------------------------------------------------------
CREATE FUNCTION fn_calculate_risk_score(website_uuid BINARY(16))
RETURNS DECIMAL(5,2)
DETERMINISTIC
READS SQL DATA
BEGIN
  DECLARE v_community_score DECIMAL(5,2) DEFAULT 0;
  DECLARE v_automated_score DECIMAL(5,2) DEFAULT 0;
  DECLARE v_severity_avg DECIMAL(3,2) DEFAULT 0;
  DECLARE v_final_score DECIMAL(5,2) DEFAULT 0;
  DECLARE v_report_count INT DEFAULT 0;
  DECLARE v_confirm_ratio DECIMAL(5,2) DEFAULT 0;
  DECLARE v_total_votes INT DEFAULT 0;
  DECLARE v_confirm_votes INT DEFAULT 0;
  DECLARE v_days_since_first INT DEFAULT 0;
  DECLARE v_ssl_valid BOOLEAN DEFAULT FALSE;
  DECLARE v_dmarc_exists BOOLEAN DEFAULT FALSE;
  DECLARE v_spf_exists BOOLEAN DEFAULT FALSE;
  DECLARE v_blacklist INT DEFAULT 0;

  -- Count reports for this website
  SELECT COUNT(*) INTO v_report_count
  FROM fraud_reports WHERE website_url_id = website_uuid;

  -- Vote consensus
  SELECT COALESCE(SUM(confirm_votes), 0), COALESCE(SUM(deny_votes), 0)
  INTO v_confirm_votes, v_total_votes
  FROM fraud_reports WHERE website_url_id = website_uuid;

  IF v_total_votes > 0 THEN
    SET v_confirm_ratio = (v_confirm_votes / v_total_votes) * 100;
  END IF;

  -- Category severity average
  SELECT COALESCE(AVG(c.severity_weight), 0) INTO v_severity_avg
  FROM fraud_reports fr
  JOIN categories c ON c.id = fr.category_id
  WHERE fr.website_url_id = website_uuid;

  -- Community signals (40% weight)
  -- Report count: logarithmic scale, max 25 points
  SET v_community_score = LEAST(25, LN(GREATEST(v_report_count, 1) + 1) * 5.4);

  -- Vote consensus: 15 points
  SET v_community_score = v_community_score + (v_confirm_ratio / 100 * 15);

  -- Corroboration bonus: 10 points if 3+ independent reporters
  IF (SELECT COUNT(DISTINCT reporter_id) FROM fraud_reports WHERE website_url_id = website_uuid) >= 3 THEN
    SET v_community_score = v_community_score + 10;
  END IF;

  -- Recency: 10 points (recent reports weigh more)
  SELECT DATEDIFF(NOW(), MIN(created_at)) INTO v_days_since_first
  FROM fraud_reports WHERE website_url_id = website_uuid;

  IF v_days_since_first <= 7 THEN
    SET v_community_score = v_community_score + 10;
  ELSEIF v_days_since_first <= 30 THEN
    SET v_community_score = v_community_score + 7.5;
  ELSEIF v_days_since_first <= 90 THEN
    SET v_community_score = v_community_score + 5;
  ELSE
    SET v_community_score = v_community_score + 2.5;
  END IF;

  -- Cap community score at 100
  SET v_community_score = LEAST(100, v_community_score);

  -- Automated signals (40% weight)
  SELECT ssl_valid, dmarc_exists, spf_exists, blacklist_matches
  INTO v_ssl_valid, v_dmarc_exists, v_spf_exists, v_blacklist
  FROM website_urls WHERE id = website_uuid;

  -- SSL validity: 10 points
  IF v_ssl_valid = FALSE THEN
    SET v_automated_score = 10;
  END IF;

  -- DMARC: 5 points if missing
  IF v_dmarc_exists = FALSE THEN
    SET v_automated_score = v_automated_score + 5;
  END IF;

  -- SPF: 5 points if missing
  IF v_spf_exists = FALSE THEN
    SET v_automated_score = v_automated_score + 5;
  END IF;

  -- Blacklist matches: up to 20 points
  SET v_automated_score = v_automated_score + LEAST(20, v_blacklist * 4);

  -- Cap automated score at 100
  SET v_automated_score = LEAST(100, v_automated_score);

  -- Final score: Community(40%) + Automated(40%) + Severity(20%)
  SET v_final_score = ROUND(
    (v_community_score * 0.40) +
    (v_automated_score * 0.40) +
    (v_severity_avg * 10 * 0.20),
    2
  );

  -- Clamp to 0-100
  SET v_final_score = GREATEST(0, LEAST(100, v_final_score));

  RETURN v_final_score;
END //

-- ------------------------------------------------------------
-- 2. fn_get_reputation_tier
-- CASE logic for reputation tier assignment
-- Returns: VARCHAR(20)
-- ------------------------------------------------------------
CREATE FUNCTION fn_get_reputation_tier(score INT)
RETURNS VARCHAR(20)
DETERMINISTIC
BEGIN
  RETURN CASE
    WHEN score >= 90 THEN 'moderator'
    WHEN score >= 70 THEN 'expert'
    WHEN score >= 40 THEN 'trusted'
    WHEN score >= 20 THEN 'new'
    ELSE 'newcomer'
  END;
END //

-- ------------------------------------------------------------
-- 3. fn_normalize_url
-- String manipulation, REGEXP for URL normalization
-- Returns: TEXT
-- ------------------------------------------------------------
CREATE FUNCTION fn_normalize_url(url TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  DECLARE normalized TEXT;
  SET normalized = LOWER(TRIM(url));

  -- Remove trailing slash
  SET normalized = REGEXP_REPLACE(normalized, '/$', '');

  -- Remove www. prefix
  SET normalized = REGEXP_REPLACE(normalized, '^https?://www\\.', '');

  -- Remove default ports
  SET normalized = REGEXP_REPLACE(normalized, ':80$', '');
  SET normalized = REGEXP_REPLACE(normalized, ':443$', '');

  -- Remove tracking parameters (common ones)
  SET normalized = REGEXP_REPLACE(normalized, '[?&](utm_[a-z]+|fbclid|gclid|ref)=[^&]*', '');
  SET normalized = REGEXP_REPLACE(normalized, '\\?$', '');

  -- Add protocol if missing
  IF normalized NOT REGEXP '^https?://' THEN
    SET normalized = CONCAT('https://', normalized);
  END IF;

  RETURN normalized;
END //

-- ------------------------------------------------------------
-- 4. fn_check_rate_limit
-- Sliding window with date math
-- Returns: BOOLEAN (TRUE = allowed, FALSE = rate limited)
-- ------------------------------------------------------------
CREATE FUNCTION fn_check_rate_limit(uid BINARY(16), action VARCHAR(50))
RETURNS BOOLEAN
DETERMINISTIC
READS SQL DATA
BEGIN
  DECLARE v_limit INT DEFAULT 0;
  DECLARE v_count INT DEFAULT 0;
  DECLARE v_window_start TIMESTAMP;

  -- Determine limit based on action type
  SET v_limit = CASE action
    WHEN 'report_new' THEN 5
    WHEN 'report_established' THEN 20
    WHEN 'vote' THEN 20
    WHEN 'appeal' THEN 3
    ELSE 20
  END;

  -- Check if user is established (reputation >= 40)
  IF action = 'report_new' THEN
    IF (SELECT reputation_score FROM users WHERE id = uid) >= 40 THEN
      SET v_limit = 20;
    END IF;
  END IF;

  -- Sliding window: count actions in last hour (or day for appeals)
  IF action = 'appeal' THEN
    SET v_window_start = DATE_SUB(NOW(), INTERVAL 1 DAY);
  ELSE
    SET v_window_start = DATE_SUB(NOW(), INTERVAL 1 HOUR);
  END IF;

  SELECT COUNT(*) INTO v_count
  FROM rate_limit_events
  WHERE user_id = uid
    AND action_type = action
    AND created_at >= v_window_start;

  RETURN v_count < v_limit;
END //

-- ------------------------------------------------------------
-- 5. fn_calculate_domain_age
-- Date arithmetic for domain age
-- Returns: INT (days)
-- ------------------------------------------------------------
CREATE FUNCTION fn_calculate_domain_age(reg_date DATE)
RETURNS INT
DETERMINISTIC
BEGIN
  IF reg_date IS NULL THEN
    RETURN -1;
  END IF;
  RETURN DATEDIFF(NOW(), reg_date);
END //

-- ------------------------------------------------------------
-- 6. fn_determine_verification_stage
-- Business logic with vote aggregation
-- Returns: VARCHAR(30)
-- ------------------------------------------------------------
CREATE FUNCTION fn_determine_verification_stage(report_uuid BINARY(16))
RETURNS VARCHAR(30)
DETERMINISTIC
READS SQL DATA
BEGIN
  DECLARE v_confirm_votes INT DEFAULT 0;
  DECLARE v_deny_votes INT DEFAULT 0;
  DECLARE v_total_votes INT DEFAULT 0;
  DECLARE v_reporter_count INT DEFAULT 0;
  DECLARE v_evidence_count INT DEFAULT 0;
  DECLARE v_website_reports INT DEFAULT 0;
  DECLARE v_current_stage VARCHAR(30);

  -- Get current stage
  SELECT verification_stage INTO v_current_stage
  FROM fraud_reports WHERE id = report_uuid;

  -- Get vote counts
  SELECT confirm_votes, deny_votes, total_votes
  INTO v_confirm_votes, v_deny_votes, v_total_votes
  FROM fraud_reports WHERE id = report_uuid;

  -- Get independent reporters for same website
  SELECT COUNT(DISTINCT fr.reporter_id) INTO v_reporter_count
  FROM fraud_reports fr
  WHERE fr.website_url_id = (SELECT website_url_id FROM fraud_reports WHERE id = report_uuid);

  -- Get evidence count
  SELECT COUNT(*) INTO v_evidence_count
  FROM report_evidence WHERE report_id = report_uuid;

  -- Get total reports for this website
  SELECT COUNT(*) INTO v_website_reports
  FROM fraud_reports
  WHERE website_url_id = (SELECT website_url_id FROM fraud_reports WHERE id = report_uuid);

  -- Stage determination logic
  -- Auto-advance from reported to multiple_reports
  IF v_current_stage = 'reported' AND v_reporter_count >= 2 THEN
    RETURN 'multiple_reports';
  END IF;

  -- Auto-advance from multiple_reports to community_verified
  IF v_current_stage = 'multiple_reports' AND (v_confirm_votes >= 5 OR (v_reporter_count >= 2 AND v_evidence_count >= 2)) THEN
    RETURN 'community_verified';
  END IF;

  -- Any stage can regress on high deny votes
  IF v_total_votes > 0 AND (v_deny_votes / v_total_votes) > 0.5 THEN
    RETURN 'under_review';
  END IF;

  -- Return current stage if no transition triggered
  RETURN v_current_stage;
END //

DELIMITER ;
