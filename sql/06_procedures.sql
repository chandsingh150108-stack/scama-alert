-- ============================================================
-- ScamAlert — Stored Procedures
-- 5 procedures: transactions, cursors, savepoints
-- ============================================================

USE scamalert;

DELIMITER //

-- ------------------------------------------------------------
-- 1. sp_submit_fraud_report
-- Transaction: BEGIN/COMMIT/ROLLBACK
-- URL dedup, rate limit check, evidence insert, audit log
-- All atomic — all succeed or all rollback
-- ------------------------------------------------------------
DROP PROCEDURE IF EXISTS sp_submit_fraud_report //

CREATE PROCEDURE sp_submit_fraud_report(
  IN p_reporter_id BINARY(16),
  IN p_url TEXT,
  IN p_category_slug VARCHAR(100),
  IN p_title VARCHAR(200),
  IN p_description TEXT,
  IN p_target_brand VARCHAR(255),
  IN p_amount_lost DECIMAL(12,2),
  IN p_currency CHAR(3),
  IN p_incident_date DATE,
  IN p_country_code CHAR(2),
  IN p_is_anonymous BOOLEAN
)
BEGIN
  DECLARE v_website_id BINARY(16);
  DECLARE v_category_id BINARY(16);
  DECLARE v_report_id BINARY(16);
  DECLARE v_normalized_url TEXT;
  DECLARE v_domain VARCHAR(255);
  DECLARE v_is_allowed BOOLEAN;
  DECLARE v_user_role VARCHAR(20);

  DECLARE EXIT HANDLER FOR SQLEXCEPTION
  BEGIN
    ROLLBACK;
    RESIGNAL;
  END;

  START TRANSACTION;

  -- Step 1: Check rate limit
  SET v_is_allowed = fn_check_rate_limit(p_reporter_id, 'report_new');
  IF v_is_allowed = FALSE THEN
    ROLLBACK;
    SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = 'Rate limit exceeded. Please try again later.';
  END IF;

  -- Step 2: Get user role to check established status
  SELECT role INTO v_user_role FROM users WHERE id = p_reporter_id;

  -- Step 3: Normalize URL and check for existing
  SET v_normalized_url = fn_normalize_url(p_url);
  SET v_domain = SUBSTRING_INDEX(SUBSTRING_INDEX(v_normalized_url, '://', -1), '/', 1);

  SELECT id INTO v_website_id
  FROM website_urls
  WHERE normalized_url = v_normalized_url
  LIMIT 1;

  -- Step 4: Create website if not exists
  IF v_website_id IS NULL THEN
    SET v_website_id = UUID_TO_BIN(UUID());
    INSERT INTO website_urls (id, normalized_url, raw_url, domain)
    VALUES (v_website_id, v_normalized_url, p_url, v_domain);
  END IF;

  -- Step 5: Get category ID
  SELECT id INTO v_category_id
  FROM categories
  WHERE slug = p_category_slug AND is_active = TRUE
  LIMIT 1;

  IF v_category_id IS NULL THEN
    ROLLBACK;
    SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = 'Invalid category slug';
  END IF;

  -- Step 6: Create report
  SET v_report_id = UUID_TO_BIN(UUID());
  INSERT INTO fraud_reports (
    id, reporter_id, website_url_id, category_id,
    title, description, target_brand, amount_lost,
    currency, incident_date, country_code,
    status, verification_stage, is_anonymous
  ) VALUES (
    v_report_id, p_reporter_id, v_website_id, v_category_id,
    p_title, p_description, p_target_brand, p_amount_lost,
    COALESCE(p_currency, 'INR'), p_incident_date, p_country_code,
    'active', 'reported', COALESCE(p_is_anonymous, FALSE)
  );

  -- Step 7: Log rate limit event
  INSERT INTO rate_limit_events (id, user_id, ip_address, action_type)
  VALUES (UUID_TO_BIN(UUID()), p_reporter_id, NULL, 'report_new');

  COMMIT;

  -- Return the report ID
  SELECT BIN_TO_UUID(v_report_id) AS report_id;

END //

-- ------------------------------------------------------------
-- 2. sp_process_verification_vote
-- Transaction with savepoint
-- Vote validation, count update, stage transition check
-- ------------------------------------------------------------
DROP PROCEDURE IF EXISTS sp_process_verification_vote //

CREATE PROCEDURE sp_process_verification_vote(
  IN p_report_id BINARY(16),
  IN p_voter_id BINARY(16),
  IN p_vote_type ENUM('confirm', 'deny', 'inconclusive'),
  IN p_confidence DECIMAL(3,2),
  IN p_comment TEXT
)
BEGIN
  DECLARE v_new_stage VARCHAR(30);
  DECLARE v_old_stage VARCHAR(30);
  DECLARE v_voter_rep INT DEFAULT 0;

  DECLARE EXIT HANDLER FOR SQLEXCEPTION
  BEGIN
    ROLLBACK;
    RESIGNAL;
  END;

  START TRANSACTION;

  -- Save current stage for comparison
  SELECT verification_stage INTO v_old_stage
  FROM fraud_reports WHERE id = p_report_id;

  -- Get voter reputation
  SELECT reputation_score INTO v_voter_rep
  FROM users WHERE id = p_voter_id;

  -- Insert vote (triggers handle validation and count updates)
  INSERT INTO verification_votes (
    id, report_id, voter_id, vote_type, confidence, comment
  ) VALUES (
    UUID_TO_BIN(UUID()), p_report_id, p_voter_id, p_vote_type,
    COALESCE(p_confidence, 1.00), p_comment
  );

  -- Check if stage changed
  SET v_new_stage = fn_determine_verification_stage(p_report_id);

  IF v_new_stage != v_old_stage THEN
    SAVEPOINT sp_stage_change;

    UPDATE fraud_reports
    SET verification_stage = v_new_stage
    WHERE id = p_report_id;

    -- Log stage change
    INSERT INTO report_history (id, report_id, actor_id, action, old_value, new_value)
    VALUES (UUID_TO_BIN(UUID()), p_report_id, p_voter_id, 'status_changed',
      JSON_OBJECT('verification_stage', v_old_stage),
      JSON_OBJECT('verification_stage', v_new_stage));
  END IF;

  COMMIT;

  SELECT 'Vote processed successfully' AS result, v_new_stage AS new_stage;

END //

-- ------------------------------------------------------------
-- 3. sp_resolve_appeal
-- Transaction with rollback on failure
-- Appeal status update, report status update, audit log
-- ------------------------------------------------------------
DROP PROCEDURE IF EXISTS sp_resolve_appeal //

CREATE PROCEDURE sp_resolve_appeal(
  IN p_appeal_id BINARY(16),
  IN p_resolved_by BINARY(16),
  IN p_new_status ENUM('upheld', 'overturned', 'partially_upheld', 'rejected')
)
BEGIN
  DECLARE v_report_id BINARY(16);
  DECLARE v_old_appeal_status VARCHAR(20);
  DECLARE v_old_report_status VARCHAR(20);

  DECLARE EXIT HANDLER FOR SQLEXCEPTION
  BEGIN
    ROLLBACK;
    RESIGNAL;
  END;

  START TRANSACTION;

  -- Get current appeal info
  SELECT report_id, status INTO v_report_id, v_old_appeal_status
  FROM appeals WHERE id = p_appeal_id;

  IF v_report_id IS NULL THEN
    ROLLBACK;
    SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = 'Appeal not found';
  END IF;

  -- Get current report status
  SELECT status INTO v_old_report_status
  FROM fraud_reports WHERE id = v_report_id;

  -- Update appeal status
  UPDATE appeals
  SET status = p_new_status,
      resolved_at = NOW(),
      resolved_by = p_resolved_by
  WHERE id = p_appeal_id;

  -- Update report status based on appeal outcome
  CASE p_new_status
    WHEN 'overturned' THEN
      UPDATE fraud_reports
      SET status = 'archived',
          verification_stage = 'under_review'
      WHERE id = v_report_id;
    WHEN 'upheld' THEN
      UPDATE fraud_reports
      SET status = 'active'
      WHERE id = v_report_id;
    WHEN 'rejected' THEN
      UPDATE fraud_reports
      SET status = 'active'
      WHERE id = v_report_id;
    ELSE
      SET v_old_report_status = v_old_report_status;
  END CASE;

  -- Get updated report status
  SELECT status INTO v_old_report_status
  FROM fraud_reports WHERE id = v_report_id;

  -- Log in report history
  INSERT INTO report_history (id, report_id, actor_id, action, old_value, new_value)
  VALUES (UUID_TO_BIN(UUID()), v_report_id, p_resolved_by, 'resolved',
    JSON_OBJECT('appeal_status', v_old_appeal_status, 'report_status', v_old_report_status),
    JSON_OBJECT('appeal_status', p_new_status, 'report_status', v_old_report_status));

  COMMIT;

  SELECT 'Appeal resolved' AS result, p_new_status AS new_status;

END //

-- ------------------------------------------------------------
-- 4. sp_recalculate_all_risk_scores
-- Cursor-based batch processing
-- Iterate all websites, calculate score, update
-- ------------------------------------------------------------
DROP PROCEDURE IF EXISTS sp_recalculate_all_risk_scores //

CREATE PROCEDURE sp_recalculate_all_risk_scores()
BEGIN
  DECLARE v_done INT DEFAULT FALSE;
  DECLARE v_website_id BINARY(16);
  DECLARE v_score DECIMAL(5,2);
  DECLARE v_risk_level VARCHAR(20);
  DECLARE v_total INT DEFAULT 0;
  DECLARE v_processed INT DEFAULT 0;

  DECLARE cur CURSOR FOR
    SELECT id FROM website_urls WHERE is_active = TRUE;

  DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = TRUE;

  -- Create temporary table for results
  CREATE TEMPORARY TABLE IF NOT EXISTS tmp_risk_results (
    website_id BINARY(16),
    new_score DECIMAL(5,2),
    new_level VARCHAR(20)
  );

  OPEN cur;

  read_loop: LOOP
    FETCH cur INTO v_website_id;
    IF v_done THEN
      LEAVE read_loop;
    END IF;

    SET v_total = v_total + 1;

    -- Calculate score
    SET v_score = fn_calculate_risk_score(v_website_id);

    -- Determine risk level
    SET v_risk_level = CASE
      WHEN v_score >= 80 THEN 'critical'
      WHEN v_score >= 60 THEN 'high'
      WHEN v_score >= 40 THEN 'medium'
      WHEN v_score >= 20 THEN 'low'
      ELSE 'safe'
    END;

    -- Update website
    UPDATE website_urls
    SET risk_score = v_score,
        risk_level = v_risk_level
    WHERE id = v_website_id;

    -- Store breakdown
    INSERT INTO risk_score_breakdowns (id, website_url_id, final_score, calculated_at)
    VALUES (UUID_TO_BIN(UUID()), v_website_id, v_score, NOW());

    -- Log in temp table
    INSERT INTO tmp_risk_results VALUES (v_website_id, v_score, v_risk_level);

    SET v_processed = v_processed + 1;
  END LOOP;

  CLOSE cur;

  -- Return results
  SELECT BIN_TO_UUID(website_id) AS website_id,
         new_score AS risk_score,
         new_level AS risk_level
  FROM tmp_risk_results;

  -- Summary
  SELECT v_processed AS processed, v_total AS total;

  DROP TEMPORARY TABLE IF EXISTS tmp_risk_results;
END //

-- ============================================================
-- 5. sp_update_reputation
-- Update user reputation score and tier
-- Insert reputation event for audit trail
-- ============================================================

DELIMITER //

DROP PROCEDURE IF EXISTS sp_update_reputation //

CREATE PROCEDURE sp_update_reputation(
  IN p_user_id BINARY(16),
  IN p_delta INT,
  IN p_reason ENUM('report_confirmed','report_denied','vote_accurate','vote_inaccurate','report_resolved','penalty','decay','manual_adjustment'),
  IN p_reference_id BINARY(16)
)
BEGIN
  DECLARE v_new_score INT;

  -- Insert reputation event
  INSERT INTO reputation_events (id, user_id, delta, reason, reference_id)
  VALUES (UUID_TO_BIN(UUID()), p_user_id, p_delta, p_reason, p_reference_id);

  -- Update reputation score (clamp to 0-100)
  UPDATE users
  SET reputation_score = GREATEST(0, LEAST(100, reputation_score + p_delta)),
      reputation_tier = fn_get_reputation_tier(GREATEST(0, LEAST(100, reputation_score + p_delta)))
  WHERE id = p_user_id;

  -- Return new score
  SELECT reputation_score INTO v_new_score FROM users WHERE id = p_user_id;
  SELECT v_new_score AS new_score;
END //

DELIMITER ;
