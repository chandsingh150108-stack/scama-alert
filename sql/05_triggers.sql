-- ============================================================
-- ScamAlert — Triggers v1.0
-- 7 triggers: cascading updates, audit trails, integrity
-- ============================================================

USE scamalert;

DELIMITER //

DROP TRIGGER IF EXISTS trg_after_report_insert //
DROP TRIGGER IF EXISTS trg_after_vote_insert //
DROP TRIGGER IF EXISTS trg_after_evidence_insert //
DROP TRIGGER IF EXISTS trg_before_user_insert //
DROP TRIGGER IF EXISTS trg_audit_report_update //
DROP TRIGGER IF EXISTS trg_audit_report_delete //
DROP TRIGGER IF EXISTS trg_prevent_vote_manipulation //

-- ------------------------------------------------------------
-- 1. trg_after_report_insert
-- AFTER INSERT on fraud_reports
-- Cascading update: website_urls report counts
-- ------------------------------------------------------------
CREATE TRIGGER trg_after_report_insert
AFTER INSERT ON fraud_reports
FOR EACH ROW
BEGIN
  -- Update website_urls report counts
  UPDATE website_urls
  SET total_reports = total_reports + 1,
      active_reports = active_reports + CASE WHEN NEW.status = 'active' THEN 1 ELSE 0 END,
      confirmed_reports = confirmed_reports + CASE WHEN NEW.verification_stage = 'confirmed_malicious' THEN 1 ELSE 0 END,
      last_reported_at = GREATEST(last_reported_at, NEW.created_at),
      first_reported_at = LEAST(first_reported_at, NEW.created_at)
  WHERE id = NEW.website_url_id;

  -- Update users report count
  UPDATE users
  SET total_reports = total_reports + 1,
      last_active_date = NOW()
  WHERE id = NEW.reporter_id;

  -- Insert audit trail
  INSERT INTO report_history (id, report_id, actor_id, action, new_value)
  VALUES (UUID_TO_BIN(UUID()), NEW.id, NEW.reporter_id, 'created',
    JSON_OBJECT('status', NEW.status, 'verification_stage', NEW.verification_stage));

  -- Award +2 reputation for submitting a report (skip for anonymous)
  IF NEW.is_anonymous = FALSE THEN
    INSERT INTO reputation_events (id, user_id, delta, reason, reference_id)
    VALUES (UUID_TO_BIN(UUID()), NEW.reporter_id, 2, 'report_resolved', NEW.id);

    UPDATE users
    SET reputation_score = GREATEST(0, LEAST(100, reputation_score + 2)),
        reputation_tier = fn_get_reputation_tier(GREATEST(0, LEAST(100, reputation_score + 2)))
    WHERE id = NEW.reporter_id;
  END IF;
END //

-- ------------------------------------------------------------
-- 2. trg_after_vote_insert
-- AFTER INSERT on verification_votes
-- Auto-update report counts + stage check
-- ------------------------------------------------------------
CREATE TRIGGER trg_after_vote_insert
AFTER INSERT ON verification_votes
FOR EACH ROW
BEGIN
  DECLARE v_stage VARCHAR(30);

  -- Update report vote counts
  UPDATE fraud_reports
  SET confirm_votes = confirm_votes + CASE WHEN NEW.vote_type = 'confirm' THEN 1 ELSE 0 END,
      deny_votes = deny_votes + CASE WHEN NEW.vote_type = 'deny' THEN 1 ELSE 0 END,
      total_votes = total_votes + 1
  WHERE id = NEW.report_id;

  -- Update user vote count
  UPDATE users
  SET total_votes_cast = total_votes_cast + 1,
      accurate_votes = accurate_votes + CASE WHEN NEW.vote_type = 'confirm' THEN 1 ELSE 0 END,
      last_active_date = NOW()
  WHERE id = NEW.voter_id;

  -- Determine new verification stage
  SET v_stage = fn_determine_verification_stage(NEW.report_id);

  -- Update stage if changed
  IF v_stage != (SELECT verification_stage FROM fraud_reports WHERE id = NEW.report_id) THEN
    UPDATE fraud_reports
    SET verification_stage = v_stage
    WHERE id = NEW.report_id;

    -- Log stage change
    INSERT INTO report_history (id, report_id, actor_id, action, old_value, new_value)
    VALUES (UUID_TO_BIN(UUID()), NEW.report_id, NEW.voter_id, 'status_changed',
      JSON_OBJECT('verification_stage', (SELECT verification_stage FROM fraud_reports WHERE id = NEW.report_id)),
      JSON_OBJECT('verification_stage', v_stage));

    -- Award reputation to reporter when report reaches community_verified
    IF v_stage = 'community_verified' THEN
      INSERT INTO reputation_events (id, user_id, delta, reason, reference_id)
      VALUES (UUID_TO_BIN(UUID()), (SELECT reporter_id FROM fraud_reports WHERE id = NEW.report_id), 5, 'report_confirmed', NEW.report_id);

      UPDATE users
      SET reputation_score = GREATEST(0, LEAST(100, reputation_score + 5)),
          reputation_tier = fn_get_reputation_tier(GREATEST(0, LEAST(100, reputation_score + 5)))
      WHERE id = (SELECT reporter_id FROM fraud_reports WHERE id = NEW.report_id);
    END IF;

    -- Deduct reputation from voter when report is denied (deny ratio > 50%)
    IF v_stage = 'under_review' AND NEW.vote_type = 'deny' THEN
      INSERT INTO reputation_events (id, user_id, delta, reason, reference_id)
      VALUES (UUID_TO_BIN(UUID()), NEW.voter_id, -3, 'vote_inaccurate', NEW.report_id);

      UPDATE users
      SET reputation_score = GREATEST(0, LEAST(100, reputation_score - 3)),
          reputation_tier = fn_get_reputation_tier(GREATEST(0, LEAST(100, reputation_score - 3)))
      WHERE id = NEW.voter_id;
    END IF;
  END IF;

  -- Insert audit trail
  INSERT INTO report_history (id, report_id, actor_id, action, new_value)
  VALUES (UUID_TO_BIN(UUID()), NEW.report_id, NEW.voter_id, 'vote_added',
    JSON_OBJECT('vote_type', NEW.vote_type, 'confidence', NEW.confidence));
END //

-- ------------------------------------------------------------
-- 3. trg_after_evidence_insert
-- AFTER INSERT on report_evidence
-- Update evidence count (informational)
-- ------------------------------------------------------------
CREATE TRIGGER trg_after_evidence_insert
AFTER INSERT ON report_evidence
FOR EACH ROW
BEGIN
  -- Update user activity
  UPDATE users
  SET last_active_date = NOW()
  WHERE id = NEW.uploaded_by;

  -- Insert audit trail
  INSERT INTO report_history (id, report_id, actor_id, action, new_value)
  VALUES (UUID_TO_BIN(UUID()), NEW.report_id, NEW.uploaded_by, 'evidence_uploaded',
    JSON_OBJECT('evidence_id', BIN_TO_UUID(NEW.id), 'evidence_type', NEW.evidence_type, 'file_name', NEW.file_name));
END //

-- ------------------------------------------------------------
-- 4. trg_before_user_insert
-- BEFORE INSERT on users
-- Default value computation
-- ------------------------------------------------------------
CREATE TRIGGER trg_before_user_insert
BEFORE INSERT ON users
FOR EACH ROW
BEGIN
  -- Compute reputation tier from score
  IF NEW.reputation_tier IS NULL OR NEW.reputation_tier = '' THEN
    SET NEW.reputation_tier = fn_get_reputation_tier(NEW.reputation_score);
  END IF;

  -- Set last_active_date if NULL
  IF NEW.last_active_date IS NULL THEN
    SET NEW.last_active_date = NOW();
  END IF;
END //

-- ------------------------------------------------------------
-- 5. trg_audit_report_update
-- AFTER UPDATE on fraud_reports
-- Audit trail: INSERT into report_history
-- ------------------------------------------------------------
CREATE TRIGGER trg_audit_report_update
AFTER UPDATE ON fraud_reports
FOR EACH ROW
BEGIN
  -- Log status changes
  IF OLD.status != NEW.status THEN
    INSERT INTO report_history (id, report_id, actor_id, action, old_value, new_value)
    VALUES (UUID_TO_BIN(UUID()), NEW.id, NULL, 'status_changed',
      JSON_OBJECT('status', OLD.status),
      JSON_OBJECT('status', NEW.status));
  END IF;

  -- Log verification stage changes
  IF OLD.verification_stage != NEW.verification_stage THEN
    INSERT INTO report_history (id, report_id, actor_id, action, old_value, new_value)
    VALUES (UUID_TO_BIN(UUID()), NEW.id, NULL, 'status_changed',
      JSON_OBJECT('verification_stage', OLD.verification_stage),
      JSON_OBJECT('verification_stage', NEW.verification_stage));
  END IF;

  -- Log any other field changes
  IF OLD.title != NEW.title OR OLD.description != NEW.description OR
     OLD.target_brand != NEW.target_brand OR OLD.amount_lost != NEW.amount_lost THEN
    INSERT INTO report_history (id, report_id, actor_id, action, old_value, new_value)
    VALUES (UUID_TO_BIN(UUID()), NEW.id, NULL, 'updated',
      JSON_OBJECT('title', OLD.title, 'description', LEFT(OLD.description, 200)),
      JSON_OBJECT('title', NEW.title, 'description', LEFT(NEW.description, 200)));
  END IF;
END //

-- ------------------------------------------------------------
-- 6. trg_audit_report_delete
-- AFTER DELETE on fraud_reports
-- Soft-delete enforcement + audit log
-- ------------------------------------------------------------
CREATE TRIGGER trg_audit_report_delete
AFTER DELETE ON fraud_reports
FOR EACH ROW
BEGIN
  -- Note: We allow hard delete but log it for audit
  -- In production, prefer soft delete via status='archived'
  INSERT INTO audit_events (id, actor_id, action, entity_type, entity_id, metadata)
  VALUES (UUID_TO_BIN(UUID()), NULL, 'hard_delete', 'fraud_reports', OLD.id,
    JSON_OBJECT('title', OLD.title, 'reporter_id', BIN_TO_UUID(OLD.reporter_id)));
END //

-- ------------------------------------------------------------
-- 7. trg_prevent_vote_manipulation
-- BEFORE INSERT on verification_votes
-- Integrity check: reputation >= 60 and max 20 votes/day.
-- (One vote per report needs no check here: the UNIQUE
-- key on verification_votes(report_id, voter_id) rejects it.)
-- ------------------------------------------------------------
CREATE TRIGGER trg_prevent_vote_manipulation
BEFORE INSERT ON verification_votes
FOR EACH ROW
BEGIN
  DECLARE v_reputation INT DEFAULT 0;
  DECLARE v_daily_votes INT DEFAULT 0;

  -- Get voter reputation
  SELECT reputation_score INTO v_reputation
  FROM users WHERE id = NEW.voter_id;

  -- Minimum reputation check (score >= 60)
  IF v_reputation < 60 THEN
    SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = 'Insufficient reputation to cast verification vote (minimum score: 60)';
  END IF;

  -- Daily limit check (20 votes/day)
  SELECT COUNT(*) INTO v_daily_votes
  FROM verification_votes
  WHERE voter_id = NEW.voter_id
    AND created_at >= DATE(NOW());

  IF v_daily_votes >= 20 THEN
    SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = 'Daily vote limit reached (20 votes per day)';
  END IF;

  -- Store voter reputation at time of vote
  SET NEW.voter_reputation_at_vote = v_reputation;
END //

-- ------------------------------------------------------------
-- 8. trg_comment_vote_integrity
-- BEFORE INSERT on comment_votes
-- Permission check: trusted+ (score >= 40) or moderator/admin role
-- Daily limit: 50 votes/day
-- ------------------------------------------------------------
DROP TRIGGER IF EXISTS trg_comment_vote_integrity //
CREATE TRIGGER trg_comment_vote_integrity
BEFORE INSERT ON comment_votes
FOR EACH ROW
BEGIN
  DECLARE v_score INT;
  DECLARE v_role VARCHAR(20);

  SELECT reputation_score, role INTO v_score, v_role
  FROM users WHERE id = NEW.user_id;

  -- Must be trusted+ (score >= 40) OR moderator/admin role
  IF v_score < 40 AND v_role NOT IN ('moderator', 'admin') THEN
    SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = 'Insufficient reputation to vote on comments (minimum tier: trusted, score: 40)';
  END IF;

  -- Daily limit: 50 votes/day (combined up+down)
  IF (SELECT COUNT(*) FROM comment_votes
      WHERE user_id = NEW.user_id AND created_at >= DATE(NOW())) >= 50 THEN
    SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = 'Daily vote limit reached (50 votes per day)';
  END IF;
END //

-- ------------------------------------------------------------
-- 9. trg_after_comment_vote
-- AFTER INSERT on comment_votes
-- Update comment vote counts, award reputation to comment author
-- ------------------------------------------------------------
DROP TRIGGER IF EXISTS trg_after_comment_vote //
CREATE TRIGGER trg_after_comment_vote
AFTER INSERT ON comment_votes
FOR EACH ROW
BEGIN
  DECLARE v_comment_author BINARY(16);
  DECLARE v_up INT DEFAULT 0;
  DECLARE v_down INT DEFAULT 0;

  -- Get comment author
  SELECT user_id INTO v_comment_author FROM report_comments WHERE id = NEW.comment_id;

  -- Recalculate counts
  SELECT
    SUM(CASE WHEN vote_value = 1 THEN 1 ELSE 0 END),
    SUM(CASE WHEN vote_value = -1 THEN 1 ELSE 0 END)
  INTO v_up, v_down
  FROM comment_votes WHERE comment_id = NEW.comment_id;

  UPDATE report_comments
  SET upvotes = COALESCE(v_up, 0), downvotes = COALESCE(v_down, 0)
  WHERE id = NEW.comment_id;

  -- Reputation reward to comment author (+1 for upvote, -1 for downvote)
  -- Skip self-votes
  IF v_comment_author != NEW.user_id THEN
    CALL sp_update_reputation(v_comment_author,
      CASE WHEN NEW.vote_value = 1 THEN 1 ELSE -1 END,
      CASE WHEN NEW.vote_value = 1 THEN 'vote_accurate' ELSE 'vote_inaccurate' END,
      NEW.comment_id);
  END IF;

  -- Audit log
  INSERT INTO audit_events (id, actor_id, action, entity_type, entity_id, metadata)
  VALUES (UUID_TO_BIN(UUID()), NEW.user_id, 'comment_vote', 'report_comments', NEW.comment_id,
    JSON_OBJECT('vote_value', NEW.vote_value));
END //

DELIMITER ;
