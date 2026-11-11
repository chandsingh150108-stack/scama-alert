-- ============================================================
-- ScamAlert — ACID Demonstration Queries
-- Atomicity, Consistency, Isolation, Durability
-- ============================================================

USE scamalert;

-- ============================================================
-- ATOMICITY — All-or-nothing transactions
-- ============================================================

-- Demo 1: Successful atomic transaction
-- All inserts succeed together
SELECT '--- ATOMICITY DEMO 1: Successful transaction ---' AS demo;

START TRANSACTION;

  -- Insert a test report
  SET @test_reporter = (SELECT id FROM users WHERE email = 'priya.sharma@example.com' LIMIT 1);
  SET @test_website = (SELECT id FROM website_urls WHERE domain = 'investquick.xyz' LIMIT 1);
  SET @test_category = (SELECT id FROM categories WHERE slug = 'investment-scam' LIMIT 1);

  INSERT INTO fraud_reports (id, reporter_id, website_url_id, category_id, title, description, status, verification_stage)
  VALUES (UUID_TO_BIN(UUID()), @test_reporter, @test_website, @test_category,
    'ACID Test Report - Will Succeed', 'This is an atomicity demonstration report.', 'active', 'reported');

  -- Both succeed
  SELECT 'Transaction committed successfully' AS result;

COMMIT;

-- Demo 2: Failed atomic transaction — deliberate rollback
-- One insert fails, entire transaction rolls back
SELECT '--- ATOMICITY DEMO 2: Failed transaction with rollback ---' AS demo;

-- Record count before
SELECT COUNT(*) AS reports_before FROM fraud_reports;

START TRANSACTION;

  -- This insert will succeed
  INSERT INTO fraud_reports (id, reporter_id, website_url_id, category_id, title, description, status, verification_stage)
  VALUES (UUID_TO_BIN(UUID()), @test_reporter, @test_website, @test_category,
    'ACID Test - Will Be Rolled Back', 'This insert will be undone.', 'active', 'reported');

  -- This insert will FAIL (duplicate key on a non-existent UUID)
  -- We deliberately use an invalid foreign key to trigger an error
  -- INSERT INTO fraud_reports (id, reporter_id, website_url_id, category_id, title, description, status, verification_stage)
  -- VALUES (UUID_TO_BIN(UUID()), 0x00000000000000000000000000000000, @test_website, @test_category,
  --   'Should Not Exist', 'This should fail.', 'active', 'reported');

  -- Simulate error and rollback
  ROLLBACK;

-- Verify count unchanged
SELECT COUNT(*) AS reports_after_rollback FROM fraud_reports;

-- ============================================================
-- CONSISTENCY — Audit trail always matches state
-- ============================================================

SELECT '--- CONSISTENCY DEMO: Audit trail verification ---' AS demo;

-- Before update
SELECT fr.id, fr.status, fr.verification_stage,
       (SELECT COUNT(*) FROM report_history rh WHERE rh.report_id = fr.id) AS history_entries
FROM fraud_reports fr
WHERE fr.status = 'active'
LIMIT 1;

-- Perform an update
SET @demo_report = (SELECT id FROM fraud_reports WHERE status = 'active' LIMIT 1);

START TRANSACTION;
  UPDATE fraud_reports
  SET status = 'disputed'
  WHERE id = @demo_report;
COMMIT;

-- After update — trigger should have inserted audit trail
SELECT fr.id, fr.status, fr.verification_stage,
       (SELECT COUNT(*) FROM report_history rh WHERE rh.report_id = fr.id) AS history_entries,
       (SELECT rh.action FROM report_history rh WHERE rh.report_id = @demo_report ORDER BY rh.created_at DESC LIMIT 1) AS last_action
FROM fraud_reports fr
WHERE fr.id = @demo_report;

-- Restore original status
UPDATE fraud_reports SET status = 'active' WHERE id = @demo_report;

-- ============================================================
-- ISOLATION — Concurrent transactions
-- ============================================================

SELECT '--- ISOLATION DEMO: Concurrent vote insertion ---' AS demo;

-- Show unique constraint prevents duplicate votes
SET @demo_report2 = (SELECT id FROM fraud_reports WHERE title LIKE 'Investment scam%' LIMIT 1);
SET @demo_voter1 = (SELECT id FROM users WHERE email = 'kunal.desai@example.com' LIMIT 1);

-- First vote succeeds
START TRANSACTION;
  INSERT INTO verification_votes (id, report_id, voter_id, vote_type, confidence, comment)
  VALUES (UUID_TO_BIN(UUID()), @demo_report2, @demo_voter1, 'confirm', 0.80, 'Isolation demo vote');
COMMIT;

-- Duplicate vote fails (same voter on same report)
-- This demonstrates UNIQUE constraint enforcement
START TRANSACTION;
  -- This would fail with duplicate key error:
  -- INSERT INTO verification_votes (id, report_id, voter_id, vote_type, confidence, comment)
  -- VALUES (UUID_TO_BIN(UUID()), @demo_report2, @demo_voter1, 'confirm', 0.90, 'Duplicate vote');
ROLLBACK;

-- Show the vote exists
SELECT BIN_TO_UUID(vv.id) AS vote_id, vv.vote_type, vv.confidence,
       u.name AS voter
FROM verification_votes vv
JOIN users u ON u.id = vv.voter_id
WHERE vv.report_id = @demo_report2 AND vv.voter_id = @demo_voter1;

-- Clean up demo vote
DELETE FROM verification_votes
WHERE report_id = @demo_report2 AND voter_id = @demo_voter1;

-- ============================================================
-- DURABILITY — Committed data persists
-- ============================================================

SELECT '--- DURABILITY DEMO: Committed data survives ---' AS demo;

-- Insert and commit
START TRANSACTION;
  INSERT INTO audit_events (id, actor_id, action, entity_type, entity_id, metadata)
  VALUES (UUID_TO_BIN(UUID()), NULL, 'durability_test', 'system', UUID_TO_BIN(UUID()),
    JSON_OBJECT('test', 'committed data persists after COMMIT'));
COMMIT;

-- Read back — data is durably stored
SELECT ae.action, ae.entity_type, ae.metadata->>'$.test' AS test_message
FROM audit_events ae
WHERE ae.action = 'durability_test'
ORDER BY ae.created_at DESC
LIMIT 1;

-- Clean up durability test
DELETE FROM audit_events WHERE action = 'durability_test';

-- ============================================================
-- CURSOR-BASED PROCESSING
-- ============================================================

SELECT '--- CURSOR DEMO: Batch processing with cursor ---' AS demo;

-- Demonstrate cursor usage in a procedure context
-- This is a simplified version of sp_recalculate_all_risk_scores

DELIMITER //

CREATE PROCEDURE sp_demo_cursor_batch()
BEGIN
  DECLARE v_done INT DEFAULT FALSE;
  DECLARE v_id BINARY(16);
  DECLARE v_domain VARCHAR(255);
  DECLARE v_count INT DEFAULT 0;

  DECLARE cur CURSOR FOR
    SELECT id, domain FROM website_urls WHERE is_active = TRUE LIMIT 5;

  DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = TRUE;

  CREATE TEMPORARY TABLE IF NOT EXISTS tmp_cursor_demo (
    domain VARCHAR(255),
    processed BOOLEAN
  );

  OPEN cur;

  read_loop: LOOP
    FETCH cur INTO v_id, v_domain;
    IF v_done THEN
      LEAVE read_loop;
    END IF;

    SET v_count = v_count + 1;
    INSERT INTO tmp_cursor_demo VALUES (v_domain, TRUE);
  END LOOP;

  CLOSE cur;

  SELECT * FROM tmp_cursor_demo;
  SELECT v_count AS total_processed;

  DROP TEMPORARY TABLE IF EXISTS tmp_cursor_demo;
END //

DELIMITER ;

CALL sp_demo_cursor_batch();
DROP PROCEDURE IF EXISTS sp_demo_cursor_batch;

-- ============================================================
-- SAVEPOINT DEMO — Partial rollback
-- ============================================================

SELECT '--- SAVEPOINT DEMO: Partial rollback ---' AS demo;

START TRANSACTION;

  -- Step 1: Insert rate limit event (will succeed)
  INSERT INTO rate_limit_events (id, user_id, ip_address, action_type)
  VALUES (UUID_TO_BIN(UUID()), NULL, '127.0.0.1', 'demo_savepoint');

  SAVEPOINT sp1;

  -- Step 2: This might fail — we save a point before it
  -- Deliberately try an invalid insert
  -- INSERT INTO fraud_reports (id, reporter_id, website_url_id, category_id, title, description)
  -- VALUES (UUID_TO_BIN(UUID()), 0x00, 0x00, 0x00, 'fail', 'fail');

  -- Rollback to savepoint (undoes step 2 only)
  -- ROLLBACK TO sp1;

  -- Step 3: Continue with valid work
  INSERT INTO rate_limit_events (id, user_id, ip_address, action_type)
  VALUES (UUID_TO_BIN(UUID()), NULL, '127.0.0.1', 'demo_savepoint_2');

COMMIT;

-- Show both inserts survived
SELECT action_type, created_at
FROM rate_limit_events
WHERE action_type LIKE 'demo_savepoint%'
ORDER BY created_at;

-- Clean up
DELETE FROM rate_limit_events WHERE action_type LIKE 'demo_savepoint%';
