-- ============================================================
-- ScamAlert — Cleanup Script
-- Drops all objects in reverse dependency order
-- ============================================================

USE scamalert;

-- Drop tables in reverse FK order
DROP TABLE IF EXISTS discussion_votes;
DROP TABLE IF EXISTS discussion_replies;
DROP TABLE IF EXISTS website_discussions;
DROP TABLE IF EXISTS platform_config;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS rate_limit_events;
DROP TABLE IF EXISTS reputation_events;
DROP TABLE IF EXISTS appeal_evidence;
DROP TABLE IF EXISTS appeals;
DROP TABLE IF EXISTS risk_score_breakdowns;
DROP TABLE IF EXISTS report_history;
DROP TABLE IF EXISTS report_comments;
DROP TABLE IF EXISTS report_tags;
DROP TABLE IF EXISTS tags;
DROP TABLE IF EXISTS verification_votes;
DROP TABLE IF EXISTS report_evidence;
DROP TABLE IF EXISTS fraud_reports;
DROP TABLE IF EXISTS website_urls;
DROP TABLE IF EXISTS categories;
DROP TABLE IF EXISTS users;
-- Better Auth auto-created tables
DROP TABLE IF EXISTS `verification`;
DROP TABLE IF EXISTS `session`;
DROP TABLE IF EXISTS `account`;
DROP TABLE IF EXISTS `user`;
