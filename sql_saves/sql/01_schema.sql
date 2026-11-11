-- ============================================================
-- ScamAlert — Schema v1.0
-- 20 tables, CHECK constraints, DEFAULT fallbacks, indexes
-- ============================================================

CREATE DATABASE IF NOT EXISTS scamalert
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE scamalert;

-- ------------------------------------------------------------
-- 1. users
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id               BINARY(16)    PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID())),
  email            VARCHAR(255)  NOT NULL,
  name             VARCHAR(50)   NOT NULL,
  password         VARCHAR(255)  NULL,
  role             ENUM('user','trusted_hunter','moderator','admin') NOT NULL DEFAULT 'user',
  emailVerified    BOOLEAN       NOT NULL DEFAULT FALSE,
  is_active        BOOLEAN       NOT NULL DEFAULT TRUE,
  reputation_score INT           NOT NULL DEFAULT 0,
  reputation_tier  VARCHAR(20)   NOT NULL DEFAULT 'newcomer',
  total_reports    INT           NOT NULL DEFAULT 0,
  verified_reports INT           NOT NULL DEFAULT 0,
  total_votes_cast INT           NOT NULL DEFAULT 0,
  accurate_votes   INT           NOT NULL DEFAULT 0,
  better_auth_id   VARCHAR(36)   NULL,
  last_active_date DATETIME      NULL,
  created_at       TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       TIMESTAMP     NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_users_email (email),
  UNIQUE KEY uk_users_better_auth_id (better_auth_id)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- 2. categories
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS categories (
  id              BINARY(16)    PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID())),
  name            VARCHAR(100)  NOT NULL,
  slug            VARCHAR(100)  NOT NULL,
  description     TEXT          NULL,
  severity_weight DECIMAL(3,2)  NOT NULL DEFAULT 1.00,
  icon            VARCHAR(50)   NULL,
  display_order   INT           NOT NULL DEFAULT 0,
  is_active       BOOLEAN       NOT NULL DEFAULT TRUE,
  UNIQUE KEY uk_categories_name (name),
  UNIQUE KEY uk_categories_slug (slug),
  CHECK (severity_weight BETWEEN 0 AND 10),
  CHECK (display_order >= 0)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- 3. website_urls
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS website_urls (
  id                 BINARY(16)    PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID())),
  normalized_url     TEXT          NOT NULL,
  raw_url            TEXT          NOT NULL,
  domain             VARCHAR(255)  NOT NULL,
  subdomain          VARCHAR(255)  NULL,
  registrar          VARCHAR(255)  NULL,
  registration_date  DATE          NULL,
  expiration_date    DATE          NULL,
  whois_data         JSON          NULL,
  whois_fetched_at   TIMESTAMP     NULL,
  ssl_valid          BOOLEAN       NULL,
  ssl_issuer         VARCHAR(255)  NULL,
  ssl_expiry_date    TIMESTAMP     NULL,
  dmarc_exists       BOOLEAN       NULL,
  spf_exists         BOOLEAN       NULL,
  blacklist_matches  INT           NOT NULL DEFAULT 0,
  is_active          BOOLEAN       NOT NULL DEFAULT TRUE,
  first_reported_at  TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_reported_at   TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  total_reports      INT           NOT NULL DEFAULT 0,
  confirmed_reports  INT           NOT NULL DEFAULT 0,
  active_reports     INT           NOT NULL DEFAULT 0,
  risk_score         DECIMAL(5,2)  NOT NULL DEFAULT 0.00,
  risk_level         VARCHAR(20)   NOT NULL DEFAULT 'safe',
  UNIQUE KEY uk_website_urls_normalized (normalized_url(255)),
  CHECK (risk_score BETWEEN 0 AND 100),
  CHECK (blacklist_matches >= 0),
  CHECK (total_reports >= 0),
  CHECK (confirmed_reports >= 0),
  CHECK (active_reports >= 0)
) ENGINE=InnoDB;

CREATE INDEX idx_website_urls_domain ON website_urls (domain);
CREATE INDEX idx_website_urls_risk_score ON website_urls (risk_score);

-- ------------------------------------------------------------
-- 4. fraud_reports
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fraud_reports (
  id                 BINARY(16)    PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID())),
  reporter_id        BINARY(16)    NOT NULL,
  website_url_id     BINARY(16)    NOT NULL,
  category_id        BINARY(16)    NOT NULL,
  title              VARCHAR(200)  NOT NULL,
  description        TEXT          NOT NULL,
  target_brand       VARCHAR(255)  NULL,
  amount_lost        DECIMAL(12,2) NULL,
  currency           CHAR(3)       NOT NULL DEFAULT 'INR',
  incident_date      DATE          NULL,
  country_code       CHAR(2)       NULL,
  status             ENUM('active','archived','disputed','rejected','duplicate') NOT NULL DEFAULT 'active',
  verification_stage ENUM('reported','under_review','multiple_reports','community_verified','confirmed_malicious') NOT NULL DEFAULT 'reported',
  is_anonymous       BOOLEAN       NOT NULL DEFAULT FALSE,
  is_duplicate_of    BINARY(16)    NULL,
  confirm_votes      INT           NOT NULL DEFAULT 0,
  deny_votes         INT           NOT NULL DEFAULT 0,
  total_votes        INT           NOT NULL DEFAULT 0,
  slug               VARCHAR(255)  NULL,
  created_at         TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at         TIMESTAMP     NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  resolved_at        TIMESTAMP     NULL,
  CONSTRAINT fk_reports_reporter  FOREIGN KEY (reporter_id)    REFERENCES users(id),
  CONSTRAINT fk_reports_website   FOREIGN KEY (website_url_id) REFERENCES website_urls(id),
  CONSTRAINT fk_reports_category  FOREIGN KEY (category_id)    REFERENCES categories(id),
  CONSTRAINT fk_reports_duplicate FOREIGN KEY (is_duplicate_of) REFERENCES fraud_reports(id),
  CHECK (amount_lost >= 0),
  CHECK (confirm_votes >= 0),
  CHECK (deny_votes >= 0),
  CHECK (total_votes >= 0)
) ENGINE=InnoDB;

CREATE FULLTEXT INDEX ft_reports_title_desc ON fraud_reports (title, description);
CREATE INDEX idx_reports_status_stage ON fraud_reports (status, verification_stage);
CREATE INDEX idx_reports_reporter_date ON fraud_reports (reporter_id, created_at);

-- ------------------------------------------------------------
-- 5. report_evidence
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS report_evidence (
  id             BINARY(16)    PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID())),
  report_id      BINARY(16)    NOT NULL,
  uploaded_by    BINARY(16)    NOT NULL,
  evidence_type  ENUM('screenshot','email_file','text_message','document','video','audio','url_archive','other') NOT NULL DEFAULT 'other',
  file_name      VARCHAR(255)  NOT NULL,
  file_path      TEXT          NOT NULL,
  mime_type      VARCHAR(100)  NOT NULL,
  file_size_bytes BIGINT       NOT NULL,
  sha256_hash    VARCHAR(64)   NOT NULL,
  width          INT           NULL,
  height         INT           NULL,
  description    TEXT          NULL,
  is_approved    BOOLEAN       NULL DEFAULT NULL,
  uploaded_at    TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_evidence_report FOREIGN KEY (report_id)   REFERENCES fraud_reports(id),
  CONSTRAINT fk_evidence_user   FOREIGN KEY (uploaded_by) REFERENCES users(id),
  CHECK (file_size_bytes > 0)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- 6. verification_votes
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS verification_votes (
  id                    BINARY(16)    PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID())),
  report_id             BINARY(16)    NOT NULL,
  voter_id              BINARY(16)    NOT NULL,
  vote_type             ENUM('confirm','deny','inconclusive') NOT NULL DEFAULT 'confirm',
  confidence            DECIMAL(3,2)  NOT NULL DEFAULT 1.00,
  comment               TEXT          NULL,
  voter_reputation_at_vote INT        NULL,
  created_at            TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_votes_report FOREIGN KEY (report_id) REFERENCES fraud_reports(id),
  CONSTRAINT fk_votes_voter  FOREIGN KEY (voter_id)  REFERENCES users(id),
  UNIQUE KEY uk_votes_report_voter (report_id, voter_id),
  CHECK (confidence BETWEEN 0 AND 1)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- 7. tags
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tags (
  id         BINARY(16)   PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID())),
  name       VARCHAR(50)  NOT NULL,
  slug       VARCHAR(50)  NOT NULL,
  created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_tags_name (name),
  UNIQUE KEY uk_tags_slug (slug)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- 8. report_tags (many-to-many)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS report_tags (
  report_id BINARY(16) NOT NULL,
  tag_id    BINARY(16) NOT NULL,
  PRIMARY KEY (report_id, tag_id),
  CONSTRAINT fk_rtags_report FOREIGN KEY (report_id) REFERENCES fraud_reports(id),
  CONSTRAINT fk_rtags_tag    FOREIGN KEY (tag_id)    REFERENCES tags(id)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- 9. report_comments (self-referential)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS report_comments (
  id         BINARY(16)  PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID())),
  report_id  BINARY(16)  NOT NULL,
  user_id    BINARY(16)  NOT NULL,
  parent_id  BINARY(16)  NULL,
  body       TEXT        NOT NULL,
  is_deleted BOOLEAN     NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_comments_report FOREIGN KEY (report_id) REFERENCES fraud_reports(id),
  CONSTRAINT fk_comments_user   FOREIGN KEY (user_id)   REFERENCES users(id),
  CONSTRAINT fk_comments_parent FOREIGN KEY (parent_id) REFERENCES report_comments(id)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- 10. report_history (append-only audit trail)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS report_history (
  id         BINARY(16)  PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID())),
  report_id  BINARY(16)  NOT NULL,
  actor_id   BINARY(16)  NULL,
  action     ENUM('created','updated','status_changed','vote_added','evidence_uploaded','appeal_filed','resolved') NOT NULL,
  old_value  JSON        NULL,
  new_value  JSON        NULL,
  created_at TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_history_report FOREIGN KEY (report_id) REFERENCES fraud_reports(id),
  CONSTRAINT fk_history_actor  FOREIGN KEY (actor_id)  REFERENCES users(id)
) ENGINE=InnoDB;

CREATE INDEX idx_history_report_date ON report_history (report_id, created_at);

-- ------------------------------------------------------------
-- 11. risk_score_breakdowns
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk_score_breakdowns (
  id                     BINARY(16)    PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID())),
  website_url_id         BINARY(16)    NOT NULL,
  community_sub_score    DECIMAL(5,2)  NULL,
  automated_sub_score    DECIMAL(5,2)  NULL,
  category_severity_avg  DECIMAL(3,2)  NULL,
  final_score            DECIMAL(5,2)  NULL,
  signals                JSON          NULL,
  calculated_at          TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_risk_website FOREIGN KEY (website_url_id) REFERENCES website_urls(id),
  CHECK (community_sub_score BETWEEN 0 AND 100),
  CHECK (automated_sub_score BETWEEN 0 AND 100),
  CHECK (final_score BETWEEN 0 AND 100)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- 12. appeals
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS appeals (
  id                     BINARY(16)    PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID())),
  report_id              BINARY(16)    NOT NULL,
  appellant_email        VARCHAR(255)  NOT NULL,
  domain_owner_verified  BOOLEAN       NOT NULL DEFAULT FALSE,
  status                 ENUM('pending','under_review','upheld','overturned','partially_upheld','rejected') NOT NULL DEFAULT 'pending',
  reason                 TEXT          NOT NULL,
  submitted_at           TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  resolved_at            TIMESTAMP     NULL,
  resolved_by            BINARY(16)    NULL,
  CONSTRAINT fk_appeals_report   FOREIGN KEY (report_id)   REFERENCES fraud_reports(id),
  CONSTRAINT fk_appeals_resolver FOREIGN KEY (resolved_by) REFERENCES users(id)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- 13. appeal_evidence
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS appeal_evidence (
  id            BINARY(16)   PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID())),
  appeal_id     BINARY(16)   NOT NULL,
  evidence_type ENUM('business_registration','dns_verification','html_verification','legal_document','other') NOT NULL,
  file_path     TEXT         NOT NULL,
  sha256_hash   VARCHAR(64)  NOT NULL,
  description   TEXT         NULL,
  uploaded_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_appeal_ev_appeal FOREIGN KEY (appeal_id) REFERENCES appeals(id)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- 14. reputation_events
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reputation_events (
  id           BINARY(16)  PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID())),
  user_id      BINARY(16)  NOT NULL,
  delta        INT         NOT NULL,
  reason       ENUM('report_confirmed','report_denied','vote_accurate','vote_inaccurate','report_resolved','penalty','decay','manual_adjustment') NOT NULL,
  reference_id BINARY(16)  NULL,
  created_at   TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_rep_events_user FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- 15. rate_limit_events
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rate_limit_events (
  id          BINARY(16)   PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID())),
  user_id     BINARY(16)   NULL,
  ip_address  VARCHAR(45)  NULL,
  action_type VARCHAR(50)  NOT NULL,
  created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_ratelimit_user FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB;

CREATE INDEX idx_ratelimit_user_action ON rate_limit_events (user_id, action_type, created_at);

-- ------------------------------------------------------------
-- 16. audit_events
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_events (
  id          BINARY(16)   PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID())),
  actor_id    BINARY(16)   NULL,
  action      VARCHAR(100) NOT NULL,
  entity_type VARCHAR(50)  NOT NULL,
  entity_id   BINARY(16)  NOT NULL,
  metadata    JSON         NULL,
  ip_address  VARCHAR(45)  NULL,
  created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_audit_actor FOREIGN KEY (actor_id) REFERENCES users(id)
) ENGINE=InnoDB;

CREATE INDEX idx_audit_entity ON audit_events (entity_type, entity_id);

-- ------------------------------------------------------------
-- 17. platform_config
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS platform_config (
  `key`       VARCHAR(100) PRIMARY KEY,
  value       JSON         NOT NULL,
  description TEXT         NULL,
  updated_at  TIMESTAMP    NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- 18. website_discussions
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS website_discussions (
  id               BINARY(16)   PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID())),
  website_url_id   BINARY(16)   NOT NULL,
  author_id        BINARY(16)   NOT NULL,
  title            VARCHAR(200) NOT NULL,
  body             TEXT         NOT NULL,
  is_pinned        BOOLEAN      NOT NULL DEFAULT FALSE,
  is_locked        BOOLEAN      NOT NULL DEFAULT FALSE,
  is_deleted       BOOLEAN      NOT NULL DEFAULT FALSE,
  upvotes          INT          NOT NULL DEFAULT 0,
  downvotes        INT          NOT NULL DEFAULT 0,
  reply_count      INT          NOT NULL DEFAULT 0,
  last_activity_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       TIMESTAMP    NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_disc_website FOREIGN KEY (website_url_id) REFERENCES website_urls(id),
  CONSTRAINT fk_disc_author  FOREIGN KEY (author_id)      REFERENCES users(id),
  CHECK (upvotes >= 0),
  CHECK (downvotes >= 0),
  CHECK (reply_count >= 0)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- 19. discussion_replies (self-referential, max depth 5)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS discussion_replies (
  id            BINARY(16)  PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID())),
  discussion_id BINARY(16)  NOT NULL,
  author_id     BINARY(16)  NOT NULL,
  parent_id     BINARY(16)  NULL,
  body          TEXT        NOT NULL,
  is_deleted    BOOLEAN     NOT NULL DEFAULT FALSE,
  upvotes       INT         NOT NULL DEFAULT 0,
  downvotes     INT         NOT NULL DEFAULT 0,
  depth         INT         NOT NULL DEFAULT 0,
  created_at    TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    TIMESTAMP   NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_replies_discussion FOREIGN KEY (discussion_id) REFERENCES website_discussions(id),
  CONSTRAINT fk_replies_author     FOREIGN KEY (author_id)     REFERENCES users(id),
  CONSTRAINT fk_replies_parent     FOREIGN KEY (parent_id)     REFERENCES discussion_replies(id),
  CHECK (depth >= 0 AND depth <= 5),
  CHECK (upvotes >= 0),
  CHECK (downvotes >= 0)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- 20. discussion_votes
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS discussion_votes (
  id          BINARY(16)  PRIMARY KEY DEFAULT (UUID_TO_BIN(UUID())),
  user_id     BINARY(16)  NOT NULL,
  target_type ENUM('discussion','reply') NOT NULL,
  target_id   BINARY(16)  NOT NULL,
  vote_value  TINYINT     NOT NULL,
  created_at  TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_dvotes_user FOREIGN KEY (user_id) REFERENCES users(id),
  UNIQUE KEY uk_dvotes_user_target (user_id, target_type, target_id),
  CHECK (vote_value IN (-1, 1))
) ENGINE=InnoDB;
