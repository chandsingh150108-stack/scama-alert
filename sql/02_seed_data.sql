-- ============================================================
-- ScamAlert — Seed Data v1.0
-- 15 users, 8 websites, 13 reports + evidence, votes, tags
-- ============================================================

USE scamalert;

-- ------------------------------------------------------------
-- Categories (10)
-- ------------------------------------------------------------
INSERT INTO categories (id, name, slug, description, severity_weight, icon, display_order) VALUES
(UUID_TO_BIN(UUID()), 'Investment scam', 'investment-scam', 'Fake investment platforms promising high returns', 9.5, 'trending-up', 1),
(UUID_TO_BIN(UUID()), 'Malware', 'malware', 'Sites distributing malicious software', 9.5, 'bug', 2),
(UUID_TO_BIN(UUID()), 'Phishing', 'phishing', 'Sites impersonating legitimate organisations to steal credentials', 9.0, 'fish', 3),
(UUID_TO_BIN(UUID()), 'Payment fraud', 'payment-fraud', 'Fraudulent payment collection or unauthorised charges', 8.5, 'credit-card', 4),
(UUID_TO_BIN(UUID()), 'Fake e-commerce', 'fake-ecommerce', 'Online stores that take money but never deliver', 8.0, 'shopping-cart', 5),
(UUID_TO_BIN(UUID()), 'Impersonation', 'impersonation', 'Sites impersonating known brands or persons', 8.0, 'copy', 6),
(UUID_TO_BIN(UUID()), 'Fake job scam', 'fake-job-scam', 'Fraudulent job listings demanding upfront payment', 7.5, 'briefcase', 7),
(UUID_TO_BIN(UUID()), 'Product never delivered', 'product-never-delivered', 'Paid for product but nothing arrived', 7.0, 'package-x', 8),
(UUID_TO_BIN(UUID()), 'Suspicious behaviour', 'suspicious-behaviour', 'General suspicious online behaviour', 5.0, 'alert-triangle', 9),
(UUID_TO_BIN(UUID()), 'Other', 'other', 'Other fraud not covered above', 4.0, 'help-circle', 10);

-- ------------------------------------------------------------
-- Users (15) — Indian names across all tiers
-- Password hash is a bcrypt placeholder ($2b$10$placeholder)
-- ------------------------------------------------------------
SET @pwd = '$2b$10$placeholder';
-- Demo logins (password Password@123, bcrypt cost 12)
SET @demo_pwd = '$2b$12$UcYtetOF0xemgdtvXf0w3Oe5o3V1ll/BBjYu08X3JRpVbTcv8SiOi';

INSERT INTO users (id, email, name, password, role, emailVerified, is_active, reputation_score, reputation_tier, total_reports, verified_reports, total_votes_cast, accurate_votes, better_auth_id) VALUES
-- Anonymous sentinel (fixed UUID for anonymous submissions)
(UUID_TO_BIN('00000000-0000-0000-0000-000000000001'), 'anonymous@scamalert.local', 'Anonymous', NULL, 'user', FALSE, TRUE, 0, 'newcomer', 0, 0, 0, 0, NULL),
-- Admin + Moderator
(UUID_TO_BIN(UUID()), 'arjun.mehta@example.com',   'Arjun M.',   @pwd, 'admin',         TRUE, TRUE, 95, 'moderator',  12, 11, 50, 48, NULL),
(UUID_TO_BIN(UUID()), 'priya.sharma@example.com',  'Priya S.',   @pwd, 'moderator',     TRUE, TRUE, 88, 'moderator',  18, 16, 42, 39, NULL),
-- Trusted hunters
(UUID_TO_BIN(UUID()), 'rahul.patel@example.com',   'Rahul P.',   @pwd, 'trusted_hunter', TRUE, TRUE, 75, 'expert',     10,  8, 35, 30, NULL),
(UUID_TO_BIN(UUID()), 'ananya.singh@example.com',  'Ananya S.',  @pwd, 'trusted_hunter', TRUE, TRUE, 72, 'expert',      9,  7, 28, 24, NULL),
(UUID_TO_BIN(UUID()), 'vikram.joshi@example.com',  'Vikram J.',  @pwd, 'trusted_hunter', TRUE, TRUE, 58, 'trusted',     6,  5, 20, 17, NULL),
-- Regular users
(UUID_TO_BIN(UUID()), 'neha.gupta@example.com',    'Neha G.',    @pwd, 'user',           TRUE, TRUE, 48, 'trusted',     4,  3, 15, 12, NULL),
(UUID_TO_BIN(UUID()), 'amit.kumar@example.com',    'Amit K.',    @pwd, 'user',           TRUE, TRUE, 45, 'trusted',     3,  2, 12, 10, NULL),
(UUID_TO_BIN(UUID()), 'sneha.reddy@example.com',   'Sneha R.',   @pwd, 'user',           TRUE, TRUE, 35, 'new',         2,  1,  8,  6, NULL),
(UUID_TO_BIN(UUID()), 'kunal.desai@example.com',   'Kunal D.',   @pwd, 'user',           TRUE, TRUE, 28, 'new',         2,  1,  5,  4, NULL),
(UUID_TO_BIN(UUID()), 'deepa.nair@example.com',    'Deepa N.',   @pwd, 'user',           TRUE, TRUE, 15, 'newcomer',    1,  0,  3,  2, NULL),
(UUID_TO_BIN(UUID()), 'sanjay.verma@example.com',  'Sanjay V.',  @pwd, 'user',           TRUE, TRUE, 10, 'newcomer',    1,  0,  2,  1, NULL),
(UUID_TO_BIN(UUID()), 'pooja.iyer@example.com',    'Pooja I.',   @pwd, 'user',           TRUE, TRUE,  5, 'newcomer',    1,  0,  1,  0, NULL),
(UUID_TO_BIN(UUID()), 'karthik.bose@example.com',  'Karthik B.', @pwd, 'user',           TRUE, TRUE,  3, 'newcomer',    1,  0,  1,  0, NULL),
(UUID_TO_BIN(UUID()), 'ritu.chopra@example.com',   'Ritu C.',    @pwd, 'user',           TRUE, TRUE,  0, 'newcomer',    0,  0,  0,  0, NULL),
(UUID_TO_BIN(UUID()), 'manish.tiwari@example.com', 'Manish T.',  @pwd, 'user',           TRUE, TRUE,  0, 'newcomer',    0,  0,  0,  0, NULL),
-- Demo quick-fill accounts (see login page)
(UUID_TO_BIN(UUID()), 'admin@scamalert.in', 'Arjun', @demo_pwd, 'admin', TRUE, TRUE, 95, 'moderator', 0, 0, 0, 0, NULL),
(UUID_TO_BIN(UUID()), 'moderator@scamalert.in', 'Sunita', @demo_pwd, 'moderator', TRUE, TRUE, 88, 'moderator', 0, 0, 0, 0, NULL);

-- ------------------------------------------------------------
-- Website URLs (8) — varying risk levels
-- ------------------------------------------------------------
INSERT INTO website_urls (id, normalized_url, raw_url, domain, subdomain, ssl_valid, dmarc_exists, spf_exists, blacklist_matches, risk_score, risk_level, total_reports, confirmed_reports, active_reports) VALUES
(UUID_TO_BIN(UUID()), 'https://investquick.xyz',        'http://investquick.xyz',        'investquick.xyz',        NULL,             FALSE, FALSE, FALSE, 8,  92.50, 'critical', 3, 2, 3),
(UUID_TO_BIN(UUID()), 'https://cheapdeals.shop',        'https://cheapdeals.shop',        'cheapdeals.shop',        NULL,             TRUE,  FALSE, FALSE, 5,  74.20, 'high',     2, 1, 2),
(UUID_TO_BIN(UUID()), 'https://bankofindia-secure.xyz', 'https://bankofindia-secure.xyz', 'bankofindia-secure.xyz', NULL,             FALSE, FALSE, FALSE, 6,  71.80, 'high',     2, 1, 2),
(UUID_TO_BIN(UUID()), 'https://jobfresher.com',         'https://jobfresher.com',         'jobfresher.com',         'www',            TRUE,  TRUE,  TRUE,  2,  48.50, 'medium',   2, 0, 2),
(UUID_TO_BIN(UUID()), 'https://payeazy.in',             'https://payeazy.in',             'payeazy.in',             NULL,             TRUE,  FALSE, TRUE,  1,  42.10, 'medium',   1, 0, 1),
(UUID_TO_BIN(UUID()), 'https://flipkart-sale.com',      'https://flipkart-sale.com',      'flipkart-sale.com',      NULL,             TRUE,  FALSE, FALSE, 3,  38.70, 'medium',   1, 0, 1),
(UUID_TO_BIN(UUID()), 'https://legitmart.com',          'https://legitmart.com',          'legitmart.com',          'www',            TRUE,  TRUE,  TRUE,  0,  15.30, 'low',      1, 1, 0),
(UUID_TO_BIN(UUID()), 'https://knowngood.in',           'https://knowngood.in',           'knowngood.in',           NULL,             TRUE,  TRUE,  TRUE,  0,   2.10, 'safe',     1, 0, 0);

-- ------------------------------------------------------------
-- Fraud Reports (13)
-- ------------------------------------------------------------
-- Get user IDs into variables for FK references
SET @arjun  = (SELECT id FROM users WHERE email = 'arjun.mehta@example.com');
SET @priya  = (SELECT id FROM users WHERE email = 'priya.sharma@example.com');
SET @rahul  = (SELECT id FROM users WHERE email = 'rahul.patel@example.com');
SET @ananya = (SELECT id FROM users WHERE email = 'ananya.singh@example.com');
SET @vikram = (SELECT id FROM users WHERE email = 'vikram.joshi@example.com');
SET @neha   = (SELECT id FROM users WHERE email = 'neha.gupta@example.com');
SET @amit   = (SELECT id FROM users WHERE email = 'amit.kumar@example.com');
SET @sneha  = (SELECT id FROM users WHERE email = 'sneha.reddy@example.com');
SET @kunal  = (SELECT id FROM users WHERE email = 'kunal.desai@example.com');
SET @deepa  = (SELECT id FROM users WHERE email = 'deepa.nair@example.com');
SET @sanjay = (SELECT id FROM users WHERE email = 'sanjay.verma@example.com');
SET @pooja  = (SELECT id FROM users WHERE email = 'pooja.iyer@example.com');
SET @karthik= (SELECT id FROM users WHERE email = 'karthik.bose@example.com');
SET @ritu   = (SELECT id FROM users WHERE email = 'ritu.chopra@example.com');

SET @w1 = (SELECT id FROM website_urls WHERE domain = 'investquick.xyz');
SET @w2 = (SELECT id FROM website_urls WHERE domain = 'cheapdeals.shop');
SET @w3 = (SELECT id FROM website_urls WHERE domain = 'bankofindia-secure.xyz');
SET @w4 = (SELECT id FROM website_urls WHERE domain = 'jobfresher.com');
SET @w5 = (SELECT id FROM website_urls WHERE domain = 'payeazy.in');
SET @w6 = (SELECT id FROM website_urls WHERE domain = 'flipkart-sale.com');
SET @w7 = (SELECT id FROM website_urls WHERE domain = 'legitmart.com');
SET @w8 = (SELECT id FROM website_urls WHERE domain = 'knowngood.in');

SET @cat_invest  = (SELECT id FROM categories WHERE slug = 'investment-scam');
SET @cat_phish   = (SELECT id FROM categories WHERE slug = 'phishing');
SET @cat_pay     = (SELECT id FROM categories WHERE slug = 'payment-fraud');
SET @cat_ecom    = (SELECT id FROM categories WHERE slug = 'fake-ecommerce');
SET @cat_impost  = (SELECT id FROM categories WHERE slug = 'impersonation');
SET @cat_job     = (SELECT id FROM categories WHERE slug = 'fake-job-scam');
SET @cat_product = (SELECT id FROM categories WHERE slug = 'product-never-delivered');
SET @cat_susp    = (SELECT id FROM categories WHERE slug = 'suspicious-behaviour');
SET @cat_other   = (SELECT id FROM categories WHERE slug = 'other');

INSERT INTO fraud_reports (id, reporter_id, website_url_id, category_id, title, description, target_brand, amount_lost, currency, incident_date, country_code, status, verification_stage, confirm_votes, deny_votes, total_votes) VALUES
-- investquick.xyz (3 reports)
(UUID_TO_BIN(UUID()), @priya,  @w1, @cat_invest,  'Investment scam - fake crypto platform',
  'This website promises 30% monthly returns on crypto investments. I deposited 50000 INR and cannot withdraw. Customer support stopped responding after 2 weeks.',
  'InvestQuick', 50000.00, 'INR', '2026-08-15', 'IN', 'active', 'community_verified', 8, 1, 9),

(UUID_TO_BIN(UUID()), @rahul,  @w1, @cat_pay,     'Unauthorized credit card charges after signup',
  'Signed up for a free trial on investquick.xyz. They charged 15000 INR to my credit card without authorization. Statement shows 3 charges of 5000 each.',
  'InvestQuick', 15000.00, 'INR', '2026-08-20', 'IN', 'active', 'multiple_reports', 5, 0, 5),

(UUID_TO_BIN(UUID()), @ananya, @w1, @cat_impost,  'Impersonating SEBI registered advisor',
  'This site claims to be a SEBI-registered investment advisor. I verified on SEBI website - no such registration exists. They are using fake SEBI logos.',
  'InvestQuick', NULL, 'INR', '2026-09-01', 'IN', 'active', 'reported', 3, 0, 3),

-- cheapdeals.shop (2 reports)
(UUID_TO_BIN(UUID()), @vikram, @w2, @cat_ecom,    'Fake e-commerce - no delivery after payment',
  'Ordered electronics worth 12000 INR. Payment confirmed via UPI. Order status shows "shipped" but no tracking number provided. 3 weeks have passed.',
  NULL, 12000.00, 'INR', '2026-08-25', 'IN', 'active', 'multiple_reports', 6, 1, 7),

(UUID_TO_BIN(UUID()), @neha,   @w2, @cat_product, 'Product never delivered - refund not responding',
  'Ordered clothes for 3500 INR. Product never arrived. Called the number on website - it is switched off. Email bounces back.',
  NULL, 3500.00, 'INR', '2026-09-05', 'IN', 'active', 'reported', 2, 0, 2),

-- bankofindia-secure.xyz (2 reports)
(UUID_TO_BIN(UUID()), @amit,   @w3, @cat_phish,   'Phishing - fake Bank of India login page',
  'Received SMS saying "Your BOI account is locked, click here to unlock". The URL is bankofindia-secure.xyz, NOT the real bankofindia.com. This is a phishing page for credentials.',
  'Bank of India', NULL, 'INR', '2026-08-28', 'IN', 'active', 'community_verified', 9, 0, 9),

(UUID_TO_BIN(UUID()), @sneha,  @w3, @cat_impost,  'Impersonating Bank of India to steal OTP',
  'Same phishing campaign. They call pretending to be bank officials and ask for OTP. My father almost lost 25000 INR. Reported to police.',
  'Bank of India', 25000.00, 'INR', '2026-09-02', 'IN', 'active', 'multiple_reports', 4, 0, 4),

-- jobfresher.com (2 reports)
(UUID_TO_BIN(UUID()), @kunal,  @w4, @cat_job,     'Fake job scam - demands training fee',
  'Applied for "Data Entry Operator" job. Received call asking to pay 2500 INR for "training materials". After payment, no further communication. Phone number switched off.',
  NULL, 2500.00, 'INR', '2026-09-08', 'IN', 'active', 'reported', 1, 0, 1),

(UUID_TO_BIN(UUID()), @deepa,  @w4, @cat_job,     'Fake job offer - asked for bank details',
  'Received email saying I was selected for "Content Writer" role. Asked for bank account details for "salary setup" before joining. Suspicious - no interview was conducted.',
  NULL, NULL, 'INR', '2026-09-10', 'IN', 'active', 'reported', 1, 0, 1),

-- payeazy.in (1 report)
(UUID_TO_BIN(UUID()), @sanjay, @w5, @cat_susp,    'Suspicious payment gateway behaviour',
  'This payment gateway asked for CVV and PIN during a transaction. Legitimate gateways never ask for PIN. Almost entered my PIN before realising something was wrong.',
  NULL, NULL, 'INR', '2026-09-06', 'IN', 'active', 'reported', 2, 0, 2),

-- flipkart-sale.com (1 report)
(UUID_TO_BIN(UUID()), @pooja,  @w6, @cat_impost,  'Fake Flipkart sale website',
  'Website looks exactly like Flipkart but URL is flipkart-sale.com. Selling iPhone 15 for 9999 INR. Too good to be true. Likely a phishing/fraud site impersonating Flipkart.',
  'Flipkart', NULL, 'INR', '2026-09-09', 'IN', 'active', 'reported', 3, 0, 3),

-- legitmart.com (1 report - archived, community verified)
(UUID_TO_BIN(UUID()), @karthik, @w7, @cat_other,  'Suspicious refund policy',
  'The refund policy is extremely vague and gives them 90 days to process refunds. Contacted support - very slow responses. Marking as suspicious but not confirmed fraud.',
  NULL, NULL, 'INR', '2026-07-20', 'IN', 'archived', 'community_verified', 7, 2, 9),

-- knowngood.in (1 report - rejected)
(UUID_TO_BIN(UUID()), @ritu,   @w8, @cat_other,   'False report - this is a legitimate site',
  'I reported this site by mistake. It is actually a legitimate business. Please disregard this report. I am a new user and made an error.',
  NULL, NULL, 'INR', '2026-09-01', 'IN', 'rejected', 'under_review', 0, 5, 5);

-- ------------------------------------------------------------
-- Tags (5)
-- ------------------------------------------------------------
INSERT INTO tags (id, name, slug) VALUES
(UUID_TO_BIN(UUID()), 'UPI fraud',        'upi-fraud'),
(UUID_TO_BIN(UUID()), 'Credential theft', 'credential-theft'),
(UUID_TO_BIN(UUID()), 'Credit card',      'credit-card'),
(UUID_TO_BIN(UUID()), 'Crypto scam',      'crypto-scam'),
(UUID_TO_BIN(UUID()), 'Job fraud',        'job-fraud');

-- Link reports to tags
SET @t1 = (SELECT id FROM tags WHERE slug = 'upi-fraud');
SET @t2 = (SELECT id FROM tags WHERE slug = 'credential-theft');
SET @t3 = (SELECT id FROM tags WHERE slug = 'credit-card');
SET @t4 = (SELECT id FROM tags WHERE slug = 'crypto-scam');
SET @t5 = (SELECT id FROM tags WHERE slug = 'job-fraud');

SET @r1 = (SELECT id FROM fraud_reports WHERE title LIKE 'Investment scam%' LIMIT 1);
SET @r2 = (SELECT id FROM fraud_reports WHERE title LIKE 'Unauthorized%' LIMIT 1);
SET @r3 = (SELECT id FROM fraud_reports WHERE title LIKE 'Phishing%' LIMIT 1);
SET @r4 = (SELECT id FROM fraud_reports WHERE title LIKE 'Fake e-commerce%' LIMIT 1);
SET @r5 = (SELECT id FROM fraud_reports WHERE title LIKE 'Fake job scam%' LIMIT 1);

INSERT INTO report_tags (report_id, tag_id) VALUES
(@r1, @t4),
(@r2, @t3),
(@r3, @t2),
(@r4, @t1),
(@r5, @t5);

-- ------------------------------------------------------------
-- Report Evidence (8 samples)
-- ------------------------------------------------------------
SET @rpt1 = (SELECT id FROM fraud_reports WHERE title LIKE 'Investment scam%' LIMIT 1);
SET @rpt2 = (SELECT id FROM fraud_reports WHERE title LIKE 'Unauthorized%' LIMIT 1);
SET @rpt3 = (SELECT id FROM fraud_reports WHERE title LIKE 'Phishing%' LIMIT 1);
SET @rpt4 = (SELECT id FROM fraud_reports WHERE title LIKE 'Fake e-commerce%' LIMIT 1);
SET @rpt5 = (SELECT id FROM fraud_reports WHERE title LIKE 'Impersonating Bank%' LIMIT 1);
SET @rpt6 = (SELECT id FROM fraud_reports WHERE title LIKE 'Fake Flipkart%' LIMIT 1);
SET @rpt7 = (SELECT id FROM fraud_reports WHERE title LIKE 'Suspicious payment%' LIMIT 1);
SET @rpt8 = (SELECT id FROM fraud_reports WHERE title LIKE 'False report%' LIMIT 1);
SET @rpt_legit = (SELECT id FROM fraud_reports WHERE title LIKE 'Suspicious refund%' LIMIT 1);

INSERT INTO report_evidence (id, report_id, uploaded_by, evidence_type, file_name, file_path, mime_type, file_size_bytes, sha256_hash, description, is_approved) VALUES
(UUID_TO_BIN(UUID()), @rpt1, @priya,  'screenshot', 'investquick-homepage.png',   '/uploads/evidence/1/screenshot1.png', 'image/png', 245000, 'abc123hash1', 'Screenshot of homepage showing 30% monthly return promise', TRUE),
(UUID_TO_BIN(UUID()), @rpt2, @rahul,  'document',   'bank-statement.pdf',         '/uploads/evidence/2/statement.pdf',  'application/pdf', 180000, 'abc123hash2', 'Bank statement showing unauthorized charges', TRUE),
(UUID_TO_BIN(UUID()), @rpt3, @amit,   'screenshot', 'phishing-sms.png',           '/uploads/evidence/3/sms.png',        'image/png', 95000, 'abc123hash3', 'SMS screenshot with phishing link', TRUE),
(UUID_TO_BIN(UUID()), @rpt4, @vikram, 'screenshot', 'order-confirmation.png',      '/uploads/evidence/4/order.png',      'image/png', 110000, 'abc123hash4', 'Order confirmation with no tracking', TRUE),
(UUID_TO_BIN(UUID()), @rpt5, @sneha,  'text_message', 'scam-call-log.txt',         '/uploads/evidence/5/calllog.txt',    'text/plain', 2500, 'abc123hash5', 'Log of scam calls received', TRUE),
(UUID_TO_BIN(UUID()), @rpt6, @pooja,  'screenshot', 'fake-flipkart.png',          '/uploads/evidence/6/fakeflip.png',   'image/png', 180000, 'abc123hash6', 'Screenshot of fake Flipkart sale page', NULL),
(UUID_TO_BIN(UUID()), @rpt7, @sanjay, 'screenshot', 'suspicious-gateway.png',     '/uploads/evidence/7/gateway.png',    'image/png', 75000, 'abc123hash7', 'Screenshot of payment page asking for PIN', NULL),
(UUID_TO_BIN(UUID()), @rpt1, @rahul,  'url_archive', 'investquick-archive.html',  '/uploads/evidence/1/archive.html',   'text/html', 320000, 'abc123hash8', 'Wayback Machine archive of the site', TRUE);

-- ------------------------------------------------------------
-- Verification Votes (15 samples)
-- ------------------------------------------------------------
INSERT INTO verification_votes (id, report_id, voter_id, vote_type, confidence, comment, voter_reputation_at_vote) VALUES
-- Report 1 (Investment scam) - strong community verified
(UUID_TO_BIN(UUID()), @rpt1, @rahul,  'confirm', 1.00, 'I also lost money on this platform. Definitely a scam.', 75),
(UUID_TO_BIN(UUID()), @rpt1, @ananya, 'confirm', 0.95, 'Verified - SEBI has no record of this advisor.', 72),
(UUID_TO_BIN(UUID()), @rpt1, @vikram, 'confirm', 0.90, 'Multiple friends reported same issue.', 58),
(UUID_TO_BIN(UUID()), @rpt1, @neha,   'confirm', 0.85, 'Checked domain - registered 2 months ago.', 48),
(UUID_TO_BIN(UUID()), @rpt1, @amit,   'confirm', 0.80, 'Classic crypto scam pattern.', 45),
(UUID_TO_BIN(UUID()), @rpt1, @kunal,  'deny',    0.60, 'I was able to withdraw my money. Might not be a scam.', 28),
-- Report 6 (Phishing) - strong community verified
(UUID_TO_BIN(UUID()), @rpt3, @priya,  'confirm', 1.00, 'The domain bankofindia-secure.xyz is definitely not BOI official.', 88),
(UUID_TO_BIN(UUID()), @rpt3, @rahul,  'confirm', 1.00, 'BOI confirmed this is not their website when I called.', 75),
(UUID_TO_BIN(UUID()), @rpt3, @ananya, 'confirm', 0.95, 'URL analysis shows it is hosted on suspicious infrastructure.', 72),
(UUID_TO_BIN(UUID()), @rpt3, @vikram, 'confirm', 0.90, 'Reported to cybercrime.gov.in as well.', 58),
-- Report 4 (Fake e-commerce)
(UUID_TO_BIN(UUID()), @rpt4, @neha,   'confirm', 0.90, 'Same experience - no delivery.', 48),
(UUID_TO_BIN(UUID()), @rpt4, @amit,   'confirm', 0.85, 'Known scam pattern for this domain.', 45),
-- Report 7 (Impersonating Bank - OTP)
(UUID_TO_BIN(UUID()), @rpt7, @priya,  'confirm', 1.00, 'This is part of the same phishing campaign as report 6.', 88),
(UUID_TO_BIN(UUID()), @rpt7, @sneha,  'confirm', 0.95, 'My neighbour also received similar call.', 35),
-- Report 12 (Legitmart - archived)
(UUID_TO_BIN(UUID()), (SELECT id FROM fraud_reports WHERE title LIKE 'Suspicious refund%' LIMIT 1), @kunal,  'confirm', 0.70, 'Slow support is suspicious but not conclusive.', 28),
(UUID_TO_BIN(UUID()), (SELECT id FROM fraud_reports WHERE title LIKE 'Suspicious refund%' LIMIT 1), @deepa,  'deny',    0.65, 'I ordered and received my product fine.', 15);

-- ------------------------------------------------------------
-- Report Comments (8 samples)
-- ------------------------------------------------------------
INSERT INTO report_comments (id, report_id, user_id, body, is_deleted) VALUES
(UUID_TO_BIN(UUID()), @rpt1, @rahul,  'I have filed a complaint with cybercrime.gov.in. Anyone else want to file a joint complaint?', FALSE),
(UUID_TO_BIN(UUID()), @rpt1, @ananya, 'SEBI has a helpline at 1800-266-0001 for reporting fake advisors.', FALSE),
(UUID_TO_BIN(UUID()), @rpt3, @amit,   'For everyone seeing this - the real Bank of India website is bankofindia.com. Always check the URL carefully.', FALSE),
(UUID_TO_BIN(UUID()), @rpt3, @sneha,  'My father almost fell for this. These people are very convincing on the phone.', FALSE),
(UUID_TO_BIN(UUID()), @rpt4, @vikram, 'I paid via UPI. Is there any way to get a refund through the bank?', FALSE),
(UUID_TO_BIN(UUID()), @rpt4, @neha,   'File a chargeback with your bank. UPI transactions can be reversed within 3 days.', FALSE),
(UUID_TO_BIN(UUID()), @rpt6, @pooja,  'The prices are too good to be true. iPhones at 80% discount is a clear red flag.', FALSE),
(UUID_TO_BIN(UUID()), @rpt1, @priya,  'Updated: Domain registrar has been notified. Waiting for takedown.', FALSE);

-- ------------------------------------------------------------
-- Report History (8 samples)
-- ------------------------------------------------------------
INSERT INTO report_history (id, report_id, actor_id, action, old_value, new_value) VALUES
(UUID_TO_BIN(UUID()), @rpt1, @priya,  'created', NULL, '{"status":"active","verification_stage":"reported"}'),
(UUID_TO_BIN(UUID()), @rpt1, @arjun,  'status_changed', '{"verification_stage":"reported"}', '{"verification_stage":"multiple_reports"}'),
(UUID_TO_BIN(UUID()), @rpt1, @priya,  'vote_added', NULL, '{"vote_type":"confirm","voter":"rahul"}'),
(UUID_TO_BIN(UUID()), @rpt1, @arjun,  'status_changed', '{"verification_stage":"multiple_reports"}', '{"verification_stage":"community_verified"}'),
(UUID_TO_BIN(UUID()), @rpt3, @amit,   'created', NULL, '{"status":"active","verification_stage":"reported"}'),
(UUID_TO_BIN(UUID()), @rpt3, @arjun,  'status_changed', '{"verification_stage":"reported"}', '{"verification_stage":"community_verified"}'),
(UUID_TO_BIN(UUID()), @rpt4, @vikram, 'created', NULL, '{"status":"active","verification_stage":"reported"}'),
(UUID_TO_BIN(UUID()), @rpt4, @arjun,  'status_changed', '{"verification_stage":"reported"}', '{"verification_stage":"multiple_reports"}');

-- ------------------------------------------------------------
-- Risk Score Breakdowns (8)
-- ------------------------------------------------------------
INSERT INTO risk_score_breakdowns (id, website_url_id, community_sub_score, automated_sub_score, category_severity_avg, final_score, signals) VALUES
(UUID_TO_BIN(UUID()), @w1, 88.00, 95.00, 9.33, 92.50, '{"report_count":3,"evidence_avg":8,"corroboration":true,"domain_age_days":45,"ssl_valid":false,"blacklist":8}'),
(UUID_TO_BIN(UUID()), @w2, 70.00, 78.00, 7.50, 74.20, '{"report_count":2,"evidence_avg":6,"corroboration":true,"domain_age_days":90,"ssl_valid":true,"blacklist":5}'),
(UUID_TO_BIN(UUID()), @w3, 65.00, 78.50, 8.50, 71.80, '{"report_count":2,"evidence_avg":7,"corroboration":true,"domain_age_days":30,"ssl_valid":false,"blacklist":6}'),
(UUID_TO_BIN(UUID()), @w4, 45.00, 52.00, 7.50, 48.50, '{"report_count":2,"evidence_avg":3,"corroboration":false,"domain_age_days":180,"ssl_valid":true,"blacklist":2}'),
(UUID_TO_BIN(UUID()), @w5, 40.00, 44.20, 5.00, 42.10, '{"report_count":1,"evidence_avg":5,"corroboration":false,"domain_age_days":120,"ssl_valid":true,"blacklist":1}'),
(UUID_TO_BIN(UUID()), @w6, 35.00, 42.40, 8.00, 38.70, '{"report_count":1,"evidence_avg":6,"corroboration":false,"domain_age_days":60,"ssl_valid":true,"blacklist":3}'),
(UUID_TO_BIN(UUID()), @w7, 10.00, 20.60, 4.00, 15.30, '{"report_count":1,"evidence_avg":2,"corroboration":false,"domain_age_days":365,"ssl_valid":true,"blacklist":0}'),
(UUID_TO_BIN(UUID()), @w8,  2.00,  2.20, 4.00,  2.10, '{"report_count":1,"evidence_avg":0,"corroboration":false,"domain_age_days":730,"ssl_valid":true,"blacklist":0}');

-- ------------------------------------------------------------
-- Appeals (2 samples)
-- ------------------------------------------------------------
INSERT INTO appeals (id, report_id, appellant_email, domain_owner_verified, status, reason) VALUES
(UUID_TO_BIN(UUID()), @rpt_legit, 'owner@legitmart.com', FALSE, 'pending', 'We are a legitimate business. The refund policy complaint is being addressed. Please remove the listing.'),
(UUID_TO_BIN(UUID()), @rpt8, 'admin@knowngood.in', FALSE, 'overturned', 'This report was submitted in error by the reporter. The reporter themselves has stated this is a legitimate site.');

-- ------------------------------------------------------------
-- Reputation Events (8 samples)
-- ------------------------------------------------------------
INSERT INTO reputation_events (id, user_id, delta, reason) VALUES
(UUID_TO_BIN(UUID()), @priya,  15, 'report_confirmed'),
(UUID_TO_BIN(UUID()), @rahul,  10, 'vote_accurate'),
(UUID_TO_BIN(UUID()), @ananya, 10, 'vote_accurate'),
(UUID_TO_BIN(UUID()), @amit,   12, 'report_confirmed'),
(UUID_TO_BIN(UUID()), @vikram,  8, 'vote_accurate'),
(UUID_TO_BIN(UUID()), @neha,   10, 'report_confirmed'),
(UUID_TO_BIN(UUID()), @kunal, -5,  'vote_inaccurate'),
(UUID_TO_BIN(UUID()), @ritu,  -10, 'report_denied');

-- ------------------------------------------------------------
-- Discussion Threads (3 samples)
-- ------------------------------------------------------------
SET @disc1 = (SELECT id FROM website_urls WHERE domain = 'investquick.xyz');
SET @disc2 = (SELECT id FROM website_urls WHERE domain = 'bankofindia-secure.xyz');

INSERT INTO website_discussions (id, website_url_id, author_id, title, body, is_pinned, upvotes, downvotes, reply_count) VALUES
(UUID_TO_BIN(UUID()), @disc1, @priya,  'InvestQuick - How to recover your money?',
  'I lost 50000 INR to this platform. Has anyone successfully recovered their money? I am thinking of filing a police complaint. Please share your experiences.', TRUE, 12, 1, 3),
(UUID_TO_BIN(UUID()), @disc1, @rahul,  'Warning: New phone numbers being used',
  'They are now calling from +91-9876543210 pretending to be investment advisors. Please do not trust these calls.', FALSE, 8, 0, 1),
(UUID_TO_BIN(UUID()), @disc2, @amit,   'How to report phishing to TRAI',
  'Besides reporting here, you can forward phishing SMS to 1909 (TRAI) and report the number for blocking.', FALSE, 15, 0, 2);

-- ------------------------------------------------------------
-- Discussion Replies (5 samples)
-- ------------------------------------------------------------
SET @d1 = (SELECT id FROM website_discussions WHERE title LIKE 'InvestQuick - How%' LIMIT 1);
SET @d2 = (SELECT id FROM website_discussions WHERE title LIKE 'Warning: New%' LIMIT 1);
SET @d3 = (SELECT id FROM website_discussions WHERE title LIKE 'How to report phishing%' LIMIT 1);

INSERT INTO discussion_replies (id, discussion_id, author_id, parent_id, body, upvotes, downvotes, depth) VALUES
(UUID_TO_BIN(UUID()), @d1, @rahul,  NULL, 'I filed a complaint on cybercrime.gov.in. Got an acknowledgment number. Not sure about recovery yet.', 5, 0, 0),
(UUID_TO_BIN(UUID()), @d1, @ananya, NULL, 'Bank chargeback is the fastest way. UPI transactions can be reversed if reported within 3 days.', 3, 0, 0),
(UUID_TO_BIN(UUID()), @d1, @vikram, NULL, 'Also report on NCRP (National Cyber Crime Reporting Portal). They have a dedicated helpline at 1930.', 4, 0, 0),
(UUID_TO_BIN(UUID()), @d2, @neha,   NULL, 'Same number called me too! They asked for my Aadhaar number. I hung up immediately.', 2, 0, 0),
(UUID_TO_BIN(UUID()), @d3, @sneha,  NULL, 'You can also report on the DoNotCall registry at 1909 to block telemarketing calls.', 3, 0, 0);

-- ------------------------------------------------------------
-- Discussion Votes (6 samples)
-- ------------------------------------------------------------
INSERT INTO discussion_votes (id, user_id, target_type, target_id, vote_value) VALUES
(UUID_TO_BIN(UUID()), @rahul,  'discussion', @d1, 1),
(UUID_TO_BIN(UUID()), @ananya, 'discussion', @d1, 1),
(UUID_TO_BIN(UUID()), @amit,   'discussion', @d3, 1),
(UUID_TO_BIN(UUID()), @sneha,  'reply',      (SELECT id FROM discussion_replies WHERE body LIKE 'I filed a complaint%' LIMIT 1), 1),
(UUID_TO_BIN(UUID()), @neha,   'reply',      (SELECT id FROM discussion_replies WHERE body LIKE 'Same number called%' LIMIT 1), 1),
(UUID_TO_BIN(UUID()), @vikram, 'discussion', @d2, 1);

-- ------------------------------------------------------------
-- Platform Config
-- ------------------------------------------------------------
INSERT INTO platform_config (`key`, value, description) VALUES
('rate_limit.new_user_reports_per_hour', '5', 'Rate limit for new users submitting reports'),
('rate_limit.established_reports_per_hour', '20', 'Rate limit for established users'),
('rate_limit.votes_per_hour', '20', 'Rate limit for vote actions'),
('rate_limit.appeals_per_day', '3', 'Rate limit for appeal submissions'),
('reputation.min_vote_threshold', '0.6', 'Minimum reputation required to cast a verification vote'),
('verification.auto_advance_reports', '2', 'Independent reports needed to auto-advance to multiple_reports stage'),
('verification.auto_advance_votes', '5', 'Confirm votes needed to auto-advance to community_verified stage'),
('verification.confirm_malicious_requires_admin', 'true', 'Admin/moderator required for confirmed_malicious stage');
