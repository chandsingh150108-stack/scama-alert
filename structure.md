# ScamAlert — Repository Structure

> DBMS course project. Community-driven platform for marking fraudulent websites (Indian users; 1930 helpline, NCRP, cybercrime.gov.in). Local dev only.
> Focus: two-axis risk scoring (**Technical Risk x Fraud Risk**) — differentiating "technically malicious" from "community-reported fraud."
> Stack: **Flask 3 + MySQL 8.4 (raw SQL, frozen `sql/`) + vanilla HTML/CSS/JS + pytest.** (Migrated from Next.js/TS; the old `src/` tree is gone.)

---

## Root files

| File | Purpose |
|---|---|
| `AGENTS.md` | Project conventions, DB summary, commands, gotchas. |
| `README.md` | Setup, config, behavior notes. |
| `requirements.txt` | Flask, mysql-connector-python, bcrypt, Flask-Session, python-docx, python-whois, dnspython, filetype, pytest, pytest-mock. |
| `Dockerfile` | `python:3.11-slim`, copies backend/frontend/scripts/sql, serves Flask on 5000. |
| `docker-compose.yml` | `mysql:8.4` (host 3307 → 3306) + `web` Flask (5000); volumes `scamalert_mysql_data`, `scamalert_uploads`. |
| `.env.example` | Template: `DATABASE_URL` (port 3307), `FLASK_SECRET`, `APP_URL`. |
| `.env` | **Present** (secrets committed). Denied by `opencode.json` policy — refer to `.env.example`, do not read. |
| `opencode.json` | Agent permissions; `.env` access denied. |
| `skills-lock.json` | Locks `agent-browser` skill. |
| `.gitignore` | Python artifacts, `.env*` (except example), `uploads/`, logs, editor files. |
| `futuretodo.md` | Remaining gaps against the Flask build. |
| `er-diagram.md` / `.mmd` / `.svg` | ER diagram (Mermaid source + rendered SVG) for the frozen schema. |

---

## `sql/` — all DB objects (ordered 01 → 09; see `sql_saves/` for the pre-cleanup backup)

| File | Contents |
|---|---|
| `01_schema.sql` | 20 tables, all 3NF. Core: `users`, `categories`, `website_urls`, `fraud_reports`, `report_evidence`, `verification_votes`; support: `tags`, `report_tags`, `report_comments`, `report_history`, `risk_score_breakdowns`, `appeals`, `appeal_evidence`, `reputation_events`, `rate_limit_events`, `audit_events`, `platform_config`; forum: `website_discussions`, `discussion_replies`, `discussion_votes`. UUIDs as `BINARY(16)` (`UUID_TO_BIN()`), CHECK constraints on numeric bounds, FULLTEXT on `fraud_reports(title, description)`, indexes. |
| `02_seed_data.sql` | 10 categories, 15 users (+ `Anonymous` sentinel `00000000-...-000000000001`), 8 websites, ~13 reports, evidence, votes, tags. |
| `03_views.sql` | 5 views (all read by the app): `v_report_full_details`, `v_website_risk_dashboard`, `v_user_reputation_leaderboard`, `v_pending_review_queue`, `v_appeal_resolution_tracker`. |
| `04_functions.sql` | 5 functions: `fn_calculate_risk_score`, `fn_get_reputation_tier` (90 moderator / 70 expert / 40 trusted / 20 new / else newcomer), `fn_normalize_url`, `fn_check_rate_limit` (report_new 5, 20 if rep >= 40), `fn_determine_verification_stage`. |
| `05_triggers.sql` | 7 triggers, incl. `trg_after_report_insert` (website/user counters + history), `trg_prevent_vote_manipulation` (voter rep >= 60, 20/day cap; one-vote-per-report via UNIQUE key). |
| `06_procedures.sql` | 5 procedures: `sp_submit_fraud_report` (own rate check + event insert), `sp_process_verification_vote`, `sp_recalculate_all_risk_scores`, `sp_resolve_appeal`, `sp_update_reputation`. |
| `07_acid_demo.sql` | ACID demonstration queries. |
| `08_complex_joins.sql` | JOIN showcase queries. |
| `09_cleanup.sql` | Drop everything in reverse FK order. |

> Risk formula (in `fn_calculate_risk_score`): `Final = (Community × 0.40) + (Automated × 0.40) + (Category Severity × 0.20)`, each 0–100. Mirrored in `backend/risk/calculator.py`.

---

## `scripts/`

| File | Purpose |
|---|---|
| `db_setup.py` | Applies `sql/01`–`06` in order (DELIMITER-aware splitter), aborts on 01/02 failure, verifies tables/views/procedures/functions/triggers/counts. Port 3307. |
| `seed_demo_posts.py` | Wipes posts + inserts 5 demo reports (votes/comments) with screenshots from `seed_images/` (copied into the `web` container via `docker cp`); registers evidence with real sha256/size. |

---

## `backend/` — Flask app (factory in `app.py`: `/api/*` + static + `/uploads/*`)

| File | Purpose |
|---|---|
| `app.py` | `create_app()`; safe JSON provider (BINARY-UUID/Decimal/datetime); `{error}` handlers; `/admin*` page gate → `/login?callbackUrl=`; 16 static page routes; `/uploads/<path>` file serving. |
| `config.py` | `DATABASE_URL` (3307 default), secret, upload dir, 7-day session lifetime; URL parser. |
| `db.py` | Pooled driver; `query()` / `query_one()` dict helpers (`%s` only); `call_procedure_first_row()`; `to_json()`; `parse_int()` (no clamp). |
| `auth.py` | bcrypt cost-12 `hash_password` / `verify_password`, user lookup/creation. |
| `auth_guard.py` | `current_user()`, `anonymous_id()` sentinel, `require_role()`, `owner_or_roles()`; 401/403 mapping. |
| `rate_limit.py` | `check_rate_limit(user_id, action, ip?, record?)` vs `rate_limit_events`, `platform_config` override; never raises. |
| `audit.py` | `log_audit_event()` (actor nullable, never throws). |
| `email.py` | `send_notification()` log stub + template builders (report/vote/comment/appeal). |
| `utils.py` | `error_response()`, `parse_int`. |
| `complaint.py` | `generate_complaint()` — cybercrime DOCX (1930/NCRP/CERT-In, IT Act 66C/66D/43). |
| `risk/calculator.py` | `calculate_risk_score()` mirror of TS + SQL fn (weights/thresholds verbatim). |
| `risk/stages.py` | `determine_stage_transition()` / `apply_stage_transition()` (2 reporters, 5 confirms / 2+2, deny-ratio regression, admin-only `confirmed_malicious`). |
| `intelligence/tld.py` | TLD reputation map (compound `.gov.in`/`.edu.in` first; unknown → safe). |
| `intelligence/dns.py` / `ssl.py` / `whois.py` | DMARC/SPF/MX (dnspython), cert inspection (10s timeout), WHOIS + 24h cache (python-whois). All fail-closed to safe defaults. |
| `evidence/handler.py` | `EVIDENCE_TYPES` weights, 10 MB cap, 11-MIME allowlist, SHA-256, `store_evidence()` → `/uploads/evidence/<reportId>/<uuid>.<ext>`, traversal guard. |

### `backend/routes/` — 14 blueprints, 52 rules

| Module | Endpoints |
|---|---|
| `auth_routes.py` | `POST /api/auth/signup|login|logout`, `GET /api/me` (anon: exact `401 {user:null}`) |
| `reports.py` | `GET /api/reports` (category/status filter, pagination), `POST /api/reports` (login required; category pre-check 400; check-only rate limit; proc SIGNAL → 400/429 mapping) |
| `report_detail.py` | `GET /api/reports/<id>` (report+evidence+votes+comments+tags), `PUT` (owner or admin/moderator), `DELETE` (admin → `status='archived'`) |
| `vote.py` | `POST .../vote` (login; enum 400; `sp_process_verification_vote`) |
| `comment.py` | `POST .../comment` (guests → sentinel `Anonymous`; IP-scoped rate limit) |
| `history.py` | `GET .../history` |
| `complaint_route.py` | `GET .../complaint` (DOCX download) |
| `search.py` | `GET /api/search` (FULLTEXT + LIKE merge, dedup by id) |
| `users.py` / `websites.py` | Leaderboard, profile (+reports+events), website risk dashboard |
| `evidence.py` | `GET /api/evidence`, `POST /api/evidence/upload` (login; validation 400) |
| `appeals.py` | List + appeal evidence |
| `discussions.py` | List/create, replies, votes |
| `admin.py` | Reports queue + bulk status, appeals resolve, config GET/PUT, recalculate-risk |

### `backend/tests/` — pytest (58 passed, 3 skipped)

| File | Coverage |
|---|---|
| `test_tld.py` (26) / `test_calculator.py` (14) / `test_stages.py` (12) / `test_handler.py` / `test_complaint.py` | Service unit tests (mocked I/O, tmp dirs) |
| `test_api.py` | Mocked-DB route tests: health, `me` 401 contract, search 400 + merge, reports validation/401/category-400/proc-429, vote 401/enum/429, comment 400 + anon 201, admin 401/403, upload 401/400, signup validation, PUT 401-before-400 |
| `test_sql_integration.py` | Live-MySQL checks (tier boundaries, normalize, domain age); skips unless `SCAMALERT_TEST_DB=1` |

---

## `frontend/` — vanilla pages served by Flask (fetch, no bundler)

| Page | JS | Purpose |
|---|---|---|
| `index.html` | `app.js`, `auth.js`, `theme.js`, `dashboard.js` | Recent reports, categories, top reporters |
| `reports.html` | `reports.js` | List + category/status filters + pagination |
| `report-new.html` | `report-new.js` | Submit form (login required; file picker with 10 MB/MIME pre-check; per-file upload after create) |
| `report-detail.html` | `report-detail.js` | Detail + vote buttons (login modal for guests) + evidence links/thumbnails + history toggle + comments (guest-friendly) |
| `search.html` | `search.js` | Query page (`?q=`) |
| `users.html` / `user-detail.html` | `users.js` / `user-detail.js` | Leaderboard / profile |
| `website-detail.html` | `website.js` | Risk dashboard |
| `discussions.html` / `discussion-detail.html` | `discussions.js` / `discussion-detail.js` | Forum list / thread |
| `login.html` / `signup.html` | `auth.js` | Auth modal + session menu |
| `help.html` | — | 1930 / NCRP / CERT-In resources |
| `admin-reports.html` / `admin-appeals.html` / `admin-config.html` | `admin-*.js` | Moderation queue, appeal resolution, config editor |
| `css/style.css` + `js/theme.js` + `js/app.js` | shared | Styles, light/dark theme, `App.api` fetch wrapper + `reportCard`/`escapeHtml` helpers |
