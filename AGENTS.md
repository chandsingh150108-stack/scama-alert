# AGENTS.md — ScamAlert

> DBMS course project. Community-driven platform for marking fraudulent websites. Indian users (1930 helpline, NCRP, cybercrime.gov.in). Local dev only.

**Two-axis risk scoring (Technical Risk x Fraud Risk)** -- differentiates "technically malicious" from "community-reported fraud."

Migration from Next.js/TS is **complete**. The `src/` tree is gone; do not reference it.

---

## Tech Stack

Flask 3 (Python, App Router-style blueprints) | MySQL 8.4 | Raw SQL (`mysql-connector-python`, no ORM) | Server sessions + bcrypt | Vanilla HTML/CSS/JS served by Flask | pytest

**Docker:** `mysql:8.4` on host port `3307` (+ `web` Flask service on `5000`). DB: `scamalert`.
**DATABASE_URL:** `mysql://scamalert_user:scamalert_pass@localhost:3307/scamalert`

---

## Database (20 tables, 20+ objects)

`sql/` is immutable, except the approved cleanup in `sql_saves/`-backed thinning (unused views/proc/function removed; counts below are current). Python adapts to the DB, never the reverse. All tables 3NF. UUIDs as `BINARY(16)` via `UUID_TO_BIN()`. CHECK constraints on all numeric bounds.

**Core:** users, categories, website_urls, fraud_reports, report_evidence, verification_votes
**Support:** tags, report_tags, report_comments, report_history, risk_score_breakdowns, appeals, appeal_evidence, reputation_events, rate_limit_events, audit_events, platform_config
**Forum:** website_discussions, discussion_replies, discussion_votes

**Objects:** 5 views (multi-table JOINs), 5 functions, 7 triggers, 5 procedures

---

## Conventions

- SQL in `sql/` files only, never schema changes; queries use `%s` placeholders (never f-string interpolation)
- UUIDs: `BINARY(16)` with `UUID_TO_BIN(%s)` filters / `BIN_TO_UUID(col) AS alias` selects (see `backend/db.py`)
- JSON columns via `CAST(%s AS JSON)` + `db.to_json()`
- ENUMs for stable values, JSON for flexible data
- FULLTEXT on `fraud_reports(title, description)`; search merges FULLTEXT hits with title/description/domain LIKE matches (dedup by id) — never fallback-only
- Soft deletes only, never hard delete (admin report delete = `status='archived'`)
- Error envelope `{error: message}`; `GET /api/me` anon contract is exactly `401 {user: null}`
- Rate limits: Flask checks, procedures record. `check_rate_limit(..., record=False)` on paths where the proc inserts its own event (report submit), otherwise one success would cost 2 tokens
- Auth model: reports + votes require login; comments allow guests (stored under sentinel `00000000-0000-0000-0000-000000000001`, displayed as "Anonymous")
- Category slugs in `frontend/report-new.html` must match `categories.slug` exactly (else proc throws `Invalid category slug`)

---

## Commands

```bash
docker compose up -d --build web   # MySQL + Flask (rebuild after backend/frontend edits; no bind mounts)
pip install -r requirements.txt
python scripts/db_setup.py         # Tables + seed from frozen sql/01-06, then verification counts
python -m flask --app backend.app run --host 0.0.0.0 --port 5000
python -m pytest backend/tests -q  # pytest, 58 passed + 3 skipped (DB tests need SCAMALERT_TEST_DB=1)
```

---

## Testing

pytest. Config: none (convention + `backend/tests/conftest.py` app/client fixtures). Tests in `backend/tests/`.
- `test_tld.py` (26 TLD cases), `test_calculator.py` (14), `test_stages.py` (12), `test_handler.py` (evidence), `test_complaint.py` (DOCX)
- `test_api.py` (mocked-DB route tests: auth matrix, validation order, search merge, upload codes)
- `test_sql_integration.py` (auto-skips unless `SCAMALERT_TEST_DB=1` with live MySQL)

---

## File Structure

```
sql/           # 01_schema through 09_cleanup (FROZEN)
scripts/       # db_setup.py (bootstrap from frozen SQL)
backend/       # app.py (factory, /api/* + static + /uploads), config.py, db.py,
               # auth.py, auth_guard.py, rate_limit.py, audit.py, email.py,
               # utils.py, complaint.py, risk/, intelligence/, evidence/, routes/
frontend/      # *.html + css/style.css + js/*.js (vanilla, fetch, no bundler)
```

---

## Key Gotchas

- `.env` has secrets committed (root password, auth secret)
- `web` container has no bind mounts: `docker compose up -d --build web` after any `backend/`/`frontend/` edit
- Uploads live under `<cwd>/uploads`, served at `/uploads/*`, persisted in `scamalert_uploads` volume; missing files return JSON 404 (not the SPA fallback)
- Vote trigger `trg_prevent_vote_manipulation` requires voter reputation >= 60 — most users (and all guests) cannot vote by schema design; keep votes login-only
- Proc SIGNAL texts are mapped to HTTP codes in routes (`Invalid category slug` → 400, `Rate limit exceeded` → 429); never let them fall through as 500
- Flask `permanent_session_lifetime` = 7 days, mirroring the old Better Auth session length

---

## Risk Score Formula

`Final = (Community x 0.40) + (Automated x 0.40) + (Category Severity x 0.20)` -- each 0-100. Implemented in `fn_calculate_risk_score()`; mirrored in `backend/risk/calculator.py`.
