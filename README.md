# ScamAlert — Flask + Vanilla JS (migrated from Next.js/TS)

Community-driven platform for marking fraudulent websites (Indian users: 1930 helpline, NCRP, CERT-In).
Two-axis risk scoring (Technical Risk x Fraud Risk). Migrated from Next.js/TS to Flask (migration complete; old `src/` tree removed).

## Stack

Flask 3 (Python) | MySQL 8.4 (raw SQL via `mysql-connector-python`, frozen `sql/`) | Vanilla HTML/CSS/JS served by Flask | pytest

## Quick start (local dev only)

```bash
docker compose up -d --build web   # MySQL on 3307 + Flask on 5000
pip install -r requirements.txt
python scripts/db_setup.py         # applies sql/01-06 + verification counts
python -m flask --app backend.app run --host 0.0.0.0 --port 5000
```

> The `web` container has no bind mounts: rebuild it after any `backend/`/`frontend/` edit.

Open `http://localhost:5000/` (dashboard). API at `/api/*` (52 routes; see `structure.md`).

## Config (env)

| Key | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `mysql://scamalert_user:scamalert_pass@localhost:3307/scamalert` | MySQL (port 3307 = compose) |
| `FLASK_SECRET` (or `BETTER_AUTH_SECRET`) | `change-me-to-a-random-secret` | Session signing |
| `APP_URL` | `http://localhost:5000` | Base URL |

Uploads persist in the `scamalert_uploads` volume (container path `/app/uploads`, served at `/uploads/*`).

## Tests

```bash
python -m pytest backend/tests -q        # 58 passed, 3 skipped
SCAMALERT_TEST_DB=1 python -m pytest backend/tests -q   # + live-MySQL integration tests
```

## Layout

* `backend/` — Flask app factory, 14 route blueprints, services (auth, rate limit, audit, email stub, risk, intelligence, evidence, complaint DOCX)
* `frontend/` — 16 static pages + `css/style.css` + per-page `js/*.js` (fetch, no bundler)
* `sql/` — FROZEN, do not edit
* `scripts/db_setup.py` — bootstrap from frozen SQL

## Behavior notes

* Auth: server sessions + bcrypt (7-day cookie). Reports and votes require login; comments allow guests (shown as "Anonymous"). Logged-in reporters may tick "Submit anonymously".
* Search merges FULLTEXT matches with title/description/domain LIKE matches (deduplicated) — domain-only hits are never dropped.
* Evidence: 10 MB cap, 11-type allowlist; validation failures are 400. Files viewable at their `/uploads/...` URLs with image thumbnails on the report page.
* Rate limits (per hour, overridable via `platform_config`): reports 5, votes 20, comments 30, discussions 10. Flask checks, procedures record — one success costs one token; failed attempts cost nothing.
* Category slugs in the report form must match `categories.slug` exactly.
* Complaint download is DOCX (`GET /api/reports/<id>/complaint`) despite historic "PDF" naming.
* Voting additionally requires reputation >= 60 (enforced by DB trigger) — new accounts cannot vote yet.
