# Comment Upvote/Downvote Implementation Plan

## Database Schema Changes
- [x] Add `upvotes` and `downvotes` columns to `report_comments` table in `sql/01_schema.sql`
- [x] Create `comment_votes` table in `sql/01_schema.sql`

## Triggers (sql/05_triggers.sql)
- [x] Create `trg_comment_vote_integrity` BEFORE INSERT trigger for permission checks
- [x] Create `trg_after_comment_vote` AFTER INSERT trigger for count updates and reputation rewards

## Backend Routes
- [x] Create `backend/routes/comment_vote.py` with POST /api/reports/<rid>/comments/<cid>/vote
- [x] Register comment_vote blueprint in `backend/app.py`
- [x] Update `backend/routes/report_detail.py` to include `user_vote` in comment query

## Frontend
- [x] Update `frontend/js/report-detail.js` to add vote UI and handlers
- [x] Update `frontend/css/style.css` for vote button styles

## Testing
- [x] Create `backend/tests/test_comment_vote.py` for unit tests

## Verification
- [x] Run database setup to apply schema changes
- [x] Run pytest to verify tests pass (12 new tests pass, all existing tests pass except pre-existing enrich failure)
- [x] Verify no lint/typecheck errors

---

# Performance Fixes (Website Slowness)

## Root Causes Identified
1. **Port/Connection Mismatch**: `.env` used root@localhost:3306 vs docker-compose's scamalert_user@localhost:3308
2. **Missing Indexes**: No index on `comment_votes(user_id, created_at)` for daily limit check; no index on `report_comments(report_id, created_at)` for ordered comments
3. **Correlated Subqueries in View**: `v_report_full_details` used per-row subqueries for tags/evidence_count
4. **Small Connection Pool**: Pool size = 5

## Fixes Applied
- [x] Fixed `.env` to use correct port (3308) and user (scamalert_user)
- [x] Added index `idx_comment_votes_user_created` on `comment_votes(user_id, created_at)` for trigger's daily limit COUNT(*)
- [x] Added index `idx_comment_votes_comment` on `comment_votes(comment_id)` for vote aggregations
- [x] Added index `idx_report_comments_report_created` on `report_comments(report_id, created_at)` for ordered comment queries
- [x] Updated `sql/01_schema.sql` to document these indexes
- [x] Optimized `v_report_full_details` view: replaced correlated subqueries with LEFT JOIN + GROUP BY (single scan per aggregation table)
- [x] Increased connection pool size from 5 to 20 in `backend/db.py`
- [x] Rebuilt Docker container and verified all 91 tests pass