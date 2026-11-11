"""Tests for comment vote API (mocked DB)."""
import pytest
from unittest.mock import patch


def test_vote_requires_auth(client):
    """Anonymous users cannot vote."""
    resp = client.post("/api/reports/aaa/comments/bbb/vote",
                       json={"vote_value": 1})
    assert resp.status_code == 401


def test_vote_invalid_vote_value(client, monkeypatch):
    """vote_value must be -1 or 1."""
    import backend.auth_guard as g
    monkeypatch.setattr(g, "current_user", lambda: {"id": "u1", "email": "a@b.c", "name": "A", "role": "user"})

    for val in [0, 2, -2, "up", None]:
        resp = client.post("/api/reports/aaa/comments/bbb/vote",
                           json={"vote_value": val})
        assert resp.status_code == 400
        assert "vote_value" in resp.get_json()["error"].lower()


def test_vote_missing_field(client, monkeypatch):
    """Missing vote_value returns 400."""
    import backend.auth_guard as g
    monkeypatch.setattr(g, "current_user", lambda: {"id": "u1", "email": "a@b.c", "name": "A", "role": "user"})

    resp = client.post("/api/reports/aaa/comments/bbb/vote", json={})
    assert resp.status_code == 400


def test_vote_comment_not_found(client, monkeypatch):
    """Non-existent comment returns 404."""
    import backend.auth_guard as g
    import backend.routes.comment_vote as cv
    monkeypatch.setattr(g, "current_user", lambda: {"id": "u1", "email": "a@b.c", "name": "A", "role": "user"})
    monkeypatch.setattr(cv.db, "query_one", lambda *a, **k: None)

    resp = client.post("/api/reports/aaa/comments/bbb/vote",
                       json={"vote_value": 1})
    assert resp.status_code == 404


def test_vote_insufficient_reputation(client, monkeypatch):
    """Users with reputation < 40 cannot vote (trigger error mapped to 403)."""
    import backend.auth_guard as g
    import backend.routes.comment_vote as cv
    monkeypatch.setattr(g, "current_user", lambda: {"id": "u1", "email": "a@b.c", "name": "A", "role": "user"})
    monkeypatch.setattr(cv.db, "query_one", lambda *a, **k: {"id": "comment-id"})
    monkeypatch.setattr(cv.db, "query", lambda *a, **k: (_ for _ in ()).throw(
        Exception("Insufficient reputation to vote on comments (minimum tier: trusted, score: 40)")
    ))

    resp = client.post("/api/reports/aaa/comments/bbb/vote",
                       json={"vote_value": 1})
    assert resp.status_code == 403


def test_vote_daily_limit(client, monkeypatch):
    """Daily vote limit returns 429."""
    import backend.auth_guard as g
    import backend.routes.comment_vote as cv
    monkeypatch.setattr(g, "current_user", lambda: {"id": "u1", "email": "a@b.c", "name": "A", "role": "user"})
    monkeypatch.setattr(cv.db, "query_one", lambda *a, **k: {"id": "comment-id"})
    monkeypatch.setattr(cv.db, "query", lambda *a, **k: (_ for _ in ()).throw(
        Exception("Daily vote limit reached (50 votes per day)")
    ))

    resp = client.post("/api/reports/aaa/comments/bbb/vote",
                       json={"vote_value": 1})
    assert resp.status_code == 429


def test_vote_upvote_success(client, monkeypatch):
    """Successful upvote returns counts and user_vote."""
    import backend.auth_guard as g
    import backend.routes.comment_vote as cv
    monkeypatch.setattr(g, "current_user", lambda: {"id": "u1", "email": "a@b.c", "name": "A", "role": "user"})

    calls = {"n": 0}
    def fake_query_one(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"id": "comment-id"}
        return {"up": 5, "down": 2}

    monkeypatch.setattr(cv.db, "query_one", fake_query_one)
    monkeypatch.setattr(cv.db, "query", lambda *a, **k: None)

    resp = client.post("/api/reports/aaa/comments/bbb/vote",
                       json={"vote_value": 1})

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert data["upvotes"] == 5
    assert data["downvotes"] == 2
    assert data["user_vote"] == 1


def test_vote_downvote_success(client, monkeypatch):
    """Successful downvote returns counts and user_vote."""
    import backend.auth_guard as g
    import backend.routes.comment_vote as cv
    monkeypatch.setattr(g, "current_user", lambda: {"id": "u1", "email": "a@b.c", "name": "A", "role": "user"})

    calls = {"n": 0}
    def fake_query_one(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"id": "comment-id"}
        return {"up": 3, "down": 4}

    monkeypatch.setattr(cv.db, "query_one", fake_query_one)
    monkeypatch.setattr(cv.db, "query", lambda *a, **k: None)

    resp = client.post("/api/reports/aaa/comments/bbb/vote",
                       json={"vote_value": -1})

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert data["upvotes"] == 3
    assert data["downvotes"] == 4
    assert data["user_vote"] == -1


def test_vote_change_vote(client, monkeypatch):
    """Changing vote (upvote -> downvote) updates correctly."""
    import backend.auth_guard as g
    import backend.routes.comment_vote as cv
    monkeypatch.setattr(g, "current_user", lambda: {"id": "u1", "email": "a@b.c", "name": "A", "role": "user"})

    calls = {"n": 0}
    def fake_query_one(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"id": "comment-id"}
        return {"up": 2, "down": 3}

    monkeypatch.setattr(cv.db, "query_one", fake_query_one)
    monkeypatch.setattr(cv.db, "query", lambda *a, **k: None)

    resp = client.post("/api/reports/aaa/comments/bbb/vote",
                       json={"vote_value": -1})

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["user_vote"] == -1


def test_rate_limit_enforced(client, monkeypatch):
    """Rate limit returns 429."""
    import backend.auth_guard as g
    import backend.routes.comment_vote as cv
    monkeypatch.setattr(g, "current_user", lambda: {"id": "u1", "email": "a@b.c", "name": "A", "role": "user"})
    monkeypatch.setattr(cv.db, "query_one", lambda *a, **k: {"id": "comment-id"})
    monkeypatch.setattr(cv.rate_limit, "check_rate_limit",
                        lambda *a, **k: {"allowed": False, "remaining": 0})

    resp = client.post("/api/reports/aaa/comments/bbb/vote",
                       json={"vote_value": 1})
    assert resp.status_code == 429


def test_report_detail_includes_user_vote_anonymous(client, monkeypatch):
    """Anonymous users get user_vote = 0 in comments."""
    import backend.routes.report_detail as rd
    monkeypatch.setattr(rd.auth_guard, "current_user", lambda: None)
    monkeypatch.setattr(rd.db, "query_one", lambda *a, **k: {
        "id": "report-id", "title": "Test", "description": "Desc",
        "is_anonymous": False, "status": "active", "verification_stage": "reported",
        "reporter_id": "r1", "reporter_name": "Reporter", "reporter_tier": "newcomer",
        "category_name": "Phishing", "category_slug": "phishing",
        "website_url_id": "w1", "domain": "example.com", "website_risk_level": "safe"
    })
    monkeypatch.setattr(rd.db, "query", lambda *a, **k: [
        {"id": "c1", "body": "Comment", "user_name": "User", "user_tier": "newcomer", "user_vote": 0}
    ])

    resp = client.get("/api/reports/report-id")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "comments" in data


def test_report_detail_includes_user_vote_authenticated(client, monkeypatch):
    """Authenticated users get their vote_value in user_vote."""
    import backend.auth_guard as g
    import backend.routes.report_detail as rd
    monkeypatch.setattr(g, "current_user", lambda: {"id": "u1", "email": "a@b.c", "name": "A", "role": "user"})
    monkeypatch.setattr(rd.auth_guard, "current_user", lambda: {"id": "u1", "email": "a@b.c", "name": "A", "role": "user"})
    monkeypatch.setattr(rd.db, "query_one", lambda *a, **k: {
        "id": "report-id", "title": "Test", "description": "Desc",
        "is_anonymous": False, "status": "active", "verification_stage": "reported",
        "reporter_id": "r1", "reporter_name": "Reporter", "reporter_tier": "newcomer",
        "category_name": "Phishing", "category_slug": "phishing",
        "website_url_id": "w1", "domain": "example.com", "website_risk_level": "safe"
    })
    monkeypatch.setattr(rd.db, "query", lambda *a, **k: [
        {"id": "c1", "body": "Comment", "user_name": "User", "user_tier": "newcomer", "user_vote": 1}
    ])

    resp = client.get("/api/reports/report-id")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "comments" in data