"""API route tests with mocked DB (mirror route.test.ts files) + auth + admin matrix."""
import io


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.get_json() == {"status": "ok"}


def test_me_401(client):
    r = client.get("/api/me")
    assert r.status_code == 401 and r.get_json() == {"user": None}


def test_search_400(client):
    assert client.get("/api/search").status_code == 400
    assert client.get("/api/search?q=%20%20").status_code == 400


def test_search_ok(monkeypatch, client):
    import backend.routes.search as s
    monkeypatch.setattr(s.db, "query", lambda *a, **k: [{"id": "r1", "title": "t"}])
    r = client.get("/api/search?q=bank")
    assert r.status_code == 200 and r.get_json()["count"] == 1


def test_search_merges_domain_matches(monkeypatch, client):
    """FULLTEXT hits + domain-only LIKE hits are merged, deduped by id."""
    import backend.routes.search as s
    calls = {"n": 0}

    def fake_query(sql, params=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return [{"id": "r1", "title": "Bank OTP scam"}]
        return [{"id": "r1", "title": "Bank OTP scam"},
                {"id": "r2", "title": "Unrelated", "domain": "bankofindia-secure.xyz"}]

    monkeypatch.setattr(s.db, "query", fake_query)
    r = client.get("/api/search?q=bankofindia-secure.xyz")
    body = r.get_json()
    assert r.status_code == 200
    assert body["count"] == 2
    assert {x["id"] for x in body["results"]} == {"r1", "r2"}


def test_reports_post_validation(client):
    r = client.post("/api/reports", json={"url": "https://x.example"})
    assert r.status_code == 400


def test_reports_post_requires_login(client, monkeypatch):
    import backend.routes.reports as rep
    monkeypatch.setattr(rep.db, "query_one", lambda *a, **k: {"id": "c1"})
    r = client.post("/api/reports", json={
        "url": "https://x.example", "category_slug": "phishing",
        "title": "t", "description": "d"})
    assert r.status_code == 401


def test_reports_post_bad_category_400(client, monkeypatch):
    import backend.auth_guard as g
    import backend.routes.reports as rep
    monkeypatch.setattr(g, "current_user", lambda: {"id": "u1", "email": "a@b.c", "name": "A", "role": "user"})
    monkeypatch.setattr(rep.db, "query_one", lambda *a, **k: None)
    r = client.post("/api/reports", json={
        "url": "https://x.example", "category_slug": "nope",
        "title": "t", "description": "d"})
    assert r.status_code == 400


def test_reports_post_proc_rate_429(client, monkeypatch):
    import backend.auth_guard as g
    import backend.routes.reports as rep
    monkeypatch.setattr(g, "current_user", lambda: {"id": "u1", "email": "a@b.c", "name": "A", "role": "user"})
    monkeypatch.setattr(rep.db, "query_one", lambda *a, **k: {"id": "c1"})
    monkeypatch.setattr(rep.rate_limit, "check_rate_limit", lambda *a, **k: {"allowed": True, "remaining": 1})

    def boom(*a, **k):
        raise Exception("1644 (45000): Rate limit exceeded. Please try again later.")

    monkeypatch.setattr(rep.db, "call_procedure_first_row", boom)
    r = client.post("/api/reports", json={
        "url": "https://x.example", "category_slug": "phishing",
        "title": "t", "description": "d"})
    assert r.status_code == 429


def test_reports_get_pagination(monkeypatch, client):
    import backend.routes.reports as rep
    monkeypatch.setattr(rep.db, "query", lambda *a, **k: [])
    monkeypatch.setattr(rep.db, "query_one", lambda *a, **k: {"total": 0})
    r = client.get("/api/reports?page=1&limit=20")
    body = r.get_json()
    assert r.status_code == 200 and body["pagination"]["totalPages"] == 0


def test_vote_401(client):
    r = client.post("/api/reports/r1/vote", json={"vote_type": "confirm"})
    assert r.status_code == 401


def test_vote_enum(client, monkeypatch):
    import backend.routes.vote as v
    import backend.auth_guard as g
    monkeypatch.setattr(g, "current_user", lambda: {"id": "u1", "email": "a@b.c", "name": "A", "role": "user"})
    r = client.post("/api/reports/r1/vote", json={"vote_type": "bogus"})
    assert r.status_code == 400
    monkeypatch.setattr(v.rate_limit, "check_rate_limit", lambda *a, **k: {"allowed": False, "remaining": 0})
    r = client.post("/api/reports/r1/vote", json={"vote_type": "confirm"})
    assert r.status_code == 429


def test_comment_validation(client, monkeypatch):
    import backend.auth_guard as g
    monkeypatch.setattr(g, "current_user", lambda: {"id": "u1", "email": "a@b.c", "name": "A", "role": "user"})
    r = client.post("/api/reports/r1/comment", json={"body": "   "})
    assert r.status_code == 400


def test_anon_comment_201(client, monkeypatch):
    import backend.routes.comment as cm
    monkeypatch.setattr(cm.auth_guard, "current_user", lambda: None)
    monkeypatch.setattr(cm.rate_limit, "check_rate_limit", lambda *a, **k: {"allowed": True, "remaining": 1})
    monkeypatch.setattr(cm.db, "query", lambda *a, **k: [])
    monkeypatch.setattr(cm.audit, "log_audit_event", lambda *a, **k: None)
    calls = {"n": 0}

    def fake_one(sql, params=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"id": "r1", "title": "Some scam"}
        if calls["n"] == 2:
            return {"id": "c1", "body": "looks fake", "user_name": "Anonymous",
                    "user_tier": "newcomer", "created_at": "2026-01-01"}
        return {"reporter_id": "u9", "title": "Some scam", "email": None}

    monkeypatch.setattr(cm.db, "query_one", fake_one)
    r = client.post("/api/reports/r1/comment", json={"body": "looks fake"})
    body = r.get_json()
    assert r.status_code == 201
    assert body["comment"]["user_name"] == "Anonymous"


def test_discussion_vote_validation(client, monkeypatch):
    import backend.auth_guard as g
    monkeypatch.setattr(g, "current_user", lambda: {"id": "u1", "email": "a@b.c", "name": "A", "role": "user"})
    assert client.post("/api/discussions/vote", json={}).status_code == 400
    assert client.post("/api/discussions/vote", json={"target_type": "x", "target_id": "y", "vote_value": 1}).status_code == 400
    assert client.post("/api/discussions/vote", json={"target_type": "reply", "target_id": "y", "vote_value": 5}).status_code == 400


def test_admin_401(client):
    assert client.get("/api/admin/reports").status_code == 401
    assert client.get("/api/admin/appeals").status_code == 401
    assert client.get("/api/admin/config").status_code == 401
    assert client.post("/api/admin/recalculate-risk").status_code == 401


def test_admin_403_for_user(client, monkeypatch):
    import backend.auth_guard as g
    monkeypatch.setattr(g, "current_user", lambda: {"id": "u1", "email": "a@b.c", "name": "A", "role": "user",
                                                   "reputation_score": 0, "reputation_tier": "newcomer"})
    assert client.get("/api/admin/reports").status_code == 403
    assert client.post("/api/admin/appeals", json={"appeal_id": "a", "new_status": "upheld"}).status_code == 403


def test_evidence_upload_401(client):
    r = client.post("/api/evidence/upload", data={"report_id": "r1"})
    assert r.status_code == 401


def test_evidence_upload_validation_400(client, monkeypatch):
    import backend.auth_guard as g
    import backend.routes.evidence as ev
    monkeypatch.setattr(g, "current_user", lambda: {"id": "u1", "email": "a@b.c", "name": "A", "role": "user"})
    monkeypatch.setattr(ev.db, "query_one", lambda *a, **k: {"id": "r1"})
    r = client.post("/api/evidence/upload",
                    data={"report_id": "11111111-1111-1111-1111-111111111111",
                          "file": (io.BytesIO(b"evil"), "evil.exe", "application/x-msdownload")},
                    content_type="multipart/form-data")
    assert r.status_code == 400


def test_report_put_401_before_400(client, monkeypatch):
    import backend.routes.report_detail as rd
    monkeypatch.setattr(rd.db, "query_one", lambda *a, **k: {"reporter_id": "someone-else"})
    r = client.put("/api/reports/r1", json={})
    assert r.status_code == 401


def test_signup_validation(client):
    assert client.post("/api/auth/signup", json={"email": "a@b.c"}).status_code == 400
    assert client.post("/api/auth/signup", json={"name": "A", "email": "a@b.c", "password": "short"}).status_code == 400
    assert client.post("/api/auth/login", json={"email": "a@b.c"}).status_code == 400
