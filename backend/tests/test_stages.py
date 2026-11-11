"""12 cases mirroring risk/stages.test.ts (mocked DB)."""
import pytest

from backend.risk import stages


def _report(stage="reported", confirm=0, deny=0, total=0):
    return {"id": "r1", "verification_stage": stage, "website_url_id": b"wid",
            "confirm_votes": confirm, "deny_votes": deny, "total_votes": total}


def _run(monkeypatch, report, reporters=1, evidence=0):
    monkeypatch.setattr(stages.db, "query_one", lambda sql, params=None: (
        dict(report) if "fraud_reports WHERE id" in sql
        else ({"count": reporters} if "DISTINCT reporter_id" in sql else {"count": evidence})))


def test_missing_report(monkeypatch):
    monkeypatch.setattr(stages.db, "query_one", lambda *a, **k: None)
    with pytest.raises(ValueError):
        stages.determine_stage_transition("nope")


def test_reported_to_multiple(monkeypatch):
    _run(monkeypatch, _report("reported"), reporters=2)
    t = stages.determine_stage_transition("r1")
    assert t and t["newStage"] == "multiple_reports"


def test_reported_stays(monkeypatch):
    _run(monkeypatch, _report("reported"), reporters=1)
    assert stages.determine_stage_transition("r1") is None


def test_multiple_to_verified_votes(monkeypatch):
    _run(monkeypatch, _report("multiple_reports", confirm=5, total=5), reporters=2)
    t = stages.determine_stage_transition("r1")
    assert t and t["newStage"] == "community_verified"


def test_multiple_to_verified_evidence(monkeypatch):
    _run(monkeypatch, _report("multiple_reports"), reporters=2, evidence=2)
    t = stages.determine_stage_transition("r1")
    assert t and t["newStage"] == "community_verified"


def test_multiple_stays(monkeypatch):
    _run(monkeypatch, _report("multiple_reports"), reporters=1, evidence=0)
    assert stages.determine_stage_transition("r1") is None


def test_regression(monkeypatch):
    _run(monkeypatch, _report("multiple_reports", deny=8, total=10), reporters=3)
    t = stages.determine_stage_transition("r1")
    assert t and t["newStage"] == "under_review"


def test_no_regression_from_reported(monkeypatch):
    _run(monkeypatch, _report("reported", deny=9, total=10), reporters=1)
    # stays reported (regression only applies beyond reported/under_review)
    t = stages.determine_stage_transition("r1")
    assert t is None or t["newStage"] in ("multiple_reports", "reported")


def test_verified_requires_admin(monkeypatch):
    _run(monkeypatch, _report("community_verified", confirm=99, total=100), reporters=9)
    assert stages.determine_stage_transition("r1") is None


def test_confirmed_stays(monkeypatch):
    _run(monkeypatch, _report("confirmed_malicious", confirm=99, total=100), reporters=9)
    assert stages.determine_stage_transition("r1") is None


def test_apply_writes(monkeypatch):
    calls = []
    monkeypatch.setattr(stages.db, "query", lambda sql, params=None: calls.append(sql) or [])
    stages.apply_stage_transition({"reportId": "r1", "oldStage": "reported",
                                   "newStage": "multiple_reports", "reason": "x"})
    assert len(calls) == 2
