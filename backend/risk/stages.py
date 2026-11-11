"""Stage transitions. Verbatim port of src/lib/risk/stages.ts."""
import json

from backend import db

THRESHOLDS = {
    "multipleReportsRequired": 2,
    "communityVerifiedVotes": 5,
    "communityVerifiedEvidenceAndReports": {"reports": 2, "evidence": 2},
    "confirmedMaliciousRequiresAdmin": True,
    "denyVoteRegressionThreshold": 0.5,
}


def determine_stage_transition(report_id: str) -> dict | None:
    report = db.query_one("SELECT * FROM fraud_reports WHERE id = UUID_TO_BIN(%s)", (report_id,))
    if not report:
        raise ValueError("Report not found")
    current = report.get("verification_stage")
    rep = db.query_one(
        "SELECT COUNT(DISTINCT reporter_id) as count FROM fraud_reports WHERE website_url_id = %s",
        (report.get("website_url_id"),),
    )
    reporter_count = int((rep or {}).get("count", 0) or 0)
    ev = db.query_one("SELECT COUNT(*) as count FROM report_evidence WHERE report_id = UUID_TO_BIN(%s)", (report_id,))
    evidence_count = int((ev or {}).get("count", 0) or 0)

    new_stage = current
    reason = ""
    total = int(report.get("total_votes", 0) or 0)
    deny = int(report.get("deny_votes", 0) or 0)
    if total > 0 and deny / total > THRESHOLDS["denyVoteRegressionThreshold"]:
        if current not in ("reported", "under_review"):
            new_stage = "under_review"
            reason = "High deny vote ratio triggered regression"
    if new_stage == current:
        if current == "reported":
            if reporter_count >= THRESHOLDS["multipleReportsRequired"]:
                new_stage = "multiple_reports"
                reason = f"{reporter_count} independent reports reached threshold"
        elif current == "multiple_reports":
            need = THRESHOLDS["communityVerifiedEvidenceAndReports"]
            if int(report.get("confirm_votes", 0) or 0) >= THRESHOLDS["communityVerifiedVotes"] or (
                reporter_count >= need["reports"] and evidence_count >= need["evidence"]
            ):
                new_stage = "community_verified"
                reason = "Community verification threshold met"
    if new_stage == current:
        return None
    return {"reportId": report_id, "oldStage": current, "newStage": new_stage,
            "reason": reason, "autoAdvanced": True}


def apply_stage_transition(transition: dict) -> None:
    db.query("UPDATE fraud_reports SET verification_stage = %s WHERE id = UUID_TO_BIN(%s)",
             (transition["newStage"], transition["reportId"]))
    db.query(
        "INSERT INTO report_history (id, report_id, actor_id, action, old_value, new_value) "
        "VALUES (UUID_TO_BIN(UUID()), UUID_TO_BIN(%s), NULL, 'status_changed', %s, %s)",
        (transition["reportId"],
         json.dumps({"verification_stage": transition["oldStage"]}),
         json.dumps({"verification_stage": transition["newStage"], "reason": transition.get("reason", "")})),
    )
