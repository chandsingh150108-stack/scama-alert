"""Demo content seeder: wipes all posts and inserts 5 realistic demo reports
with generated evidence screenshots.

Usage (from repo root, MySQL reachable at DATABASE_URL):
    python scripts/seed_demo_posts.py

Images live in seed_images/ and are copied into the running web container
(`crm-web-1:/app/uploads/evidence/...`) via `docker cp`, because the
`web` service has no bind mounts. Evidence rows store real sha256/size.

WARNING: deletes all rows in report/website/discussion/event tables and
resets user counters. Users, categories, tags and platform_config are kept.
"""
import hashlib
import json
import os
import subprocess
import sys
import uuid

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

from backend import db  # noqa: E402
from PIL import Image  # noqa: E402

IMGDIR = os.path.join(ROOT, "seed_images")
WEB_CONTAINER = os.environ.get("SCAMALERT_WEB_CONTAINER", "crm-web-1")

USERS = ["amit.kumar@example.com", "neha.gupta@example.com", "sneha.reddy@example.com",
         "kunal.desai@example.com", "deepa.nair@example.com",
         "arjun.mehta@example.com", "priya.sharma@example.com",
         "rahul.patel@example.com", "ananya.singh@example.com"]
CATS = ["phishing", "fake-ecommerce", "investment-scam", "fake-job-scam", "payment-fraud"]

SITES = [
    ("sbi", "https://sbikyc-update.in/kyc-verfiy", "http://sbikyc-update.in/kyc-verfiy",
     "sbikyc-update.in", False, False, False, 6, 91.00, "critical"),
    ("flip", "https://flipkart-bigbillion-sale.com", "https://flipkart-bigbillion-sale.com",
     "flipkart-bigbillion-sale.com", True, False, False, 3, 76.50, "high"),
    ("task", "https://investgrow-earn.online", "https://investgrow-earn.online",
     "investgrow-earn.online", False, False, False, 8, 93.50, "critical"),
    ("job", "https://naukri-fast-hiring.in", "https://naukri-fast-hiring.in",
     "naukri-fast-hiring.in", True, False, True, 2, 52.00, "medium"),
    ("upi", "https://payeze-upi.in", "https://payeze-upi.in",
     "payeze-upi.in", True, False, False, 4, 68.00, "high"),
]

REPORTS = [
    ("r1", "sbi", "amit.kumar@example.com", "phishing",
     "Fake SBI KYC update page stealing logins",
     "Got an SMS from VM-SBIINF saying my SBI KYC is suspended with a link to sbikyc-update.in. The page looks exactly like onlinesbi.sbi and asks for username, password and OTP. Real SBI domain is onlinesbi.sbi - this is a phishing copy hosted to harvest credentials. I entered nothing and reported the number on 1909.",
     "State Bank of India", None, "2026-10-09"),
    ("r2", "flip", "neha.gupta@example.com", "fake-ecommerce",
     "iPhone 15 for Rs 9,999 on fake Flipkart sale page",
     "flipkart-bigbillion-sale.com is selling iPhone 15 at Rs 9,999 with 87% off banners copied from Flipkart. Seller has zero ratings, only UPI advance, no Cash on Delivery. Paid Rs 9,999 for my brother's birthday gift - order ID never generated, support chat is a bot loop. Real Flipkart is flipkart.com only.",
     "Flipkart", 9999.00, "2026-10-06"),
    ("r3", "task", "sneha.reddy@example.com", "investment-scam",
     "Telegram task scam took Rs 85,000 as security deposit",
     "Joined 'EarnDaily Tasks' on Telegram. First 3 video-like tasks genuinely paid Rs 450. Then they demanded a Rs 25,000 security deposit for premium tasks, then two more top-ups of Rs 30,000 each for 'faster withdrawals'. Total Rs 85,000 gone and the admin blocked me. Withdraw button always shows processing. Filed on cybercrime.gov.in and called 1930.",
     None, 85000.00, "2026-09-28"),
    ("r4", "job", "kunal.desai@example.com", "fake-job-scam",
     "Work-from-home job asked Rs 5,200 joining fee",
     "Email from hr-fast-hiring@gmail.com says I am selected as Data Entry Operator at Rs 28,000/month with no interview. They want Rs 5,200 registration plus training kit fee before sending the offer letter. Site naukri-fast-hiring.in was registered days ago and copies Naukri branding. Refused to pay.",
     None, 5200.00, "2026-10-10"),
    ("r5", "upi", "deepa.nair@example.com", "payment-fraud",
     "OLX buyer QR would have debited Rs 14,999",
     "Was selling my sofa on OLX. Buyer sent a QR code on WhatsApp and said scan it and enter UPI PIN to RECEIVE Rs 14,999 advance. Scanning a QR with PIN always sends money - receiving never needs a PIN. Showed it to my bank manager who confirmed it was a collect request disguised as a receive QR. Blocked and reported.",
     None, None, "2026-10-11"),
]

VOTES = [
    ("r1", "arjun.mehta@example.com", "confirm", 1.00, "Domain is 12 days old, no SBI affiliation. Confirmed phishing."),
    ("r1", "priya.sharma@example.com", "confirm", 1.00, "Reported the sender ID to TRAI 1909 as well."),
    ("r1", "rahul.patel@example.com", "confirm", 0.90, "Same SMS template hit my family group yesterday."),
    ("r2", "priya.sharma@example.com", "confirm", 0.95, "87% off + no COD + zero-rating seller. Textbook fake store."),
    ("r2", "ananya.singh@example.com", "confirm", 0.90, "Checked registrar - privacy protected, created this month."),
    ("r3", "arjun.mehta@example.com", "confirm", 1.00, "Classic task-scam ladder: small payout, then deposit demands."),
    ("r3", "rahul.patel@example.com", "confirm", 1.00, "NCRP complaint number will help others searching this domain."),
    ("r3", "ananya.singh@example.com", "confirm", 0.95, "Three UPI transfers totalling 85k matches the pattern exactly."),
    ("r3", "priya.sharma@example.com", "confirm", 1.00, "Escalated - this gang runs multiple domains."),
    ("r4", "rahul.patel@example.com", "confirm", 0.85, "Gmail sender + joining fee = job fraud markers."),
    ("r5", "priya.sharma@example.com", "confirm", 1.00, "Correct call - collect requests disguised as receive QRs are surging."),
    ("r5", "arjun.mehta@example.com", "confirm", 0.95, "Good awareness post. PIN is only ever for paying."),
]

COMMENTS = [
    ("r1", "sneha.reddy@example.com", "My father got the same SMS. Told him real banks never send KYC links - thanks for posting the screenshots."),
    ("r1", "amit.kumar@example.com", "Update: forwarded the SMS to 1909 and filed a complaint on cybercrime.gov.in. Acknowledgement received."),
    ("r3", "priya.sharma@example.com", "For UPI frauds above Rs 50,000 call 1930 within the golden hours - banks can freeze the mule account faster."),
    ("r5", "deepa.nair@example.com", "Update: OLX took down the buyer's account after my report. Stay alert everyone."),
]

EVIDENCE = [
    ("r1", "sms_sbi_kyc.png", "Screenshot of the fake SBI KYC SMS with the phishing link"),
    ("r2", "flipkart_fake_store.png", "Screenshot of the fake Flipkart sale page at 87% off"),
    ("r3", "telegram_task_scam.png", "Telegram chat showing the deposit demand ladder"),
    ("r3", "bank_statement_charges.png", "Bank statement showing Rs 85,000 debited in 3 UPI transfers"),
    ("r4", "job_offer_email.png", "Email screenshot demanding Rs 5,200 joining fee"),
    ("r5", "upi_qr_fraud.png", "UPI collect request disguised as a receive QR"),
]

WIPE_ORDER = ["appeal_evidence", "appeals", "verification_votes", "report_evidence",
              "report_comments", "report_history", "report_tags", "fraud_reports",
              "risk_score_breakdowns", "discussion_votes", "discussion_replies",
              "website_discussions", "website_urls", "reputation_events",
              "rate_limit_events", "audit_events"]


def uid(table, where, *args):
    return db.query_one(f"SELECT BIN_TO_UUID(id) AS id FROM {table} WHERE {where}", args)["id"]


def main():
    for t in WIPE_ORDER:
        db.query(f"DELETE FROM {t}")
    db.query("UPDATE users SET total_reports = 0, verified_reports = 0,"
             " total_votes_cast = 0, accurate_votes = 0")
    print("wiped posts + reset user counters")

    users = {e: uid("users", "email = %s", e) for e in USERS}
    cats = {s: uid("categories", "slug = %s", s) for s in CATS}

    site_ids, report_ids = {}, {}
    for key, norm, raw, domain, ssl, dmarc, spf, bl, score, level in SITES:
        db.query(
            "INSERT INTO website_urls (id, normalized_url, raw_url, domain, ssl_valid,"
            " dmarc_exists, spf_exists, blacklist_matches, risk_score, risk_level)"
            " VALUES (UUID_TO_BIN(UUID()), %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (norm, raw, domain, ssl, dmarc, spf, bl, score, level))
        wid = uid("website_urls", "domain = %s", domain)
        site_ids[key] = wid
        db.query(
            "INSERT INTO risk_score_breakdowns (id, website_url_id, community_sub_score,"
            " automated_sub_score, category_severity_avg, final_score, signals)"
            " VALUES (UUID_TO_BIN(UUID()), UUID_TO_BIN(%s), %s, %s, %s, %s, CAST(%s AS JSON))",
            (wid, round(float(score) * 0.9, 2), round(float(score) * 0.85, 2), 8.5,
             score, '{"seeded": true}'))

    for key, site, reporter, cat, title, desc, brand, amount, incident in REPORTS:
        db.query(
            "INSERT INTO fraud_reports (id, reporter_id, website_url_id, category_id,"
            " title, description, target_brand, amount_lost, currency, incident_date,"
            " country_code, status, verification_stage, is_anonymous)"
            " VALUES (UUID_TO_BIN(UUID()), UUID_TO_BIN(%s), UUID_TO_BIN(%s), UUID_TO_BIN(%s),"
            " %s, %s, %s, %s, 'INR', %s, 'IN', 'active', 'reported', FALSE)",
            (users[reporter], site_ids[site], cats[cat], title, desc, brand, amount, incident))
        report_ids[key] = uid("fraud_reports", "title = %s", title)

    for key, voter, vtype, conf, comment in VOTES:
        db.query(
            "INSERT INTO verification_votes (id, report_id, voter_id, vote_type, confidence, comment)"
            " VALUES (UUID_TO_BIN(UUID()), UUID_TO_BIN(%s), UUID_TO_BIN(%s), %s, %s, %s)",
            (report_ids[key], users[voter], vtype, conf, comment))

    for key, commenter, body in COMMENTS:
        db.query(
            "INSERT INTO report_comments (id, report_id, user_id, body)"
            " VALUES (UUID_TO_BIN(UUID()), UUID_TO_BIN(%s), UUID_TO_BIN(%s), %s)",
            (report_ids[key], users[commenter], body))
    print(f"sites=5 reports=5 votes={len(VOTES)} comments={len(COMMENTS)}")

    for key, img, desc in EVIDENCE:
        rid = report_ids[key]
        stored = uuid.uuid4().hex + ".png"
        subprocess.run(["docker", "exec", WEB_CONTAINER, "mkdir", "-p",
                        f"/app/uploads/evidence/{rid}"], check=True)
        subprocess.run(["docker", "cp", os.path.join(IMGDIR, img),
                        f"{WEB_CONTAINER}:/app/uploads/evidence/{rid}/{stored}"],
                       check=True)
        with open(os.path.join(IMGDIR, img), "rb") as fh:
            blob = fh.read()
        with Image.open(os.path.join(IMGDIR, img)) as im:
            w, h = im.size
        reporter = db.query_one(
            "SELECT BIN_TO_UUID(reporter_id) AS u FROM fraud_reports WHERE id = UUID_TO_BIN(%s)",
            (rid,))["u"]
        db.query(
            "INSERT INTO report_evidence (id, report_id, uploaded_by, evidence_type,"
            " file_name, file_path, mime_type, file_size_bytes, sha256_hash,"
            " width, height, description, is_approved)"
            " VALUES (UUID_TO_BIN(UUID()), UUID_TO_BIN(%s), UUID_TO_BIN(%s), %s, %s, %s,"
            " 'image/png', %s, %s, %s, %s, %s, TRUE)",
            (rid, reporter, "document" if "statement" in img else "screenshot",
             img.replace("_", "-"), f"/uploads/evidence/{rid}/{stored}",
             len(blob), hashlib.sha256(blob).hexdigest(), w, h, desc))
        print("evidence:", img, "->", rid[:8])
    print("done:", json.dumps({"reports": len(report_ids),
                               "evidence": db.query_one("SELECT COUNT(*) AS c FROM report_evidence")["c"]}))


if __name__ == "__main__":
    main()
