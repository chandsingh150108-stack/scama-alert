import sys
sys.path.insert(0, r"C:\Users\chand\OneDrive\Desktop\New folder (2)\crm")
from backend import db

sites = db.query('SELECT BIN_TO_UUID(id) as website_id, domain, ssl_valid, dmarc_exists, spf_exists, risk_score, risk_level, whois_fetched_at FROM website_urls')
for s in sites:
    print(f"{s['domain']}: ssl={s['ssl_valid']} dmarc={s['dmarc_exists']} spf={s['spf_exists']} risk={s['risk_score']} level={s['risk_level']} fetched={s['whois_fetched_at']}")