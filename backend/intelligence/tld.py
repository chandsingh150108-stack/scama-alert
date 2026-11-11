"""TLD reputation. Normalized to a 0-15 point contextual risk modifier so
that TLD choice alone cannot dominate the 0-100 automated risk score or
penalize safe TLDs (.com, .in, .gov.in) with non-zero baseline risk.
"""

TLD_REPUTATION = {
    ".xin": ("critical", "Known for malicious activity"),
    ".bond": ("critical", "Frequently abused by scammers"),
    ".buzz": ("critical", "High spam and scam association"),
    ".sbs": ("critical", "Frequently used for phishing"),
    ".cfd": ("critical", "Known for fraudulent activity"),
    ".tk": ("critical", "Free domain, extreme historical abuse"),
    ".ml": ("critical", "Free domain, extreme historical abuse"),
    ".ga": ("critical", "Free domain, extreme historical abuse"),
    ".cf": ("critical", "Free domain, extreme historical abuse"),
    ".gq": ("critical", "Free domain, extreme historical abuse"),
    ".cc": ("high", "Commonly used for impersonation"),
    ".mov": ("high", "Newer TLD with abuse issues"),
    ".rip": ("high", "Associated with scam sites"),
    ".zip": ("high", "Confusing TLD used in phishing"),
    ".top": ("high", "High abuse rate reported"),
    ".xyz": ("high", "Commonly used for low-cost registrations and abuse"),
    ".icu": ("high", "High phishing and spam abuse ratio"),
    ".cyou": ("high", "Frequently used in disposable scam campaigns"),
    ".info": ("medium", "Frequently used for spam"),
    ".vip": ("medium", "Newer TLD with some abuse"),
    ".click": ("medium", "Can be used for deceptive links"),
    ".online": ("medium", "Moderate abuse reports"),
    ".site": ("medium", "Moderate abuse reports"),
    ".store": ("medium", "Used by some fake stores"),
    ".live": ("medium", "Moderate phishing abuse"),
    ".shop": ("low", "Generally legitimate e-commerce"),
    ".club": ("low", "Generally legitimate"),
    ".io": ("low", "Popular with tech companies"),
    ".co": ("low", "Alternative to .com"),
    ".app": ("low", "HSTS-preloaded TLD"),
    ".dev": ("low", "HSTS-preloaded developer TLD"),
    ".com": ("safe", "Most established TLD"),
    ".org": ("safe", "Established for organizations"),
    ".net": ("safe", "Established network TLD"),
    ".in": ("safe", "Indian country code"),
    ".co.in": ("safe", "Established Indian commercial TLD"),
    ".org.in": ("safe", "Indian non-profit organizations"),
    ".net.in": ("safe", "Indian network infrastructure"),
    ".gov.in": ("safe", "Indian government"),
    ".nic.in": ("safe", "National Informatics Centre (India government)"),
    ".ac.in": ("safe", "Indian academic institutions"),
    ".res.in": ("safe", "Indian research institutions"),
    ".edu": ("safe", "Educational institutions"),
    ".edu.in": ("safe", "Indian educational institutions"),
    ".bank.in": ("safe", "Verified Indian banking sector"),
    ".fin.in": ("safe", "Verified Indian financial sector"),
}

# Normalized 0-15 point scale (Safe TLDs score 0, not 5; Critical TLDs score 15, not 100)
_SCORES = {"critical": 15, "high": 10, "medium": 6, "low": 2, "safe": 0}


def get_tld_reputation(domain: str) -> dict:
    clean = (domain or "").strip().lower().split("://")[-1].split("/")[0].split(":")[0].strip(".")
    parts = clean.split(".") if clean else []
    if len(parts) < 2:
        return {"tld": "", "riskLevel": "safe", "reason": "Unknown TLD"}
    for i in range(1, len(parts)):
        tld = "." + ".".join(parts[i:])
        if tld in TLD_REPUTATION:
            level, reason = TLD_REPUTATION[tld]
            return {"tld": tld, "riskLevel": level, "reason": reason}
    tld = "." + parts[-1]
    if tld in TLD_REPUTATION:
        level, reason = TLD_REPUTATION[tld]
        return {"tld": tld, "riskLevel": level, "reason": reason}
    return {"tld": tld, "riskLevel": "safe", "reason": "Unknown TLD, defaulting to safe"}


def get_tld_reputation_score(domain: str) -> int:
    return _SCORES.get(get_tld_reputation(domain)["riskLevel"], 0)
