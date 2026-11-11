"""TLD reputation. Verbatim port of src/lib/intelligence/tld.ts."""

TLD_REPUTATION = {
    ".xin": ("critical", "Known for malicious activity"),
    ".bond": ("critical", "Frequently abused by scammers"),
    ".buzz": ("critical", "High spam and scam association"),
    ".sbs": ("critical", "Frequently used for phishing"),
    ".cfd": ("critical", "Known for fraudulent activity"),
    ".cc": ("high", "Commonly used for impersonation"),
    ".mov": ("high", "Newer TLD with abuse issues"),
    ".rip": ("high", "Associated with scam sites"),
    ".zip": ("high", "Confusing TLD used in phishing"),
    ".top": ("high", "High abuse rate reported"),
    ".xyz": ("high", "Commonly used for malicious sites"),
    ".tk": ("high", "Free domain, high abuse"),
    ".ml": ("high", "Free domain, high abuse"),
    ".ga": ("high", "Free domain, high abuse"),
    ".cf": ("high", "Free domain, high abuse"),
    ".gq": ("high", "Free domain, high abuse"),
    ".info": ("medium", "Frequently used for spam"),
    ".vip": ("medium", "Newer TLD with some abuse"),
    ".click": ("medium", "Can be used for deceptive links"),
    ".online": ("medium", "Moderate abuse reports"),
    ".site": ("medium", "Moderate abuse reports"),
    ".store": ("medium", "Used by some fake stores"),
    ".shop": ("low", "Generally legitimate e-commerce"),
    ".club": ("low", "Generally legitimate"),
    ".io": ("low", "Popular with tech companies"),
    ".co": ("low", "Alternative to .com"),
    ".com": ("safe", "Most established TLD"),
    ".org": ("safe", "Established for organizations"),
    ".net": ("safe", "Established network TLD"),
    ".in": ("safe", "Indian country code"),
    ".gov.in": ("safe", "Indian government"),
    ".edu": ("safe", "Educational institutions"),
    ".edu.in": ("safe", "Indian educational institutions"),
}

_SCORES = {"critical": 100, "high": 75, "medium": 50, "low": 25, "safe": 5}


def get_tld_reputation(domain: str) -> dict:
    parts = (domain or "").split(".")
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
    return _SCORES.get(get_tld_reputation(domain)["riskLevel"], 5)
