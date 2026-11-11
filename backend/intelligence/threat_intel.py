"""Threat-intelligence ingestion, URL canonicalization, multi-tenant isolation,
and Indian/global brand impersonation detection.

Designed to operate with zero mandatory API keys (using cached bulk feeds and
local heuristics) while automatically leveraging Google Safe Browsing v4 if
GOOGLE_SAFE_BROWSING_KEY is configured in the environment.
"""
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request
from typing import Any

# Multi-tenant platforms, cloud hosts, and major portals where a malicious path
# MUST NOT taint the entire registered domain.
SHARED_HOST_DOMAINS = frozenset({
    "google.com", "docs.google.com", "drive.google.com", "sites.google.com",
    "storage.googleapis.com", "firebasestorage.googleapis.com", "web.app",
    "firebaseapp.com", "github.com", "github.io", "raw.githubusercontent.com",
    "gist.github.com", "gitlab.com", "gitlab.io", "bitbucket.org",
    "pages.dev", "workers.dev", "vercel.app", "netlify.app", "herokuapp.com",
    "onrender.com", "railway.app", "fly.dev", "replit.dev", "glitch.me",
    "blogspot.com", "wordpress.com", "medium.com", "substack.com",
    "amazonaws.com", "cloudfront.net", "azurewebsites.net", "blob.core.windows.net",
    "digitaloceanspaces.com", "backblazeb2.com", "discord.com", "discordapp.com",
    "t.me", "telegram.me", "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd",
    "linktr.ee", "notion.site", "canva.site", "weebly.com", "wixsite.com",
})

# High-value Indian and global brands frequently targeted by phishing/scams,
# mapped to their legitimate official base domains.
PROTECTED_BRANDS: dict[str, set[str]] = {
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "sbicard.com", "onlinesbi.com"},
    "onlinesbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"},
    "hdfcbank": {"hdfcbank.com", "hdfc.com"},
    "hdfc": {"hdfcbank.com", "hdfc.com", "hdfclife.com", "hdfcergo.com"},
    "icicibank": {"icicibank.com", "icicidirect.com"},
    "icici": {"icicibank.com", "icicidirect.com", "iciciprulife.com"},
    "axisbank": {"axisbank.com"},
    "kotak": {"kotak.com", "kotakbank.com"},
    "pnbindia": {"pnbindia.in", "netpnb.com"},
    "bankofbaroda": {"bankofbaroda.in", "bobibanking.com"},
    "canarabank": {"canarabank.com", "canarabank.in"},
    "unionbank": {"unionbankofindia.co.in"},
    "indusind": {"indusind.com"},
    "yesbank": {"yesbank.in"},
    "paytm": {"paytm.com", "paytmbank.com"},
    "phonepe": {"phonepe.com"},
    "bhimupi": {"bhimupi.org.in", "npci.org.in"},
    "npci": {"npci.org.in", "bhimupi.org.in"},
    "razorpay": {"razorpay.com"},
    "bharatpe": {"bharatpe.com"},
    "cred": {"cred.club"},
    "zerodha": {"zerodha.com"},
    "groww": {"groww.in"},
    "upstox": {"upstox.com"},
    "angelone": {"angelone.in"},
    "irctc": {"irctc.co.in", "irctc.com"},
    "uidai": {"uidai.gov.in"},
    "aadhaar": {"uidai.gov.in"},
    "epfo": {"epfindia.gov.in"},
    "incometax": {"incometax.gov.in", "incometaxindia.gov.in"},
    "parivahan": {"parivahan.gov.in"},
    "indiapost": {"indiapost.gov.in"},
    "digilocker": {"digilocker.gov.in"},
    "flipkart": {"flipkart.com"},
    "myntra": {"myntra.com"},
    "nykaa": {"nykaa.com"},
    "meesho": {"meesho.com"},
    "zomato": {"zomato.com"},
    "swiggy": {"swiggy.com"},
    "jio": {"jio.com"},
    "airtel": {"airtel.in"},
    "bsnl": {"bsnl.co.in"},
    "amazon": {"amazon.in", "amazon.com", "amazonaws.com"},
    "paypal": {"paypal.com"},
    "netflix": {"netflix.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "apple": {"apple.com", "icloud.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
}

LURE_KEYWORDS = frozenset({
    "kyc", "verify", "verification", "update", "pan", "aadhaar", "aadhar",
    "reward", "rewards", "points", "redeem", "cashback", "refund", "blocked",
    "suspend", "suspended", "reactivate", "unlock", "secure", "login",
    "signin", "netbanking", "ebill", "electricity", "lottery", "bonus",
    "claim", "customs", "parcel", "otp", "support", "helpdesk", "care",
})

# Common ASCII homoglyph substitutions used in typosquatting (0->o, 1->l/i, etc.)
_HOMOGLYPH_MAP = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "8": "b",
    "@": "a",
})

# Known two-level public suffixes for registered-domain extraction
_MULTI_PART_TLDS = frozenset({
    "co.in", "net.in", "org.in", "gov.in", "edu.in", "ac.in", "res.in",
    "nic.in", "firm.in", "gen.in", "ind.in", "bank.in", "fin.in",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.jp", "co.za",
    "com.br", "com.sg", "com.my",
})

DEFAULT_FEEDS = (
    {
        "name": "openphish_community",
        "source_family": "phish_feed",
        "url": "https://openphish.com/feed.txt",
        "confidence": 0.90,
        "format": "text_lines",
    },
    {
        "name": "urlhaus_online",
        "source_family": "abuse_ch",
        "url": "https://urlhaus.abuse.ch/downloads/text_online/",
        "confidence": 0.90,
        "format": "text_lines",
    },
)

_FEED_TTL_SECONDS = int(os.environ.get("SCAMALERT_FEED_TTL_SECONDS", 6 * 3600))
_CACHE_FILE = os.environ.get("SCAMALERT_THREAT_CACHE_FILE", "/tmp/scamalert_threat_cache.json")
_lock = threading.Lock()
_memory_index: dict[str, Any] = {
    "loaded_at": 0.0,
    "urls": {},     # canonical_url -> list of source dicts
    "hosts": {},    # hostname -> list of source dicts
    "domains": {},  # registered_domain -> list of source dicts
}


def normalize_hostname(host: str) -> str:
    """Lowercase, strip port/brackets/dots, and convert Unicode IDN to ASCII Punycode."""
    if not host:
        return ""
    h = host.strip().lower()
    if "://" in h:
        try:
            h = urllib.parse.urlsplit(h).hostname or h
        except Exception:
            h = h.split("://", 1)[1]
    h = h.split("/")[0].split("?")[0].split("#")[0]
    if ":" in h and not h.startswith("["):
        h = h.split(":")[0]
    h = h.strip(". ")
    if not h:
        return ""
    try:
        return h.encode("idna").decode("ascii")
    except Exception:
        return h


def extract_registered_domain(host: str) -> str:
    """Return the registrable domain (e.g. 'sub.sbi.co.in' -> 'sbi.co.in')."""
    h = normalize_hostname(host)
    if not h or _is_ip_literal(h):
        return h
    parts = h.split(".")
    if len(parts) <= 2:
        return h
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def is_shared_host(host: str) -> bool:
    """True if host or its registered domain is a multi-tenant / shared platform."""
    h = normalize_hostname(host)
    if not h:
        return False
    if h in SHARED_HOST_DOMAINS:
        return True
    reg = extract_registered_domain(h)
    if reg in SHARED_HOST_DOMAINS:
        return True
    return any(h.endswith("." + sh) for sh in SHARED_HOST_DOMAINS)


def canonicalize_url(raw_url: str) -> tuple[str, str, str]:
    """Return (canonical_url, normalized_host, registered_domain).

    Normalizes scheme, Punycode host, default ports, redundant slashes,
    and strips fragments.
    """
    raw = (raw_url or "").strip()
    if not raw:
        return "", "", ""
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parsed = urllib.parse.urlsplit(raw)
    except Exception:
        host = normalize_hostname(raw)
        reg = extract_registered_domain(host)
        return (f"http://{host}/" if host else ""), host, reg

    host = normalize_hostname(parsed.hostname or "")
    if not host:
        return "", "", ""
    reg = extract_registered_domain(host)
    path = urllib.parse.unquote(parsed.path or "/")
    path = re.sub(r"/+", "/", path)
    if not path.startswith("/"):
        path = "/" + path
    query = f"?{parsed.query}" if parsed.query else ""
    canon = f"http://{host}{path}{query}"
    return canon, host, reg


def _is_ip_literal(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)) or host.startswith("[")


def _levenshtein_le_1(a: str, b: str) -> bool:
    """Fast check for edit distance == 1 between two strings of length >= 5."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1 or min(la, lb) < 5:
        return False
    if la == lb:
        diffs = sum(1 for x, y in zip(a, b) if x != y)
        if diffs == 1:
            return True
        # Adjacent transposition check (e.g., amaozn vs amazon)
        for i in range(la - 1):
            if a[i] != b[i]:
                return a[i] == b[i + 1] and a[i + 1] == b[i] and a[i + 2:] == b[i + 2:]
        return False
    # Insertion/deletion of 1 char
    longer, shorter = (a, b) if la > lb else (b, a)
    i = j = diffs = 0
    while i < len(longer) and j < len(shorter):
        if longer[i] != shorter[j]:
            diffs += 1
            if diffs > 1:
                return False
            i += 1
        else:
            i += 1
            j += 1
    return True


def analyze_domain_heuristics(domain_or_url: str) -> dict[str, Any]:
    """Evaluate deterministic zero-day indicators: Indian/global brand
    impersonation, IDN Punycode homographs, IP-literal hosts, and subdomain abuse.

    Returns a dictionary with `score` (0..20) and `reasons` (list of strings).
    """
    _, host, reg = canonicalize_url(domain_or_url)
    if not host:
        return {"score": 0, "reasons": [], "impersonatedBrand": None, "isPunycode": False}

    # Official protected brand domains are never flagged as impersonations
    for brand, official_domains in PROTECTED_BRANDS.items():
        if host in official_domains or reg in official_domains:
            return {"score": 0, "reasons": [], "impersonatedBrand": None, "isPunycode": False}

    reasons: list[str] = []
    score = 0
    impersonated_brand = None

    # 1. Raw IP literal host
    if _is_ip_literal(host):
        score += 12
        reasons.append("Website hosted on raw IP address rather than domain name")

    # 2. IDN / Punycode check (xn--)
    labels = host.split(".")
    is_punycode = any(lbl.startswith("xn--") for lbl in labels)
    if is_punycode:
        score += 10
        reasons.append("Internationalized domain name (Punycode xn--) susceptible to homograph spoofing")

    # Extract tokens from domain & subdomain (excluding the TLD)
    reg_parts = reg.split(".")
    sld = reg_parts[0] if reg_parts else host
    host_without_tld = host[: -len(reg) - 1] + "." + sld if host != reg and host.endswith(reg) else sld
    tokens = [t for t in re.split(r"[-._]+", host_without_tld) if t]
    dehomoglyphed_sld = sld.translate(_HOMOGLYPH_MAP)
    dehomoglyphed_tokens = [t.translate(_HOMOGLYPH_MAP) for t in tokens]

    # 3. Brand impersonation & typosquatting check
    for brand, official_domains in PROTECTED_BRANDS.items():
        # Exact brand token inside a non-official domain (e.g., sbi-kyc-update.xyz, login.hdfcbank.verify.com)
        if brand in tokens or brand in dehomoglyphed_tokens:
            impersonated_brand = brand
            score += 15
            reasons.append(f"Unauthorized domain containing protected brand token '{brand}'")
            break
        # Substring match inside SLD with lure keyword or >3 char brand (e.g. sbikyc.in, paytmrewards.xyz)
        if len(brand) >= 4 and (brand in sld or brand in dehomoglyphed_sld):
            impersonated_brand = brand
            score += 14
            reasons.append(f"Domain SLD incorporates protected brand '{brand}'")
            break
        # Edit-distance 1 typosquatting on >=5 char brands (e.g. amaz0n.in, flipkrt.com, hdfcbnk.com)
        if len(brand) >= 5 and (_levenshtein_le_1(sld, brand) or _levenshtein_le_1(dehomoglyphed_sld, brand)):
            impersonated_brand = brand
            score += 14
            reasons.append(f"Lookalike/typosquatting domain resembling '{brand}'")
            break

    # 4. Deceptive lure keywords (kyc, pan, otp, refund, netbanking, etc.)
    matched_lures = [t for t in tokens if t in LURE_KEYWORDS]
    if matched_lures:
        if impersonated_brand:
            score += 5
            reasons.append(f"Combines brand impersonation with phishing lure keywords ({', '.join(matched_lures[:3])})")
        elif len(matched_lures) >= 2:
            score += 8
            reasons.append(f"Multiple high-risk financial/KYC lure keywords in domain ({', '.join(matched_lures[:3])})")
        else:
            score += 4
            reasons.append(f"Suspicious lure keyword in domain ('{matched_lures[0]}')")

    # 5. Excessive subdomain depth or hyphenation (common in phishing kits)
    if len(labels) >= 5 and not is_shared_host(host):
        score += 4
        reasons.append(f"Excessive subdomain depth ({len(labels)} labels)")
    if sld.count("-") >= 3:
        score += 4
        reasons.append(f"Excessive hyphenation in domain name ({sld.count('-')} hyphens)")

    return {
        "score": min(20, score),
        "reasons": reasons,
        "impersonatedBrand": impersonated_brand,
        "isPunycode": is_punycode,
    }


def parse_feed_lines(text: str, source_name: str, source_family: str, confidence: float) -> dict[str, dict[str, list[dict]]]:
    """Parse plaintext URL/domain feed into canonical URL, host, and domain maps.

    Returns {"urls": {...}, "hosts": {...}, "domains": {...}}.
    Validates content so HTML error pages or malformed responses are rejected.
    """
    urls: dict[str, list[dict]] = {}
    hosts: dict[str, list[dict]] = {}
    domains: dict[str, list[dict]] = {}

    if not text or "<html" in text[:500].lower() or "<!doctype html" in text[:500].lower():
        raise ValueError(f"Malformed or HTML response from feed {source_name}")

    meta = {"source": source_name, "family": source_family, "confidence": confidence}
    valid_count = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        # Handle CSV lines if first or third column is URL
        if "," in line and not line.startswith("http"):
            parts = [p.strip(' "') for p in line.split(",")]
            url_candidates = [p for p in parts if p.startswith("http://") or p.startswith("https://")]
            if not url_candidates:
                continue
            line = url_candidates[0]

        canon_url, host, reg = canonicalize_url(line)
        if not host or "." not in host:
            continue
        valid_count += 1
        urls.setdefault(canon_url, []).append(meta)
        if not is_shared_host(host):
            hosts.setdefault(host, []).append(meta)
            if reg and not is_shared_host(reg):
                domains.setdefault(reg, []).append(meta)

    if valid_count == 0:
        raise ValueError(f"Feed {source_name} contained 0 valid indicators")
    return {"urls": urls, "hosts": hosts, "domains": domains}


def _merge_parsed_into_index(target: dict[str, dict], parsed: dict[str, dict]) -> None:
    for bucket in ("urls", "hosts", "domains"):
        dest = target[bucket]
        for key, items in parsed[bucket].items():
            existing = dest.setdefault(key, [])
            existing_sources = {x["source"] for x in existing}
            for item in items:
                if item["source"] not in existing_sources:
                    existing.append(item)
                    existing_sources.add(item["source"])


def refresh_threat_feeds(force: bool = False, timeout: float = 6.0, feeds: tuple = DEFAULT_FEEDS) -> dict[str, Any]:
    """Download and index threat-intelligence feeds with memory + disk caching.

    Safe to call from background enrichment threads; falls back to cached data
    if network downloads fail or are disabled.
    """
    now = time.time()
    with _lock:
        if not force and _memory_index["loaded_at"] > 0 and (now - _memory_index["loaded_at"]) < _FEED_TTL_SECONDS:
            return {"refreshed": False, "reason": "cache_fresh", "loaded_at": _memory_index["loaded_at"]}

    # If live feed fetching is disabled via env (e.g. offline test mode), load disk cache only
    if os.environ.get("SCAMALERT_DISABLE_LIVE_FEEDS", "").lower() in ("1", "true", "yes"):
        return _load_disk_cache()

    combined: dict[str, dict] = {"urls": {}, "hosts": {}, "domains": {}}
    loaded_sources = []
    errors = []

    for feed in feeds:
        try:
            req = urllib.request.Request(
                feed["url"],
                headers={"User-Agent": "ScamAlert-ThreatIntel/1.0 (+https://scamalert.in)"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw_bytes = resp.read(15 * 1024 * 1024)  # Cap at 15 MB for memory safety
                text = raw_bytes.decode("utf-8", errors="ignore")
            parsed = parse_feed_lines(text, feed["name"], feed["source_family"], feed["confidence"])
            _merge_parsed_into_index(combined, parsed)
            loaded_sources.append(feed["name"])
        except Exception as e:
            errors.append(f"{feed['name']}: {e}")

    if loaded_sources:
        with _lock:
            _memory_index["loaded_at"] = now
            _memory_index["urls"] = combined["urls"]
            _memory_index["hosts"] = combined["hosts"]
            _memory_index["domains"] = combined["domains"]
        _save_disk_cache(combined, now)
        return {"refreshed": True, "sources": loaded_sources, "errors": errors}

    # All downloads failed: attempt to recover from disk cache or keep previous in-memory index
    disk_status = _load_disk_cache()
    with _lock:
        # Stamp attempt time briefly (5 min backoff) so we don't hammer dead network on every request
        _memory_index["loaded_at"] = now - _FEED_TTL_SECONDS + 300
    return {"refreshed": False, "reason": "all_feeds_failed", "errors": errors, "fallback": disk_status}


def _save_disk_cache(combined: dict, timestamp: float) -> None:
    try:
        payload = {"loaded_at": timestamp, "hosts": combined["hosts"], "domains": combined["domains"]}
        with open(_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f)
    except Exception:
        pass


def _load_disk_cache() -> dict[str, Any]:
    try:
        if os.path.exists(_CACHE_FILE):
            with open(_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            with _lock:
                if not _memory_index["hosts"] and isinstance(data.get("hosts"), dict):
                    _memory_index["hosts"] = data.get("hosts", {})
                    _memory_index["domains"] = data.get("domains", {})
                    _memory_index["loaded_at"] = float(data.get("loaded_at", time.time()))
            return {"loaded_from_disk": True}
    except Exception:
        pass
    return {"loaded_from_disk": False}


def check_spamhaus_dbl(domain: str) -> dict[str, Any] | None:
    """Query Spamhaus DBL via DNS, strictly validating return codes.

    Spamhaus returns 127.0.1.2..99 for legitimate listings and 127.255.255.252..255
    when queries come through blocked open resolvers (like 8.8.8.8).
    """
    _, host, reg = canonicalize_url(domain)
    target = reg or host
    if not target or _is_ip_literal(target) or is_shared_host(target):
        return None
    try:
        import dns.resolver
        qname = f"{target}.dbl.spamhaus.org"
        answers = dns.resolver.resolve(qname, "A", lifetime=3.0)
        for r in answers:
            ip = str(r)
            # Explicitly ignore error/policy return codes (127.255.255.*)
            if ip.startswith("127.255.255."):
                return None
            if ip in ("127.0.1.4", "127.0.1.5", "127.0.1.6", "127.0.1.2"):
                category = {
                    "127.0.1.4": "phishing",
                    "127.0.1.5": "malware",
                    "127.0.1.6": "botnet_c2",
                    "127.0.1.2": "spam_scam",
                }[ip]
                return {
                    "source": f"spamhaus_dbl_{category}",
                    "family": "spamhaus",
                    "confidence": 0.95 if ip != "127.0.1.2" else 0.75,
                    "granularity": "domain",
                }
    except Exception:
        pass
    return None


def check_google_safe_browsing(url_or_domain: str, timeout: float = 4.0) -> dict[str, Any] | None:
    """Optional Google Safe Browsing v4 Lookup API check when GOOGLE_SAFE_BROWSING_KEY is set."""
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "").strip()
    if not api_key:
        return None
    canon_url, host, _ = canonicalize_url(url_or_domain)
    if not canon_url:
        return None
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={urllib.parse.quote(api_key)}"
    body = {
        "client": {"clientId": "scamalert-india", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": canon_url}, {"url": f"http://{host}/"}],
        },
    }
    try:
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        matches = data.get("matches") or []
        if matches:
            threat_type = matches[0].get("threatType", "MALICIOUS").lower()
            return {
                "source": f"google_safe_browsing_{threat_type}",
                "family": "google_sb",
                "confidence": 0.98,
                "granularity": "url",
            }
    except Exception:
        pass
    return None


def evaluate_threat_intel(
    domain_or_url: str,
    existing_db_matches: int = 0,
    refresh_feeds_if_stale: bool = False,
    check_live_dns_api: bool = False,
) -> dict[str, Any]:
    """Evaluate a website against cached feeds, optional live APIs, and local
    impersonation heuristics.

    Returns:
      - blacklistScore (0..40): Confidence-weighted blacklist score for Python calculator.
      - impersonationScore (0..20): Deterministic brand/homograph/host anomaly score.
      - effectiveBlacklistMatches (0..5+): Mapped integer for website_urls.blacklist_matches
        so the frozen SQL function fn_calculate_risk_score reflects verified intelligence.
      - matchedSources: Deduplicated list of matched threat sources.
      - heuristicReasons: List of human-readable heuristic findings.
    """
    if refresh_feeds_if_stale:
        refresh_threat_feeds(force=False)

    canon_url, host, reg = canonicalize_url(domain_or_url)
    matches: list[dict[str, Any]] = []

    if canon_url and host:
        with _lock:
            # 1. Exact canonical URL match (always checked, even on shared hosts)
            for m in _memory_index["urls"].get(canon_url, ()):
                matches.append({**m, "granularity": "url", "weight": m["confidence"] * 1.0})

            # 2. Hostname & registered-domain match (ONLY if not a shared multi-tenant host)
            if not is_shared_host(host):
                for m in _memory_index["hosts"].get(host, ()):
                    matches.append({**m, "granularity": "host", "weight": m["confidence"] * 0.90})
                if reg and reg != host and not is_shared_host(reg):
                    for m in _memory_index["domains"].get(reg, ()):
                        matches.append({**m, "granularity": "domain", "weight": m["confidence"] * 0.75})

        if check_live_dns_api:
            dbl_hit = check_spamhaus_dbl(host)
            if dbl_hit:
                matches.append({**dbl_hit, "weight": dbl_hit["confidence"] * 0.90})
            gsb_hit = check_google_safe_browsing(canon_url)
            if gsb_hit:
                matches.append({**gsb_hit, "weight": gsb_hit["confidence"] * 1.0})

    # Deduplicate by source_family, keeping the highest-weight match per family
    family_best: dict[str, dict[str, Any]] = {}
    for m in matches:
        fam = m["family"]
        if fam not in family_best or m["weight"] > family_best[fam]["weight"]:
            family_best[fam] = m

    deduped_matches = list(family_best.values())
    heuristics = analyze_domain_heuristics(domain_or_url)
    impersonation_score = heuristics["score"]

    # Calculate confidence-weighted blacklist score
    if deduped_matches:
        # Primary verified source gives up to 25 pts; corroborating independent families add up to +15 pts
        weights = sorted((m["weight"] for m in deduped_matches), reverse=True)
        raw_bl_score = weights[0] * 26.0 + sum(w * 10.0 for w in weights[1:])
        blacklist_score = min(40, round(raw_bl_score))
        # Map into 1..5 effective match units for SQL compatibility (each unit = 4 pts in SQL, max 20)
        effective_matches = max(int(existing_db_matches or 0), min(5, max(3, round(blacklist_score / 7))))
    else:
        db_count = max(0, int(existing_db_matches or 0))
        blacklist_score = min(20, db_count * 4)
        # If deterministic brand impersonation is high-confidence (>=14 pts), record 2 effective units
        # during enrichment so SQL's automated score also reflects strong impersonation evidence.
        if db_count == 0 and impersonation_score >= 14:
            effective_matches = 2
        else:
            effective_matches = db_count

    return {
        "blacklistScore": blacklist_score,
        "impersonationScore": impersonation_score,
        "effectiveBlacklistMatches": effective_matches,
        "matchedSources": [m["source"] for m in deduped_matches],
        "independentFamilies": len(deduped_matches),
        "heuristicReasons": heuristics["reasons"],
        "impersonatedBrand": heuristics["impersonatedBrand"],
        "isPunycode": heuristics["isPunycode"],
    }