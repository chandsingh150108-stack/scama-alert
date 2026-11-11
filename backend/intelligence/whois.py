"""WHOIS lookup with thread-safe bounded cache and timezone-safe date parsing."""
from datetime import datetime, timezone
import json
import threading
import time

_cache: dict = {}
_cache_lock = threading.Lock()
CACHE_TTL = 24 * 60 * 60 * 1000  # 24h in ms for successful lookups
FAILURE_CACHE_TTL = 5 * 60 * 1000  # 5m backoff for failed lookups
MAX_CACHE_ENTRIES = 2048

# Commercial anonymity proxy services vs standard GDPR registry redaction
_PROXY_SERVICE_INDICATORS = (
    "whoisguard", "domains by proxy", "contactprivacy", "withheld for privacy",
    "privacyguardian", "perfect privacy", "anonymize", "whois privacy corp",
)
_GDPR_REDACTION_INDICATORS = (
    "redacted for privacy", "data protected", "statutory masking",
    "gdpr", "redacted",
)


def _now_ms() -> int:
    return int(time.time() * 1000)


def _detect_privacy(data: dict) -> bool:
    """True only when an explicit commercial WHOIS proxy service is detected.

    Standard post-2018 ICANN GDPR redaction ('REDACTED FOR PRIVACY') is the
    default for legitimate domains worldwide and should not be flagged as an
    evasion proxy.
    """
    try:
        blob = json.dumps(data, default=str).lower()
    except Exception:
        blob = str(data).lower()
    return any(i in blob for i in _PROXY_SERVICE_INDICATORS)


def _detect_gdpr_redacted(data: dict) -> bool:
    try:
        blob = json.dumps(data, default=str).lower()
    except Exception:
        blob = str(data).lower()
    return any(i in blob for i in _GDPR_REDACTION_INDICATORS)


def _parse_datetime_utc(val) -> datetime | None:
    if val is None:
        return None
    if hasattr(val, "timestamp"):
        return val.replace(tzinfo=timezone.utc) if val.tzinfo is None else val.astimezone(timezone.utc)
    s = str(val).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s[:26])
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    except Exception:
        try:
            dt = datetime.fromisoformat(s[:19])
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None


def lookup_whois(domain: str) -> dict:
    dom = (domain or "").strip().lower().split("://")[-1].split("/")[0].split(":")[0].strip(".")
    now = _now_ms()
    with _cache_lock:
        cached = _cache.get(dom)
        if cached and now - cached["timestamp"] < cached.get("ttl", CACHE_TTL):
            return cached["data"]

    try:
        import whois as pywhois

        w = pywhois.whois(dom)
        d = w if isinstance(w, dict) else (w.__dict__ if hasattr(w, "__dict__") else {})
        if not isinstance(d, dict):
            d = {"raw": str(w)}

        def first(*keys):
            for k in keys:
                v = d.get(k)
                if v:
                    return v[0] if isinstance(v, list) and v else v
            return None

        creation = first("creation_date", "created")
        expiry = first("expiration_date", "expiry_date", "expiry")
        created_dt = _parse_datetime_utc(creation)
        expiry_dt = _parse_datetime_utc(expiry)
        creation_s = created_dt.isoformat() if created_dt else (str(creation) if creation else None)
        expiry_s = expiry_dt.isoformat() if expiry_dt else (str(expiry) if expiry else None)

        ns = d.get("name_servers") or d.get("NAME_SERVERS") or []
        if isinstance(ns, str):
            ns = [ns]
        data = {
            "domain": dom,
            "registrar": first("registrar"),
            "creationDate": creation_s,
            "expirationDate": expiry_s,
            "nameServers": list(ns) if isinstance(ns, list) else [],
            "registrantOrganization": first("org", "organization"),
            "registrantCountry": first("country"),
            "privacyEnabled": _detect_privacy(d),
            "gdprRedacted": _detect_gdpr_redacted(d),
        }
        if created_dt:
            data["domainAge"] = max(0, (datetime.now(timezone.utc) - created_dt).days)

        with _cache_lock:
            if len(_cache) >= MAX_CACHE_ENTRIES:
                _cache.pop(next(iter(_cache)), None)
            _cache[dom] = {"data": data, "timestamp": now, "ttl": CACHE_TTL}
        return data
    except Exception:
        fallback = {"domain": dom, "privacyEnabled": None, "error": "whois_unavailable"}
        with _cache_lock:
            _cache[dom] = {"data": fallback, "timestamp": now, "ttl": FAILURE_CACHE_TTL}
        return fallback
