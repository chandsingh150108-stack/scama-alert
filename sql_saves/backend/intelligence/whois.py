"""WHOIS lookup with 24h in-memory cache. Mirror of src/lib/intelligence/whois.ts."""
import time

_cache: dict = {}
CACHE_TTL = 24 * 60 * 60 * 1000  # ms, matches TS


def _now_ms() -> int:
    return int(time.time() * 1000)


def _detect_privacy(data: dict) -> bool:
    import json

    try:
        blob = json.dumps(data, default=str).lower()
    except Exception:
        blob = str(data).lower()
    indicators = ["privacy", "protected", "redacted", "proxy", "whoisguard",
                  "domains by proxy", "contactprivacy", "withheld"]
    return any(i in blob for i in indicators)


def lookup_whois(domain: str) -> dict:
    cached = _cache.get(domain)
    if cached and _now_ms() - cached["timestamp"] < CACHE_TTL:
        return cached["data"]
    try:
        import whois as pywhois

        w = pywhois.whois(domain)
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
        creation_s = str(creation) if creation else None
        expiry_s = str(expiry) if expiry else None
        ns = d.get("name_servers") or d.get("name_servers".upper()) or []
        if isinstance(ns, str):
            ns = [ns]
        data = {
            "domain": domain,
            "registrar": first("registrar"),
            "creationDate": creation_s,
            "expirationDate": expiry_s,
            "nameServers": list(ns) if isinstance(ns, list) else [],
            "registrantOrganization": first("org", "organization"),
            "registrantCountry": first("country"),
            "privacyEnabled": _detect_privacy(d if isinstance(d, dict) else {}),
        }
        if creation_s:
            try:
                from datetime import datetime
                created_dt = creation if hasattr(creation, "timestamp") else datetime.fromisoformat(str(creation_s)[:19])
                data["domainAge"] = max(0, (datetime.now() - created_dt).days)
            except Exception:
                pass
        _cache[domain] = {"data": data, "timestamp": _now_ms()}
        return data
    except Exception:
        fallback = {"domain": domain, "privacyEnabled": False}
        _cache[domain] = {"data": fallback, "timestamp": _now_ms()}
        return fallback
