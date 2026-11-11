import socket
import ssl
from datetime import datetime, timezone


def _normalize_domain(domain: str) -> str:
    dom = (domain or "").strip().lower().split("://")[-1].split("/")[0].split(":")[0].strip(".")
    if not dom:
        return ""
    try:
        return dom.encode("idna").decode("ascii")
    except Exception:
        return dom


def _hostname_matches(domain: str, cert: dict, subject: dict) -> bool:
    """True if the cert covers ``domain`` via SAN or CN (wildcard-aware, IDN-safe)."""
    dom = _normalize_domain(domain)
    names = []
    for typ, val in cert.get("subjectAltName", ()):
        if typ == "DNS" and val:
            names.append(_normalize_domain(val) if not val.startswith("*.") else "*." + _normalize_domain(val[2:]))
    cn = (subject.get("commonName") or "").lower()
    if cn:
        names.append(_normalize_domain(cn) if not cn.startswith("*.") else "*." + _normalize_domain(cn[2:]))
    for pattern in names:
        if pattern == dom:
            return True
        if pattern.startswith("*."):
            suffix = pattern[1:]
            if dom == pattern[2:] or (dom.endswith(suffix) and dom.count(".") == pattern.count(".")):
                return True
    return False


def inspect_ssl(domain: str, port: int = 443) -> dict:
    """Validate the live TLS certificate."""
    dom = _normalize_domain(domain)
    if not dom:
        return {"valid": False, "error": "Empty domain"}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((dom, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=dom) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return {"valid": False, "error": "No certificate presented"}
                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")
                issuer = dict(x[0] for x in cert.get("issuer", ())) if cert.get("issuer") else {}
                subject = dict(x[0] for x in cert.get("subject", ())) if cert.get("subject") else {}
                fmt = "%b %d %H:%M:%S %Y %Z"
                now = datetime.now(timezone.utc)
                try:
                    valid_from = datetime.strptime(not_before, fmt).replace(tzinfo=timezone.utc)
                    valid_to = datetime.strptime(not_after, fmt).replace(tzinfo=timezone.utc)
                except Exception:
                    return {"valid": False, "reason": "Unparseable certificate dates"}
                days = (valid_to - now).days
                is_valid = valid_from <= now <= valid_to
                self_signed = bool(issuer.get("commonName")) and (
                    issuer.get("commonName") == subject.get("commonName")
                )
                if self_signed:
                    is_valid = False
                elif is_valid and not _hostname_matches(dom, cert, subject):
                    return {
                        "valid": False,
                        "issuer": issuer.get("commonName") or issuer.get("organizationName"),
                        "subject": subject.get("commonName"),
                        "validFrom": not_before,
                        "validTo": not_after,
                        "selfSigned": self_signed,
                        "daysUntilExpiry": days,
                        "reason": "hostname mismatch",
                    }
                return {
                    "valid": is_valid,
                    "issuer": issuer.get("commonName") or issuer.get("organizationName"),
                    "subject": subject.get("commonName"),
                    "validFrom": not_before,
                    "validTo": not_after,
                    "selfSigned": self_signed,
                    "daysUntilExpiry": days,
                }
    except socket.timeout:
        return {"valid": False, "error": "Connection timeout"}
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "issuer": None, "reason": f"certificate verify failed: {e}"}
    except Exception as e:
        msg = str(e).lower()
        if any(k in msg for k in ("getaddrinfo failed", "name or service not known",
                                  "no such host", "connection refused",
                                  "unreachable", "timed out", "timeout", "nodename nor servname")):
            return {"valid": False, "error": str(e)}
        return {"valid": False, "reason": str(e)}
