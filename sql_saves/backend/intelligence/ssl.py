"""SSL inspection. Mirror of src/lib/intelligence/ssl.ts (10s timeout)."""
import socket
import ssl
from datetime import datetime, timezone


def inspect_ssl(domain: str, port: int = 443) -> dict:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
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
                    return {"valid": False, "error": "Unparseable certificate dates"}
                days = (valid_to - now).days
                is_valid = valid_from <= now <= valid_to
                self_signed = issuer.get("commonName") == subject.get("commonName")
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
    except Exception as e:
        return {"valid": False, "error": str(e)}
