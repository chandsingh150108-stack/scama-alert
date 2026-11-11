"""DNS checks (DMARC/SPF/MX). Distinguishes confirmed absence of records (False)
from network timeouts, resolver failures, or unresolvable domains (None).
"""
import re


def check_dns(domain: str) -> dict:
    result = {"dmarcExists": None, "spfExists": None, "mxExists": None}
    dom = (domain or "").strip().lower().split("://")[-1].split("/")[0].split(":")[0].strip(".")
    if not dom:
        return result
    try:
        import dns.exception
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 4.0
        resolver.timeout = 2.0

        # --- SPF check (apex TXT) ---
        try:
            answers = resolver.resolve(dom, "TXT")
            result["spfExists"] = False
            for r in answers:
                txt = "".join(
                    s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s)
                    for s in (r.strings if hasattr(r, "strings") else [str(r)])
                )
                if txt.lower().startswith("v=spf1"):
                    result["spfExists"] = True
                    result["spfRecord"] = txt
                    break
        except dns.resolver.NoAnswer:
            result["spfExists"] = False
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout, Exception):
            result["spfExists"] = None

        # --- DMARC check (_dmarc.<domain> TXT) ---
        try:
            answers = resolver.resolve(f"_dmarc.{dom}", "TXT")
            result["dmarcExists"] = False
            for r in answers:
                txt = "".join(
                    s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s)
                    for s in (r.strings if hasattr(r, "strings") else [str(r)])
                )
                if txt.lower().startswith("v=dmarc1"):
                    result["dmarcExists"] = True
                    m = re.search(r"p=(\w+)", txt)
                    if m:
                        result["dmarcPolicy"] = m.group(1)
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # If apex SPF check succeeded (domain exists and DNS is working),
            # NXDOMAIN or NoAnswer on _dmarc.<domain> confirms DMARC is absent.
            if result["spfExists"] is not None:
                result["dmarcExists"] = False
            else:
                result["dmarcExists"] = None
        except (dns.resolver.NoNameservers, dns.exception.Timeout, Exception):
            result["dmarcExists"] = None

        # --- MX check ---
        try:
            answers = resolver.resolve(dom, "MX")
            hosts = [str(r.exchange).rstrip(".") for r in answers]
            result["mxExists"] = len(hosts) > 0
            result["mxRecords"] = hosts
        except dns.resolver.NoAnswer:
            result["mxExists"] = False
            result["mxRecords"] = []
        except Exception:
            result["mxExists"] = None
    except Exception:
        pass
    return result
