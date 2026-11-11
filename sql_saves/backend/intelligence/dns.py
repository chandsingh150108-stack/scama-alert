"""DNS checks (DMARC/SPF/MX). Mirror of src/lib/intelligence/dns.ts."""
import re


def check_dns(domain: str) -> dict:
    result = {"dmarcExists": False, "spfExists": False, "mxExists": False}
    try:
        import dns.resolver

        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
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
        except Exception:
            pass
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            for r in answers:
                txt = "".join(
                    s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s)
                    for s in (r.strings if hasattr(r, "strings") else [str(r)])
                )
                if txt.lower().startswith("v=spf1"):
                    result["spfExists"] = True
                    result["spfRecord"] = txt
                    break
        except Exception:
            pass
        try:
            answers = dns.resolver.resolve(domain, "MX")
            hosts = [str(r.exchange).rstrip(".") for r in answers]
            result["mxExists"] = len(hosts) > 0
            result["mxRecords"] = hosts
        except Exception:
            pass
    except Exception:
        pass
    return result
