"""Pure parsers for public-source responses. Personal registrant details are deliberately NOT retained."""
from __future__ import annotations
import json
from datetime import datetime, timezone


def _dt(s):
    if not s:
        return None
    d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return d.astimezone(timezone.utc).replace(tzinfo=None).isoformat() if d.tzinfo else d.isoformat()


def _fn(entity):
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item and item[0] == "fn":
            return item[3]
    return None


def parse_rdap_domain(body):
    j = json.loads(body)
    ev = {e.get("eventAction"): _dt(e.get("eventDate")) for e in j.get("events", [])}
    registrar, registrant = None, "not_listed"
    for ent in j.get("entities", []):
        roles = ent.get("roles", [])
        if "registrar" in roles:
            registrar = _fn(ent)
        if "registrant" in roles:
            fn = (_fn(ent) or "")
            registrant = "redacted_or_privacy" if (not fn or "redact" in fn.lower() or "privacy" in fn.lower()) else "published"
    return {"registered": ev.get("registration"), "expires": ev.get("expiration"), "last_changed": ev.get("last changed"),
            "registrar": registrar, "registrant_info": registrant,       # flag only; name/contact not stored
            "nameservers": sorted(n["ldhName"].lower().rstrip(".") for n in j.get("nameservers", []) if n.get("ldhName")),
            "status": j.get("status", [])}


def parse_rdap_ip(body):
    j = json.loads(body)
    org = None
    for ent in j.get("entities", []):
        if "registrant" in ent.get("roles", []) or org is None:
            org = _fn(ent) or org
    cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in j.get("cidr0_cidrs", [])]
    return {"network_name": j.get("name"), "handle": j.get("handle"), "registered_country": j.get("country"),
            "start": j.get("startAddress"), "end": j.get("endAddress"), "cidrs": cidrs, "organisation": org,
            "type": j.get("type")}


def parse_doh(body):
    j = json.loads(body)
    return {"rcode": j.get("Status"),
            "answers": [{"name": a.get("name", "").rstrip(".").lower(), "type": a.get("type"), "ttl": a.get("TTL"),
                         "data": a.get("data", "").strip().strip('"')} for a in j.get("Answer", [])]}


def parse_cymru_txt(data):
    return [p.strip() for p in data.strip('" ').split("|")]


def parse_crt(body):
    rows = json.loads(body)
    certs, seen = [], set()
    for r in rows:
        if r.get("id") in seen:
            continue
        seen.add(r.get("id"))
        names = sorted({n.strip().lower() for n in str(r.get("name_value", "")).split("\n") if n.strip()})
        certs.append({"id": r.get("id"), "issuer": r.get("issuer_name"), "names": names,
                      "not_before": _dt(r.get("not_before")), "not_after": _dt(r.get("not_after"))})
    certs.sort(key=lambda c: c["not_before"] or "")
    return {"count": len(certs), "certs": certs[:200]}


def validate_doh(data):
    """rcode 0 (ok) and 3 (NXDOMAIN) are valid DNS answers; anything else (e.g. 2 SERVFAIL) is a lookup failure."""
    if data.get("rcode") not in (0, 3):
        return f"DNS resolver returned rcode {data.get('rcode')} (lookup failed, not 'no data')"
    return None
