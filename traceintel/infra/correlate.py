"""Suggested infrastructure relationships. These are leads for an investigator, never proof of common ownership."""
from __future__ import annotations
from collections import defaultdict

COMMON_PROVIDERS = ("cloudflare.com", "awsdns", "domaincontrol.com", "googledomains.com", "azure-dns", "registrar-servers.com")
CAVEATS = {
    "shared_ip": "Shared hosting/CDN/VPS means unrelated sites can share an IP. Not proof of common ownership.",
    "shared_nameserver": "Name servers are often shared by many customers of the same DNS provider.",
    "shared_asn": "An ASN is a network operator, usually hosting many unrelated customers.",
    "shared_certificate": "One certificate listing several names shows they were configured together at issuance; CDNs and "
                          "multi-tenant platforms also do this. Verify with the certificate holder through lawful process.",
}


def _rel(kind, value, entities, strength, evidence):
    return {"type": kind, "value": value, "entities": sorted(entities), "origin": "automatic_suggestion",
            "strength": strength, "caveat": CAVEATS[kind], "evidence_refs": sorted(set(evidence)),
            "explanation": f"{len(entities)} indicators share {kind.replace('_', ' ')} '{value}'."}


def suggest_relationships(enrichments):
    by = {k: defaultdict(set) for k in ("ip", "ns", "asn", "cert")}
    ev = defaultdict(list)
    ip_asn = {e["indicator"]: e["summary"]["asn"] for e in enrichments if e["type"] == "ip" and e["summary"].get("asn")}
    domains = [e for e in enrichments if e["type"] == "domain"]
    apexes = {e["indicator"] for e in domains}
    for e in domains:
        d, s, o = e["indicator"], e["summary"], e["observations"]
        for ip in s["ips"]:
            by["ip"][ip].add(d); ev[("ip", ip)] += [o["dns_A"]["ref"], o["dns_AAAA"]["ref"]]
            if ip in ip_asn:
                by["asn"][ip_asn[ip]].add(d); ev[("asn", ip_asn[ip])] += [o["dns_A"]["ref"], f"dns|{ip}|CYMRU"]
        for ns in s["nameservers"]:
            by["ns"][ns].add(d); ev[("ns", ns)] += [o["rdap"]["ref"], o["dns_NS"]["ref"]]
        for c in (o["ct"]["data"] or {}).get("certs", []):
            hit = {a for a in apexes if any(n == a or n.endswith("." + a) for n in c["names"])}
            if len(hit) >= 2:
                for a in hit:
                    by["cert"][f"crt.sh id {c['id']}"].add(a); ev[("cert", f"crt.sh id {c['id']}")].append(o["ct"]["ref"])
    rels = []
    for ip, ds in by["ip"].items():
        if len(ds) >= 2:
            rels.append(_rel("shared_ip", ip, ds, "weak", ev[("ip", ip)]))
    groups = defaultdict(list)                       # merge nameservers shared by the same set of domains
    for ns, ds in by["ns"].items():
        if len(ds) >= 2:
            groups[frozenset(ds)].append(ns)
    for ds, nss in groups.items():
        nss = sorted(nss)
        common = all(any(p in n for p in COMMON_PROVIDERS) for n in nss)
        rels.append(_rel("shared_nameserver", ", ".join(nss), ds, "very_weak" if common else "weak",
                         [r for n in nss for r in ev[("ns", n)]]))
    for asn, ds in by["asn"].items():
        if len(ds) >= 2:
            rels.append(_rel("shared_asn", f"AS{asn}", ds, "very_weak", ev[("asn", asn)]))
    for cid, ds in by["cert"].items():
        if len(ds) >= 2:
            rels.append(_rel("shared_certificate", cid, ds, "moderate", ev[("cert", cid)]))
    return rels
