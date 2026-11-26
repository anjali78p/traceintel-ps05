from __future__ import annotations
import ipaddress
import re
from datetime import datetime, timezone

from . import parsers, sources

DISCLAIMER = ("Passive public-source data only. Hosting, ASN, registrar and geolocation attribution is indicative, "
              "NOT proof of a person's identity or location. Subscriber/login/non-public records require lawful process.")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
RTYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
TYPE_NUM = {"A": 1, "AAAA": 28}


class Enricher:
    def __init__(self, http, cache, cfg, now=None, offline=False):
        self.http, self.cache, self.offline = http, cache, offline
        self.ttl = cfg["infra"]["ttl_hours"]
        self.new_days = cfg["infra"]["new_domain_days"]
        self.crt_timeout = cfg["infra"].get("crt_timeout_seconds", 30)
        self._now = now

    def now(self):
        return self._now or datetime.now(timezone.utc).replace(tzinfo=None)

    def _observe(self, source, query, url, parse, validate=None, timeout=None, retries=0, headers=None):
        key = f"{source}|{query}"
        obs = {"ref": key, "source": source, "query": query, "url": url, "status": "unavailable",
               "retrieved_at": None, "age_hours": None, "data": None, "note": ""}
        cached = self.cache.get(key)

        def from_cache(status, note=""):
            when, data = cached
            obs.update(status=status, retrieved_at=when.isoformat(), data=data, note=note,
                       age_hours=round((self.now() - when).total_seconds() / 3600, 1))
            return obs

        if cached:
            if (self.now() - cached[0]).total_seconds() / 3600 <= self.ttl:
                return from_cache("cached")
            if self.offline:
                return from_cache("stale", "offline mode: serving older cached data")
        elif self.offline:
            obs["note"] = "offline mode and no cached result"
            return obs
        note, limited = "", False
        for _ in range(1 + retries):
            try:
                r = self.http.get(url, headers=headers, timeout=timeout)
            except Exception as e:                  # network failure must never break the case
                note = f"live lookup failed: {type(e).__name__}: {str(getattr(e, 'reason', e))[:120]}"
                continue
            if r.status == 200:
                try:
                    data = parse(r.body)
                except Exception:
                    note = "response could not be parsed"
                    continue
                bad = validate(data) if validate else None
                if bad:
                    note = bad
                    continue
                self.cache.put(key, self.now(), data)
                obs.update(status="ok", retrieved_at=self.now().isoformat(), data=data, age_hours=0.0)
                if isinstance(data, dict) and data.get("answers") == []:
                    obs["note"] = f"no records returned (DNS rcode {data.get('rcode')}: 0=no data, 3=NXDOMAIN)"
                return obs
            if r.status == 404:
                obs.update(status="not_found", retrieved_at=self.now().isoformat(), note="source has no record")
                return obs
            limited = r.status == 429
            note = "rate limited by source" if limited else f"source returned HTTP {r.status}"
            if limited:
                break
        if cached:
            return from_cache("stale", note + "; older cache shown")
        obs.update(status="rate_limited" if limited else "error", note=note)
        return obs

    def _dns(self, query, name, rtype):
        """Primary resolver (Google DoH); if it fails, fall back to Cloudflare DoH. Provenance records which one answered."""
        o = self._observe("dns", query, sources.doh_url(name, rtype), parsers.parse_doh,
                          validate=parsers.validate_doh, retries=1)
        if self.offline or o["status"] not in ("error", "rate_limited", "stale"):
            return o
        o2 = self._observe("dns", query, sources.doh_url_cf(name, rtype), parsers.parse_doh,
                           validate=parsers.validate_doh, retries=1, headers={"Accept": "application/dns-json"})
        if o2["status"] == "ok":
            o2["note"] = ("primary resolver failed (" + o["note"] + "); answered by fallback resolver (Cloudflare DoH)").strip()
            return o2
        o["note"] += f" | fallback resolver also failed: {o2['note']}"
        return o

    # ---------- domain ----------
    def enrich_domain(self, domain):
        d = domain.strip().lower().rstrip(".")
        if not DOMAIN_RE.match(d):
            raise ValueError(f"invalid domain: {domain!r}")
        o = {"rdap": self._observe("rdap_domain", d, sources.rdap_domain_url(d), parsers.parse_rdap_domain)}
        for t in RTYPES:
            o[f"dns_{t}"] = self._dns(f"{d}|{t}", d, t)
        o["ct"] = self._observe("crtsh", d, sources.crt_url(d), parsers.parse_crt, timeout=self.crt_timeout, retries=1)

        rd = (o["rdap"]["data"] or {})
        ips = sorted({a["data"] for t in ("A", "AAAA") for a in ((o[f"dns_{t}"]["data"] or {}).get("answers", []))
                      if a["type"] == TYPE_NUM[t]})
        dns_ns = sorted({a["data"].rstrip(".").lower() for a in (o["dns_NS"]["data"] or {}).get("answers", [])})
        certs = (o["ct"]["data"] or {}).get("certs", [])
        subs = sorted({n for c in certs for n in c["names"] if n.endswith("." + d) or n == d})
        age = None
        if rd.get("registered"):
            age = (self.now() - datetime.fromisoformat(rd["registered"])).days
        summary = {"registered": rd.get("registered"), "expires": rd.get("expires"), "age_days": age,
                   "registrar": rd.get("registrar"), "registrant_info": rd.get("registrant_info"),
                   "nameservers": sorted(set(rd.get("nameservers", [])) | set(dns_ns)), "ips": ips,
                   "certificate_names": subs, "certificate_count": len(certs)}
        indicators = []
        if age is not None and age < self.new_days:
            indicators.append({"code": "NEWLY_REGISTERED", "severity": "low",
                               "explanation": f"Registered {age} days before lookup (threshold {self.new_days} days). "
                                              "Many legitimate sites are also new.", "refs": [o["rdap"]["ref"]]})
        if rd.get("registrant_info") == "redacted_or_privacy":
            indicators.append({"code": "REGISTRANT_REDACTED", "severity": "info",
                               "explanation": "Registrant data is redacted/privacy-protected; this is now the norm and not suspicious by itself.",
                               "refs": [o["rdap"]["ref"]]})
        timeline = [{"ts": rd[k], "event": ev, "ref": o["rdap"]["ref"]} for k, ev in
                    (("registered", "Domain registered"), ("expires", "Registration expires"),
                     ("last_changed", "Registration record last changed")) if rd.get(k)]
        if certs and certs[0]["not_before"]:
            timeline.append({"ts": certs[0]["not_before"], "event": "Earliest certificate in CT logs", "ref": o["ct"]["ref"]})
        timeline.sort(key=lambda e: e["ts"])
        return {"type": "domain", "indicator": d, "observations": o, "summary": summary,
                "indicators": indicators, "timeline": timeline, "disclaimer": DISCLAIMER}

    # ---------- ip ----------
    def enrich_ip(self, ip):
        ip = str(ipaddress.ip_address(ip.strip()))
        o = {"rdap": self._observe("rdap_ip", ip, sources.rdap_ip_url(ip), parsers.parse_rdap_ip),
             "ptr": self._dns(f"{ip}|PTR", sources.ptr_name(ip), "PTR"),
             "asn_origin": self._dns(f"{ip}|CYMRU", sources.cymru_origin_name(ip), "TXT")}
        asn = prefix = None
        ans = (o["asn_origin"]["data"] or {}).get("answers", [])
        if ans:
            f = parsers.parse_cymru_txt(ans[0]["data"])
            asn, prefix = f[0].split()[0], f[1] if len(f) > 1 else None
            o["asn_name"] = self._dns(f"AS{asn}|CYMRU", sources.cymru_asn_name(asn), "TXT")
        as_name = None
        an = (o.get("asn_name", {}).get("data") or {}).get("answers", [])
        if an:
            f = parsers.parse_cymru_txt(an[0]["data"])
            as_name = f[-1] if f else None
        rd = o["rdap"]["data"] or {}
        ptr = [a["data"].rstrip(".") for a in (o["ptr"]["data"] or {}).get("answers", [])]
        summary = {"asn": asn, "as_name": as_name, "bgp_prefix": prefix, "network_name": rd.get("network_name"),
                   "organisation": rd.get("organisation"), "registered_country": rd.get("registered_country"),
                   "reverse_dns": ptr,
                   "asn_lookup": (o["asn_origin"]["status"] + (": " + o["asn_origin"]["note"] if o["asn_origin"]["note"] else "")) if not asn else "ok",
                   "note": "registered_country is the allocation record country, indicative only; not the user's location"}
        return {"type": "ip", "indicator": ip, "observations": o, "summary": summary, "indicators": [],
                "timeline": [], "disclaimer": DISCLAIMER}

    def enrich_all(self, domains=(), ips=()):
        """Domains plus any IPs they resolve to (dedup)."""
        out = [self.enrich_domain(d) for d in domains]
        want = list(dict.fromkeys(list(ips) + [i for e in out for i in e["summary"]["ips"]]))
        return out + [self.enrich_ip(i) for i in want]
