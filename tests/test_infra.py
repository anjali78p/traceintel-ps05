import json
import unittest
from datetime import timedelta

from traceintel.config import load_config
from traceintel.infra import parsers
from traceintel.infra.cache import Cache
from traceintel.infra.correlate import suggest_relationships
from traceintel.infra.enrich import Enricher
from traceintel.infra.fixtures import DEMO_NOW, DOMAINS, FakeHttp, SHARED_IP, OTHER_IP
from traceintel.infra.http import HttpResponse

CFG = load_config()
A, B, H = DOMAINS


def mk(http=None, cache=None, now=DEMO_NOW, offline=False):
    return Enricher(http or FakeHttp(), cache or Cache(), CFG, now=now, offline=offline)


class Domain(unittest.TestCase):
    def test_summary_and_indicators(self):
        e = mk().enrich_domain(A)
        s = e["summary"]
        self.assertEqual((s["age_days"], s["registrar"], s["ips"]), (11, "Example Registrar Inc.", [SHARED_IP]))
        self.assertEqual(s["nameservers"], ["ns1.cheapdns.example", "ns2.cheapdns.example"])
        self.assertIn("www.secure-kyc-update.example", s["certificate_names"])
        self.assertEqual({i["code"] for i in e["indicators"]}, {"NEWLY_REGISTERED", "REGISTRANT_REDACTED"})
        self.assertEqual([t["event"] for t in e["timeline"]][0], "Domain registered")
        self.assertIn("NOT proof", e["disclaimer"])

    def test_old_domain_not_flagged_new(self):
        self.assertNotIn("NEWLY_REGISTERED", {i["code"] for i in mk().enrich_domain(H)["indicators"]})

    def test_every_observation_has_provenance(self):
        for o in mk().enrich_domain(A)["observations"].values():
            self.assertTrue(o["ref"] and o["url"].startswith("https://") and o["retrieved_at"] and o["status"] == "ok")

    def test_registrant_personal_data_not_stored(self):
        r = {"entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Real Person Name"]]]}]}
        out = parsers.parse_rdap_domain(json.dumps(r))
        self.assertNotIn("Real Person", json.dumps(out)); self.assertEqual(out["registrant_info"], "published")

    def test_invalid_domain_rejected(self):
        for bad in ("not a domain", "http://x.com/path", "-bad-.com"):
            with self.assertRaises(ValueError):
                mk().enrich_domain(bad)

    def test_unknown_domain_not_found_is_honest(self):
        e = mk().enrich_domain("never-heard-of.example")
        self.assertEqual(e["observations"]["rdap"]["status"], "not_found")
        self.assertIsNone(e["summary"]["registered"])


class CacheAndFailures(unittest.TestCase):
    def test_second_call_served_from_cache(self):
        http, cache = FakeHttp(), Cache()
        mk(http, cache).enrich_domain(A); n = len(http.calls)
        e = mk(http, cache).enrich_domain(A)
        self.assertEqual(len(http.calls), n); self.assertEqual(e["observations"]["rdap"]["status"], "cached")

    def test_stale_cache_refetched_after_ttl(self):
        http, cache = FakeHttp(), Cache()
        mk(http, cache).enrich_domain(A); n = len(http.calls)
        mk(http, cache, now=DEMO_NOW + timedelta(hours=48)).enrich_domain(A)
        self.assertGreater(len(http.calls), n)

    def test_offline_no_cache_is_unavailable_and_no_network(self):
        http = FakeHttp()
        e = mk(http, offline=True).enrich_domain(A)
        self.assertEqual(http.calls, []); self.assertEqual(e["observations"]["rdap"]["status"], "unavailable")

    def test_offline_old_cache_is_labelled_stale(self):
        http, cache = FakeHttp(), Cache()
        mk(http, cache).enrich_domain(A)
        e = mk(http, cache, now=DEMO_NOW + timedelta(hours=100), offline=True).enrich_domain(A)
        o = e["observations"]["rdap"]; self.assertEqual(o["status"], "stale"); self.assertGreater(o["age_hours"], 90)

    def test_rate_limit_falls_back_to_stale_cache(self):
        http, cache = FakeHttp(), Cache()
        mk(http, cache).enrich_domain(A)
        limited = FakeHttp({u: HttpResponse(429, "") for u in http.responses})
        e = mk(limited, cache, now=DEMO_NOW + timedelta(hours=48)).enrich_domain(A)
        self.assertEqual(e["observations"]["rdap"]["status"], "stale"); self.assertIn("rate limited", e["observations"]["rdap"]["note"])

    def test_rate_limit_without_cache(self):
        limited = FakeHttp({u: HttpResponse(429, "") for u in FakeHttp().responses})
        self.assertEqual(mk(limited).enrich_domain(A)["observations"]["rdap"]["status"], "rate_limited")

    def test_garbage_and_exception_do_not_crash(self):
        bad = FakeHttp({u: HttpResponse(200, "<html>oops") for u in FakeHttp().responses})
        self.assertEqual(mk(bad).enrich_domain(A)["observations"]["rdap"]["status"], "error")

        class Boom:
            def get(self, *a, **k): raise TimeoutError()
        self.assertEqual(mk(Boom()).enrich_domain(A)["observations"]["rdap"]["status"], "error")


class IP(unittest.TestCase):
    def test_ip_summary(self):
        s = mk().enrich_ip(SHARED_IP)["summary"]
        self.assertEqual((s["asn"], s["bgp_prefix"], s["as_name"]), ("64496", "203.0.113.0/24", "DOCNET-AS, ZZ"))
        self.assertEqual(s["reverse_dns"], ["vps10.cheapdns.example"]); self.assertIn("indicative", s["note"])

    def test_ipv6_cymru_name(self):
        from traceintel.infra.sources import cymru_origin_name
        self.assertTrue(cymru_origin_name("2001:db8::1").endswith(".origin6.asn.cymru.com"))
        self.assertEqual(cymru_origin_name("203.0.113.10"), "10.113.0.203.origin.asn.cymru.com")

    def test_invalid_ip(self):
        with self.assertRaises(ValueError):
            mk().enrich_ip("999.1.1.1")


class Correlation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rels = suggest_relationships(mk().enrich_all(DOMAINS))

    def kinds(self, k):
        return [r for r in self.rels if r["type"] == k]

    def test_shared_ip_ns_asn_cert_found_between_scam_domains_only(self):
        for k in ("shared_ip", "shared_nameserver", "shared_asn", "shared_certificate"):
            r = self.kinds(k); self.assertEqual(len(r), 1, k); self.assertEqual(r[0]["entities"], sorted([A, B]), k)
        self.assertEqual(self.kinds("shared_ip")[0]["value"], SHARED_IP)

    def test_unrelated_domain_not_linked(self):
        self.assertTrue(all(H not in r["entities"] for r in self.rels))

    def test_never_claims_strong_and_always_has_caveat_and_evidence(self):
        for r in self.rels:
            self.assertNotEqual(r["strength"], "strong")
            self.assertTrue(r["caveat"] and r["evidence_refs"]); self.assertEqual(r["origin"], "automatic_suggestion")


class Resilience(unittest.TestCase):
    class Scripted:
        """Returns the scripted responses in order for every URL, then repeats the last one."""
        def __init__(self, *resps): self.resps, self.n = list(resps), 0
        def get(self, url, headers=None, timeout=None):
            self.timeouts = getattr(self, "timeouts", []) + [timeout]
            r = self.resps[min(self.n, len(self.resps) - 1)]; self.n += 1; return r

    def test_dns_servfail_is_error_not_ok_and_not_cached(self):
        h = self.Scripted(HttpResponse(200, json.dumps({"Status": 2})))
        c = Cache(); e = mk(h, c).enrich_ip(SHARED_IP)
        self.assertEqual(e["observations"]["asn_origin"]["status"], "error")
        self.assertIsNone(c.get(f"dns|{SHARED_IP}|CYMRU"))
        self.assertIn("rcode 2", e["observations"]["asn_origin"]["note"])
        self.assertIn("error", e["summary"]["asn_lookup"])

    def test_dns_retry_recovers_from_transient_servfail(self):
        ok = json.dumps({"Status": 0, "Answer": [{"name": "x.", "type": 12, "TTL": 1, "data": "host.example."}]})
        h = self.Scripted(HttpResponse(200, json.dumps({"Status": 2})), HttpResponse(200, ok))
        o = mk(h)._dns("k", "x", "PTR")
        self.assertEqual(o["status"], "ok"); self.assertEqual(o["data"]["answers"][0]["data"], "host.example.")

    def test_empty_answer_is_ok_but_explained(self):
        o = mk().enrich_ip(OTHER_IP)["observations"]["ptr"]
        self.assertEqual(o["status"], "ok"); self.assertIn("no records", o["note"])

    def test_crt_uses_long_timeout_and_retries_once(self):
        h = self.Scripted(HttpResponse(503, ""), HttpResponse(200, "[]"))
        e = mk(h)
        o = e._observe("crtsh", "x.example", "https://crt.sh/?q=x", parsers.parse_crt, timeout=30, retries=1)
        self.assertEqual(o["status"], "ok"); self.assertEqual(h.timeouts, [30, 30])
        self.assertEqual(e.crt_timeout, 30)

    def test_crt_persistent_failure_reports_reason(self):
        o = mk(self.Scripted(HttpResponse(503, "")))._observe("crtsh", "x.example", "u", parsers.parse_crt, retries=1)
        self.assertEqual(o["status"], "error"); self.assertIn("HTTP 503", o["note"])


class Fallback(unittest.TestCase):
    class Split:
        """Google DoH always SERVFAILs; Cloudflare DoH answers."""
        def __init__(self, cf_ok=True): self.calls, self.cf_ok = [], cf_ok
        def get(self, url, headers=None, timeout=None):
            self.calls.append((url, headers))
            if "dns.google" in url:
                return HttpResponse(200, json.dumps({"Status": 2}))
            if not self.cf_ok:
                return HttpResponse(200, json.dumps({"Status": 2}))
            return HttpResponse(200, json.dumps({"Status": 0, "Answer": [
                {"name": "x.", "type": 16, "TTL": 1, "data": '"64496 | 203.0.113.0/24 | ZZ | arin | 2020-01-01"'}]}))

    def test_fallback_resolver_used_and_disclosed(self):
        h = self.Split(); o = mk(h)._dns("k", "x.example", "TXT")
        self.assertEqual(o["status"], "ok"); self.assertIn("cloudflare-dns.com", o["url"])
        self.assertIn("fallback resolver", o["note"])
        self.assertTrue(any(hd == {"Accept": "application/dns-json"} for _, hd in h.calls))

    def test_both_resolvers_failing_reports_error_with_both_reasons(self):
        o = mk(self.Split(cf_ok=False))._dns("k", "x.example", "TXT")
        self.assertEqual(o["status"], "error"); self.assertIn("fallback resolver also failed", o["note"])

    def test_no_fallback_when_nxdomain(self):
        h = FakeHttp({}); mk(h)._dns("k", "nothing.example", "A")      # 404 from fixtures -> not_found, not error
        self.assertFalse(any("cloudflare" in u for u in h.calls))

    def test_no_fallback_offline(self):
        h = FakeHttp(); o = mk(h, offline=True)._dns("k", "x.example", "A")
        self.assertEqual(h.calls, []); self.assertEqual(o["status"], "unavailable")

    def test_asn_recovers_via_fallback(self):
        e = mk(self.Split()).enrich_ip("203.0.113.10")
        self.assertEqual(e["summary"]["asn"], "64496")


if __name__ == "__main__":
    unittest.main()
