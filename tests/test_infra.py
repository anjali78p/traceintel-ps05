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


if __name__ == "__main__":
    unittest.main()
