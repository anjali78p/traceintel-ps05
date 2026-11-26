"""SYNTHETIC fixture responses in the *shape* of RDAP / DoH / crt.sh replies (hand-written, NOT recordings of real services).
Uses reserved .example names and documentation IP ranges. Lets the module run and be tested fully offline."""
from __future__ import annotations
import json
from datetime import datetime

from . import sources
from .http import HttpResponse

DEMO_NOW = datetime(2026, 3, 12, 12, 0, 0)
DOMAINS = ["secure-kyc-update.example", "quick-loan-bonus.example", "harmless-shop.example"]
SHARED_IP, OTHER_IP = "203.0.113.10", "198.51.100.7"


def _rdap_domain(name, registered, ns, registrant="REDACTED FOR PRIVACY"):
    return {"ldhName": name, "status": ["active"],
            "events": [{"eventAction": "registration", "eventDate": registered},
                       {"eventAction": "expiration", "eventDate": "2027-03-01T00:00:00Z"},
                       {"eventAction": "last changed", "eventDate": registered}],
            "nameservers": [{"ldhName": n.upper()} for n in ns],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar Inc."]]]},
                         {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", registrant]]]}]}


def _doh(name, rtype, answers):
    num = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "CNAME": 5, "PTR": 12}[rtype]
    return {"Status": 0, "Answer": [{"name": name + ".", "type": num, "TTL": 300, "data": a} for a in answers]}


def build_responses():
    R = {}
    def add(url, obj, status=200):
        R[url] = HttpResponse(status, json.dumps(obj))
    spec = {
        "secure-kyc-update.example": ("2026-03-01T08:00:00Z", SHARED_IP, ["ns1.cheapdns.example", "ns2.cheapdns.example"]),
        "quick-loan-bonus.example": ("2026-03-03T09:30:00Z", SHARED_IP, ["ns1.cheapdns.example", "ns2.cheapdns.example"]),
        "harmless-shop.example": ("2019-06-10T10:00:00Z", OTHER_IP, ["ns1.otherdns.example"]),
    }
    for d, (reg, ip, ns) in spec.items():
        add(sources.rdap_domain_url(d), _rdap_domain(d, reg, ns))
        add(sources.doh_url(d, "A"), _doh(d, "A", [ip]))
        for t, ans in (("AAAA", []), ("MX", []), ("CNAME", []), ("NS", [n + "." for n in ns]), ("TXT", ['"v=spf1 -all"'])):
            add(sources.doh_url(d, t), _doh(d, t, ans))
    add(sources.crt_url("secure-kyc-update.example"), [
        {"id": 9001, "issuer_name": "C=US, O=Example CA, CN=Example CA R1", "name_value": "secure-kyc-update.example\nwww.secure-kyc-update.example\nquick-loan-bonus.example",
         "not_before": "2026-03-02T10:00:00", "not_after": "2026-06-02T10:00:00"}])
    add(sources.crt_url("quick-loan-bonus.example"), [
        {"id": 9001, "issuer_name": "C=US, O=Example CA, CN=Example CA R1", "name_value": "secure-kyc-update.example\nwww.secure-kyc-update.example\nquick-loan-bonus.example",
         "not_before": "2026-03-02T10:00:00", "not_after": "2026-06-02T10:00:00"}])
    add(sources.crt_url("harmless-shop.example"), [
        {"id": 5, "issuer_name": "C=US, O=Example CA, CN=Example CA R1", "name_value": "harmless-shop.example",
         "not_before": "2026-01-05T00:00:00", "not_after": "2026-04-05T00:00:00"}])
    for ip, pfx, asn, nm in ((SHARED_IP, "203.0.113.0/24", "64496", "DOCNET-AS, ZZ"), (OTHER_IP, "198.51.100.0/24", "64497", "OTHERNET-AS, ZZ")):
        add(sources.rdap_ip_url(ip), {"name": "DOC-NET-" + asn, "handle": "NET-" + ip, "country": "ZZ",
                                       "startAddress": pfx.split("/")[0], "endAddress": pfx.split("/")[0],
                                       "cidr0_cidrs": [{"v4prefix": pfx.split("/")[0], "length": 24}], "type": "ALLOCATION",
                                       "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Doc Hosting Ltd (synthetic)"]]]}]})
        add(sources.doh_url(sources.cymru_origin_name(ip), "TXT"), _doh("x", "TXT", [f'"{asn} | {pfx} | ZZ | arin | 2020-01-01"']))
        add(sources.doh_url(sources.cymru_asn_name(asn), "TXT"), _doh("x", "TXT", [f'"{asn} | ZZ | arin | 2020-01-01 | {nm}"']))
    add(sources.doh_url(sources.ptr_name(SHARED_IP), "PTR"), _doh("x", "PTR", ["vps10.cheapdns.example."]))
    add(sources.doh_url(sources.ptr_name(OTHER_IP), "PTR"), _doh("x", "PTR", []))
    return R


class FakeHttp:
    def __init__(self, responses=None):
        self.responses, self.calls = responses if responses is not None else build_responses(), []

    def get(self, url, headers=None, timeout=None):
        self.calls.append(url)
        return self.responses.get(url, HttpResponse(404, ""))
