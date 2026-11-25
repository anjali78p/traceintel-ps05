import argparse, json
from ..config import load_config
from .cache import Cache
from .correlate import suggest_relationships
from .enrich import Enricher
from .fixtures import DEMO_NOW, DOMAINS, FakeHttp
from .http import UrllibHttp


def main(argv=None):
    ap = argparse.ArgumentParser(prog="traceintel.infra.cli", description="Passive domain/IP intelligence")
    ap.add_argument("--demo", action="store_true", help="use SYNTHETIC fixture data (no network)")
    ap.add_argument("--domain", action="append", default=[]); ap.add_argument("--ip", action="append", default=[])
    ap.add_argument("--offline", action="store_true", help="serve cache only"); ap.add_argument("--cache", default="infra_cache.db")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    cfg = load_config()
    if a.demo:
        enr = Enricher(FakeHttp(), Cache(":memory:"), cfg, now=DEMO_NOW)
        domains, ips = DOMAINS, []
        print("** DEMO MODE: synthetic fixture data, not real lookups **")
    else:
        enr = Enricher(UrllibHttp(cfg["infra"]["http_timeout_seconds"], cfg["infra"]["min_interval_seconds"]),
                       Cache(a.cache), cfg, offline=a.offline)
        domains, ips = a.domain, a.ip
    res = enr.enrich_all(domains, ips)
    rels = suggest_relationships(res)
    if a.json:
        print(json.dumps({"enrichments": res, "suggested_relationships": rels}, indent=2, default=str)); return
    for e in res:
        s = e["summary"]
        st = {k: v["status"] for k, v in e["observations"].items()}
        print(f"\n[{e['type'].upper()}] {e['indicator']}\n  summary: {json.dumps(s, default=str)}\n  source status: {st}")
        for i in e["indicators"]:
            print(f"  indicator {i['code']} ({i['severity']}): {i['explanation']}")
    print("\nSUGGESTED RELATIONSHIPS (leads, not proof):")
    for r in rels:
        print(f"  [{r['strength']}] {r['type']}: {', '.join(r['entities'])} via {r['value']}\n     caveat: {r['caveat']}")
    print("\n" + res[0]["disclaimer"] if res else "")


if __name__ == "__main__":
    main()
