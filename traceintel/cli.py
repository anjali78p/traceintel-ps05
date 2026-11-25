import argparse, json, sys
from pathlib import Path
from .config import load_config
from .pipeline import analyze_files
from .trail import reconstruct


def main(argv=None):
    ap = argparse.ArgumentParser(prog="traceintel")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--utr"); ap.add_argument("--account"); ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    cfg = load_config()
    res = analyze_files(a.files, cfg)
    print("FILES:", *[f"{f['file']}: {f['ok']} ok / {f['invalid']} invalid / {f['duplicate']} dup" for f in res["files"]], sep="\n  ")
    print(f"TRANSFERS: {len(res['transfers'])}  PROBLEMS: {len(res['problems'])}")
    print("\nREVIEW-PRIORITY ACCOUNTS (heuristic indicators, not verdicts):")
    for x in res["assessments"]:
        print(f"  {x.priority:6} {x.score:3}  {x.account:12} {', '.join(x.rules)}")
    if a.utr or a.account:
        tr = reconstruct(res["transfers"], cfg, utr=a.utr, account=a.account)
        print("\n" + tr["label"])
        for p in tr["paths"][:10]:
            print(f"  {' -> '.join(p['accounts'])}  hops={p['hops']} span={p['span_minutes']}min  {p['attribution']}")
        if a.json:
            print(json.dumps(tr, indent=2, default=str))


if __name__ == "__main__":
    main()
