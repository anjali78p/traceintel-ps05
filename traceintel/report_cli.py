import argparse
from pathlib import Path
from .service import CaseService, seed_demo
from .reporting import generate_reports
from . import synthetic


def main():
    ap = argparse.ArgumentParser(description="Generate demo report (synthetic data) without the API")
    ap.add_argument("--out", default="reports")
    a = ap.parse_args()
    data_dir = Path(__file__).resolve().parent.parent / "data" / "synthetic"
    svc = CaseService(":memory:")
    cid = seed_demo(svc, data_dir)
    for kind, p in generate_reports(svc, cid, a.out, victim_utr=synthetic.VICTIM_UTR).items():
        print(f"{kind}: {p}")


if __name__ == "__main__":
    main()
