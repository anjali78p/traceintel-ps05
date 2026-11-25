"""Reproducible SYNTHETIC dataset with planted scenarios. No real people, accounts or banks."""
from __future__ import annotations
import csv
import json
from datetime import datetime, timedelta
from pathlib import Path

BANK = "SYNTH-BANK (synthetic)"
D0 = datetime(2026, 3, 10)

# ground truth used by tests / demo
CHAIN = ["VICTIM01", "MULE01", "MULE02", "MULE03", "CASHOUT01"]
SENDERS = [f"SENDER{i:02d}" for i in range(1, 9)]
FANOUT = [f"FANOUT{i:02d}" for i in range(1, 6)]
LOOP = ["LOOPX", "LOOPY", "LOOPZ"]
VICTIM_UTR = "699999999001"
STATEMENT_ACCOUNTS = {"VICTIM01": 500000, "MULE01": 2000, "MULE02": 1000, "MULE03": 1000, "CASHOUT01": 0,
                      **{s: 100000 for s in SENDERS}, "LOOPX": 50000, "LOOPY": 50000, "LOOPZ": 50000,
                      "DORM01": 1000, "ROUND01": 0, "SALARY01": 10000}


class _Gen:
    def __init__(self):
        self.events, self.seq = [], 0

    def utr(self):
        self.seq += 1
        return f"6{self.seq:011d}"

    def transfer(self, src, dst, amt, ts, utr=None, mode="UPI"):
        utr = utr or self.utr()
        if src in STATEMENT_ACCOUNTS:
            self.events.append(dict(acct=src, ts=ts, d="DR", amt=amt, cp=dst, utr=utr, mode=mode))
        if dst in STATEMENT_ACCOUNTS:
            self.events.append(dict(acct=dst, ts=ts, d="CR", amt=amt, cp=src, utr=utr, mode=mode))


def build_events():
    g = _Gen()
    at = lambda days=0, h=0, m=0: D0 + timedelta(days=days, hours=h, minutes=m)
    # 1. main chain + fan-in + fan-out (all around MULE01)
    for i, (s, a) in enumerate(zip(SENDERS, [4000, 5500, 3200, 6100, 4800, 5200, 3900, 4500])):
        g.transfer(s, "MULE01", a, at(h=8, m=40 + 10 * i))
    g.transfer("VICTIM01", "MULE01", 50000, at(h=10), utr=VICTIM_UTR)
    g.transfer("MULE01", "MULE02", 49500, at(h=10, m=4))
    g.transfer("MULE02", "MULE03", 49000, at(h=10, m=12))
    g.transfer("MULE03", "CASHOUT01", 48500, at(h=10, m=20))
    for i, f in enumerate(FANOUT):
        g.transfer("MULE01", f, 5000, at(h=10, m=10 + 5 * i))
    # 2. circular flow
    g.transfer("LOOPX", "LOOPY", 30000, at(1, 11, 0))
    g.transfer("LOOPY", "LOOPZ", 29500, at(1, 11, 20))
    g.transfer("LOOPZ", "LOOPX", 29000, at(1, 11, 40))
    # 3. dormant -> active
    g.transfer("EXT-OLD", "DORM01", 500, datetime(2025, 1, 15, 9, 0))
    g.transfer("EXT-DSRC", "DORM01", 200000, at(2, 14, 0))
    g.transfer("DORM01", "EXT-F6", 195000, at(2, 14, 20))
    # 4. round figures
    for i, (a, h, m) in enumerate([(10000, 10, 0), (20000, 10, 30), (50000, 11, 0), (10000, 11, 30)]):
        g.transfer(f"EXT-R{i + 1}", "ROUND01", a, at(3, h, m))
    # 5. negative control: ordinary salaried account (salary, rent, EMI, small spends)
    for mth in (1, 2, 3):
        base = datetime(2026, mth, 1)
        g.transfer("EXT-EMPLOYER", "SALARY01", 60000, base.replace(hour=10), mode="NEFT")
        g.transfer("SALARY01", "EXT-LANDLORD", 15000, base.replace(day=5, hour=9, minute=30))
        g.transfer("SALARY01", "EXT-BANKLOAN", 12000, base.replace(day=7, hour=8))
    for i, amt in enumerate([250, 640, 310, 780, 420, 560]):
        g.transfer("SALARY01", f"EXT-MERCH{i + 1}", amt, datetime(2026, 2, 10 + 2 * i, 18, 15))
    return g.events


def _rows(events, with_account=True):
    rows, bal = [], dict(STATEMENT_ACCOUNTS)
    for acct in STATEMENT_ACCOUNTS:
        es = sorted((e for e in events if e["acct"] == acct), key=lambda e: e["ts"])
        for e in es:
            bal[acct] += e["amt"] if e["d"] == "CR" else -e["amt"]
            narr = f"{e['mode']}/{e['utr']}/{e['cp']}"
            rows.append({"account_ref": acct, "bank": BANK, "date": e["ts"].strftime("%d-%m-%Y"),
                         "time": e["ts"].strftime("%H:%M:%S"), "narration": narr,
                         "debit": f"{e['amt']:.2f}" if e["d"] == "DR" else "",
                         "credit": f"{e['amt']:.2f}" if e["d"] == "CR" else "",
                         "balance": f"{bal[acct]:.2f}", "utr": e["utr"], "counterparty": e["cp"]})
    return rows


DIRTY = [  # account DIRTY01: duplicate, bad date, missing amount, balance mismatch, date-only
    ["DIRTY01", BANK, "10-03-2026", "09:00:00", "UPI/700000000001/EXT-A", "", "10000.00", "15000.00", "700000000001", "EXT-A"],
    ["DIRTY01", BANK, "10-03-2026", "09:00:00", "UPI/700000000001/EXT-A", "", "10000.00", "15000.00", "700000000001", "EXT-A"],
    ["DIRTY01", BANK, "31-02-2026", "09:30:00", "UPI/700000000002/EXT-B", "", "500.00", "15500.00", "700000000002", "EXT-B"],
    ["DIRTY01", BANK, "10-03-2026", "10:00:00", "UPI/700000000003/EXT-C", "", "", "15500.00", "700000000003", "EXT-C"],
    ["DIRTY01", BANK, "10-03-2026", "11:00:00", "UPI/700000000004/EXT-D", "1000.00", "", "99999.00", "700000000004", "EXT-D"],
    ["DIRTY01", BANK, "10-03-2026", "12:00:00", "UPI/700000000005/EXT-E", "500.00", "", "", "700000000005", "EXT-E"],
    ["DIRTY01", BANK, "11-03-2026", "", "UPI/700000000006/EXT-F", "", "250.00", "", "700000000006", "EXT-F"],
]
HEADER = ["account_ref", "bank", "date", "time", "narration", "debit", "credit", "balance", "utr", "counterparty"]


def generate(out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    events = build_events()
    rows = _rows(events)
    with open(out / "statements_all.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=HEADER)
        w.writeheader()
        w.writerows(rows)
    with open(out / "dirty_sample.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(HEADER)
        w.writerows(DIRTY)
    # narration-only XLSX (no utr / counterparty / account columns) to exercise narration parsing
    import pandas as pd
    sal = [{k: r[k] for k in ("date", "time", "narration", "debit", "credit", "balance")}
           for r in rows if r["account_ref"] == "SALARY01"]
    pd.DataFrame(sal).to_excel(out / "statement_SALARY01_narration_only.xlsx", index=False)
    # PDF statement for one account (table), to exercise PDF extraction
    _write_pdf(out / "statement_MULE02.pdf", [r for r in rows if r["account_ref"] == "MULE02"])
    truth = {"victim_utr": VICTIM_UTR, "chain": CHAIN,
             "note": "SYNTHETIC DATA. Planted: chain+fan-in+fan-out at MULE01, circular LOOPX/Y/Z, dormant DORM01, "
                     "round-figure ROUND01, negative control SALARY01, dirty rows in dirty_sample.csv."}
    (out / "ground_truth.json").write_text(json.dumps(truth, indent=2))
    return out


def _write_pdf(path, rows):
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
    from reportlab.lib import colors
    cols = ["date", "time", "narration", "debit", "credit", "balance"]
    data = [["Date", "Time", "Narration", "Debit", "Credit", "Balance"]] + [[r[c] for c in cols] for r in rows]
    t = Table(data)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.black), ("FONTSIZE", (0, 0), (-1, -1), 8)]))
    SimpleDocTemplate(str(path), pagesize=landscape(A4)).build([t])


if __name__ == "__main__":
    print(generate(Path(__file__).resolve().parent.parent / "data" / "synthetic"))
