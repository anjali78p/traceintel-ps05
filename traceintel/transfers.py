"""Layer 1 (ledger rows) -> Layer 2 (account-to-account transfers) with provenance.

method:
  utr_both_sides   debit and credit rows with same UTR + amount found in two statements (strongest, observed)
  utr_one_side     only one side present; other account taken from counterparty text (unverified)
  counterparty_only no UTR; counterparty text only (weak)
"""
from __future__ import annotations
from collections import defaultdict
from .models import Transfer


def build_transfers(entries):
    usable = [e for e in entries if e.usable]
    by_utr = defaultdict(lambda: {"DR": [], "CR": []})
    for e in usable:
        if e.utr:
            by_utr[e.utr][e.direction].append(e)

    matched, transfers, unresolved = set(), [], []
    raw = []   # (ts, from, to, amt, utr, method, conf, deb_id, cred_id, notes)

    for utr, grp in by_utr.items():
        for d in sorted(grp["DR"], key=lambda x: x.ts_utc):
            cands = [c for c in grp["CR"] if c.entry_id not in matched
                     and c.account_key != d.account_key and c.amount_paise == d.amount_paise]
            if not cands:
                continue
            cands.sort(key=lambda c: (c.account_key != d.counterparty_key, abs((c.ts_utc - d.ts_utc).total_seconds())))
            c = cands[0]
            matched.update({d.entry_id, c.entry_id})
            notes, conf = [], "high"
            if d.counterparty_key and d.counterparty_key != c.account_key:
                conf = "medium"
                notes.append(f"debit-side counterparty text '{d.counterparty_raw}' differs from credited account '{c.account_raw}'")
            skew = abs((c.ts_utc - d.ts_utc).total_seconds())
            if skew > 300:
                notes.append(f"debit/credit timestamps differ by {int(skew)}s; debit time used")
            raw.append((d.ts_utc, d.account_key, c.account_key, d.amount_paise, utr, "utr_both_sides", conf,
                        d.entry_id, c.entry_id, notes))

    for e in usable:
        if e.entry_id in matched:
            continue
        if not e.counterparty_key:
            unresolved.append({"entry_id": e.entry_id, "reason": "no matching UTR pair and no counterparty text"})
            continue
        method = "utr_one_side" if e.utr else "counterparty_only"
        conf = "medium" if e.utr else "low"
        if e.direction == "DR":
            raw.append((e.ts_utc, e.account_key, e.counterparty_key, e.amount_paise, e.utr, method, conf,
                        e.entry_id, None, ["counterparty taken from statement text; other side not verified"]))
        else:
            raw.append((e.ts_utc, e.counterparty_key, e.account_key, e.amount_paise, e.utr, method, conf,
                        None, e.entry_id, ["counterparty taken from statement text; other side not verified"]))

    raw.sort(key=lambda r: (r[0], r[1], r[2], r[3]))
    for i, r in enumerate(raw, 1):
        transfers.append(Transfer(i, r[1], r[2], r[3], r[0], r[4], r[5], r[6], r[7], r[8], r[9]))
    return transfers, unresolved
