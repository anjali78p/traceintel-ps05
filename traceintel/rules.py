"""Transparent rule engine. Output = review-priority indicators with evidence, never a verdict."""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from .models import inr

DISCLAIMER = ("Review-priority indicator from configurable heuristics. It is NOT evidence of wrongdoing "
              "and must be verified by an authorised investigator.")
SKIP_KEYS = {"", "UNKNOWN"}

LIMITATIONS = {
    "FAN_IN": "Whether the senders are actually unrelated is not known from the data; legitimate collections (shops, collections, crowdfunding) look similar.",
    "FAN_OUT": "Legitimate disbursements (payroll, refunds, splits) look similar; recipients' relationships are unknown.",
    "RAPID_PASS_THROUGH": "Matches timing and amount only; cannot show the outgoing money is the same money that came in.",
    "HIGH_VELOCITY": "Counts rows in the supplied statements only; busy legitimate accounts can trigger this.",
    "HIGH_TURNOVER_24H": "Absolute threshold on supplied data; not normalised against the account's real history.",
    "DORMANT_TO_ACTIVE": "Only valid if the statement covers the earlier inactive period; a statement gap is not proof of dormancy.",
    "LAYERING": "Amount-similarity chain heuristic; fund attribution through commingled accounts is not proven.",
    "CIRCULAR_FLOW": "Time-ordered cycle of transfers; cycles can arise from legitimate settlements or reversals.",
    "ROUND_FIGURE": "Round amounts are common in legitimate payments (rent, fees).",
}


@dataclass
class Finding:
    account: str
    rule: str
    weight: int
    title: str
    explanation: str
    transfer_ids: list = field(default_factory=list)
    entry_ids: list = field(default_factory=list)
    utrs: list = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    limitation: str = ""


@dataclass
class AccountAssessment:
    account: str
    score: int
    priority: str
    findings: list
    disclaimer: str = DISCLAIMER

    @property
    def rules(self):
        return sorted({f.rule for f in self.findings})


def _utrs(ts):
    return sorted({t.utr for t in ts if t.utr})


def _fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _by(transfers, attr):
    d = defaultdict(list)
    for t in transfers:
        d[getattr(t, attr)].append(t)
    for v in d.values():
        v.sort(key=lambda t: (t.ts_utc, t.transfer_id))
    return d


def _best_window(items, window, metric):
    """Find the window (starting at an item) maximising metric(items_in_window). items sorted by ts."""
    best, best_val = None, 0
    for i, it in enumerate(items):
        win = [x for x in items[i:] if x.ts_utc - it.ts_utc <= window]
        v = metric(win)
        if v > best_val:
            best, best_val = win, v
    return best, best_val


def rule_fan(transfers, cfg, direction):
    key_attr, other_attr = ("to_key", "from_key") if direction == "in" else ("from_key", "to_key")
    rc = cfg["rules"]["fan_in" if direction == "in" else "fan_out"]
    window = timedelta(hours=rc["window_hours"])
    out = []
    for acct, items in _by(transfers, key_attr).items():
        if acct in SKIP_KEYS:
            continue
        items = [t for t in items if getattr(t, other_attr) not in SKIP_KEYS | {acct}]
        win, n = _best_window(items, window, lambda w: len({getattr(t, other_attr) for t in w}))
        if win and n >= rc["min_distinct_counterparties"]:
            total = sum(t.amount_paise for t in win)
            name, verb = ("FAN_IN", "received from") if direction == "in" else ("FAN_OUT", "sent to")
            out.append(Finding(
                acct, name, rc["weight"],
                f"{name.replace('_', ' ').title()}: {n} distinct counterparties",
                f"Account {verb} {n} distinct accounts within {rc['window_hours']}h "
                f"({_fmt(win[0].ts_utc)} to {_fmt(win[-1].ts_utc)}), total INR {inr(total):,.2f}. "
                f"Rule: >= {rc['min_distinct_counterparties']} distinct counterparties in {rc['window_hours']}h.",
                [t.transfer_id for t in win], [], _utrs(win),
                {"distinct_counterparties": n, "total_inr": inr(total),
                 "counterparties": sorted({getattr(t, other_attr) for t in win})},
                LIMITATIONS[name]))
    return out


def rule_pass_through(transfers, cfg):
    rc = cfg["rules"]["rapid_pass_through"]
    window = timedelta(minutes=rc["window_minutes"])
    min_amt = int(rc["min_credit_amount"] * 100)
    ins, outs = _by(transfers, "to_key"), _by(transfers, "from_key")
    out = []
    for acct, credits in ins.items():
        if acct in SKIP_KEYS:
            continue
        hits = []
        for c in credits:
            if c.amount_paise < min_amt:
                continue
            ds = [d for d in outs.get(acct, []) if c.ts_utc <= d.ts_utc <= c.ts_utc + window
                  and d.to_key != c.from_key and d.transfer_id != c.transfer_id]
            fwd = sum(d.amount_paise for d in ds)
            if ds and fwd >= rc["min_forward_ratio"] * c.amount_paise:
                hits.append((c, ds, fwd))
        if hits:
            tids = sorted({c.transfer_id for c, _, _ in hits} | {d.transfer_id for _, ds, _ in hits for d in ds})
            delays = [round((ds[0].ts_utc - c.ts_utc).total_seconds() / 60, 1) for c, ds, _ in hits]
            first = hits[0]
            c0, ds0, f0 = first
            span = round((ds0[-1].ts_utc - c0.ts_utc).total_seconds() / 60, 1)
            over = (f" The forwarded total exceeds this credit, so the account also held other funds; "
                    f"the debits cannot be attributed to this credit alone.") if f0 > c0.amount_paise else ""
            out.append(Finding(
                acct, "RAPID_PASS_THROUGH", rc["weight"],
                f"Rapid pass-through: {len(hits)} credit(s) forwarded within {rc['window_minutes']} min",
                f"Credit of INR {inr(c0.amount_paise):,.2f} (UTR {c0.utr or 'n/a'}) at {_fmt(c0.ts_utc)} "
                f"was followed by {len(ds0)} debit(s) totalling INR {inr(f0):,.2f}: the first after {delays[0]} min, "
                f"the last after {span} min.{over} Rule: >= {int(rc['min_forward_ratio'] * 100)}% of a credit >= INR "
                f"{rc['min_credit_amount']:,} forwarded within {rc['window_minutes']} min (refunds to the sender excluded).",
                tids, [], _utrs([t for t in transfers if t.transfer_id in tids]),
                {"hits": [{"credit_transfer": c.transfer_id, "debit_transfers": [d.transfer_id for d in ds],
                           "credit_inr": inr(c.amount_paise), "forwarded_inr": inr(f)} for c, ds, f in hits],
                 "delay_minutes": delays}, LIMITATIONS["RAPID_PASS_THROUGH"]))
    return out


def _entries_by_acct(entries):
    d = defaultdict(list)
    for e in entries:
        if e.usable and e.account_key not in SKIP_KEYS:
            d[e.account_key].append(e)
    for v in d.values():
        v.sort(key=lambda e: (e.ts_utc, e.entry_id))
    return d


def rule_velocity(entries, cfg):
    rc = cfg["rules"]["velocity"]
    window = timedelta(minutes=rc["window_minutes"])
    out = []
    for acct, es in _entries_by_acct(entries).items():
        win, n = _best_window(es, window, len)
        if win and n >= rc["min_entries"]:
            out.append(Finding(
                acct, "HIGH_VELOCITY", rc["weight"], f"High velocity: {n} entries in {rc['window_minutes']} min",
                f"{n} ledger rows between {_fmt(win[0].ts_utc)} and {_fmt(win[-1].ts_utc)}. "
                f"Rule: >= {rc['min_entries']} rows within {rc['window_minutes']} min.",
                [], [e.entry_id for e in win], sorted({e.utr for e in win if e.utr}), {"entries": n},
                LIMITATIONS["HIGH_VELOCITY"]))
    return out


def rule_turnover(entries, cfg):
    rc = cfg["rules"]["high_turnover_24h"]
    thr = int(rc["min_turnover"] * 100)
    out = []
    for acct, es in _entries_by_acct(entries).items():
        win, v = _best_window(es, timedelta(hours=24), lambda w: sum(e.amount_paise for e in w))
        if win and v >= thr:
            out.append(Finding(
                acct, "HIGH_TURNOVER_24H", rc["weight"], f"High 24h turnover: INR {inr(v):,.2f}",
                f"Gross credits+debits of INR {inr(v):,.2f} within 24h starting {_fmt(win[0].ts_utc)}. "
                f"Rule: >= INR {rc['min_turnover']:,} gross turnover in 24h.",
                [], [e.entry_id for e in win], sorted({e.utr for e in win if e.utr}), {"turnover_inr": inr(v)},
                LIMITATIONS["HIGH_TURNOVER_24H"]))
    return out


def rule_dormant(entries, cfg):
    rc = cfg["rules"]["dormant_to_active"]
    gap, thr = timedelta(days=rc["dormant_days"]), int(rc["min_credit_amount"] * 100)
    out = []
    for acct, es in _entries_by_acct(entries).items():
        for prev, cur in zip(es, es[1:]):
            if cur.direction == "CR" and cur.amount_paise >= thr and cur.ts_utc - prev.ts_utc >= gap:
                days = (cur.ts_utc - prev.ts_utc).days
                out.append(Finding(
                    acct, "DORMANT_TO_ACTIVE", rc["weight"], f"Dormant-to-active: {days} days idle, then INR {inr(cur.amount_paise):,.2f}",
                    f"No activity in the supplied statement for {days} days (last row {_fmt(prev.ts_utc)}), then a credit of "
                    f"INR {inr(cur.amount_paise):,.2f} at {_fmt(cur.ts_utc)}. Rule: >= {rc['dormant_days']} idle days then credit >= INR {rc['min_credit_amount']:,}.",
                    [], [prev.entry_id, cur.entry_id], [cur.utr] if cur.utr else [],
                    {"idle_days": days, "credit_inr": inr(cur.amount_paise)}, LIMITATIONS["DORMANT_TO_ACTIVE"]))
                break
    return out


def _chains(transfers, rc, limit=5000):
    cfg_span = timedelta(hours=rc["max_span_hours"])
    out_by = _by(transfers, "from_key")
    found, count = [], [0]

    def dfs(chain):
        last = chain[-1]
        accts = {chain[0].from_key} | {t.to_key for t in chain}
        ext = False
        for n in out_by.get(last.to_key, []):
            if count[0] > limit:
                return
            if (n.ts_utc >= last.ts_utc and n.ts_utc - chain[0].ts_utc <= cfg_span and n.to_key not in accts
                    and n.to_key not in SKIP_KEYS
                    and rc["amount_ratio_min"] <= n.amount_paise / last.amount_paise <= rc["amount_ratio_max"]):
                ext = True
                count[0] += 1
                dfs(chain + [n])
        if not ext and len(chain) >= rc["min_hops"]:
            found.append(tuple(t.transfer_id for t in chain))

    for t in transfers:
        dfs([t])
    ids = [tuple(c) for c in set(found)]
    def contained(a, b):
        return len(a) < len(b) and any(b[i:i + len(a)] == a for i in range(len(b) - len(a) + 1))
    return [c for c in ids if not any(contained(c, o) for o in ids)]


def rule_layering(transfers, cfg):
    rc = cfg["rules"]["layering"]
    tmap = {t.transfer_id: t for t in transfers}
    per_acct = defaultdict(list)
    for chain in _chains(transfers, rc):
        for tid in chain[:-1]:
            per_acct[tmap[tid].to_key].append(chain)
    out = []
    for acct, chains in per_acct.items():
        chains = sorted(set(chains))
        ts = [tmap[i] for i in chains[0]]
        path = " -> ".join([ts[0].from_key] + [t.to_key for t in ts])
        out.append(Finding(
            acct, "LAYERING", rc["weight"], f"Layering chain of {len(ts)} hops",
            f"Account is an intermediate hop in a time-ordered chain {path} spanning "
            f"{(ts[-1].ts_utc - ts[0].ts_utc).total_seconds() / 60:.0f} min with similar amounts "
            f"(INR {inr(ts[0].amount_paise):,.2f} -> INR {inr(ts[-1].amount_paise):,.2f}). Rule: >= {rc['min_hops']} hops within "
            f"{rc['max_span_hours']}h, each hop {int(rc['amount_ratio_min']*100)}-{int(rc['amount_ratio_max']*100)}% of the previous.",
            sorted({i for c in chains for i in c}), [], _utrs([tmap[i] for c in chains for i in c]),
            {"chains": [list(c) for c in chains], "path": path}, LIMITATIONS["LAYERING"]))
    return out


def rule_circular(transfers, cfg):
    rc = cfg["rules"]["circular_flow"]
    span = timedelta(hours=rc["max_span_hours"])
    out_by = _by(transfers, "from_key")
    cycles = set()

    def dfs(path):
        last = path[-1]
        for n in out_by.get(last.to_key, []):
            if n.transfer_id in {p.transfer_id for p in path} or n.ts_utc < last.ts_utc or n.ts_utc - path[0].ts_utc > span:
                continue
            if n.to_key == path[0].from_key and len(path) + 1 >= rc["min_len"]:
                cycles.add(tuple(sorted(p.transfer_id for p in path + [n])))
            elif len(path) + 1 < rc["max_len"] and n.to_key not in {p.to_key for p in path}:
                dfs(path + [n])

    for t in transfers:
        if t.from_key not in SKIP_KEYS:
            dfs([t])
    tmap = {t.transfer_id: t for t in transfers}
    per_acct = defaultdict(list)
    for c in cycles:
        for tid in c:
            for a in (tmap[tid].from_key, tmap[tid].to_key):
                if c not in per_acct[a]:
                    per_acct[a].append(c)
    out = []
    for acct, cs in per_acct.items():
        ts = sorted((tmap[i] for c in cs for i in c), key=lambda t: t.ts_utc)
        out.append(Finding(
            acct, "CIRCULAR_FLOW", rc["weight"], "Circular flow: funds return to an earlier account",
            f"Account is part of {len(cs)} time-ordered transfer cycle(s) (e.g. accounts "
            f"{', '.join(sorted({tmap[i].from_key for i in cs[0]}))}) within {rc['max_span_hours']}h. "
            f"Rule: cycle of {rc['min_len']}-{rc['max_len']} transfers returning to the starting account.",
            sorted({i for c in cs for i in c}), [], _utrs(ts), {"cycles": [list(c) for c in cs]},
            LIMITATIONS["CIRCULAR_FLOW"]))
    return out


def rule_round(transfers, cfg):
    rc = cfg["rules"]["round_figure"]
    step, mn = int(rc["step"] * 100), int(rc["min_amount"] * 100)
    window = timedelta(hours=rc["window_hours"])
    rows = defaultdict(list)
    for t in transfers:
        if t.amount_paise >= mn and t.amount_paise % step == 0:
            for a in (t.from_key, t.to_key):
                if a not in SKIP_KEYS:
                    rows[a].append(t)
    out = []
    for acct, items in rows.items():
        items.sort(key=lambda t: t.ts_utc)
        win, n = _best_window(items, window, len)
        if win and n >= rc["min_count"]:
            out.append(Finding(
                acct, "ROUND_FIGURE", rc["weight"], f"Round-figure amounts: {n} in {rc['window_hours']}h",
                f"{n} transfers of round amounts (multiples of INR {rc['step']:,}, >= INR {rc['min_amount']:,}) within "
                f"{rc['window_hours']}h: {', '.join(f'{inr(t.amount_paise):,.0f}' for t in win)}.",
                [t.transfer_id for t in win], [], _utrs(win), {"amounts_inr": [inr(t.amount_paise) for t in win]},
                LIMITATIONS["ROUND_FIGURE"]))
    return out


def run_rules(entries, transfers, cfg):
    findings = []
    findings += rule_fan(transfers, cfg, "in")
    findings += rule_fan(transfers, cfg, "out")
    findings += rule_pass_through(transfers, cfg)
    findings += rule_velocity(entries, cfg)
    findings += rule_turnover(entries, cfg)
    findings += rule_dormant(entries, cfg)
    findings += rule_layering(transfers, cfg)
    findings += rule_circular(transfers, cfg)
    findings += rule_round(transfers, cfg)
    return findings


def score_accounts(findings, cfg):
    by_acct = defaultdict(list)
    for f in findings:
        by_acct[f.account].append(f)
    hi, med = cfg["scoring"]["high"], cfg["scoring"]["medium"]
    res = []
    for acct, fs in by_acct.items():
        score = min(100, sum(f.weight for f in fs))   # one weight per rule (rules emit one finding per account)
        pr = "HIGH" if score >= hi else "MEDIUM" if score >= med else "LOW"
        res.append(AccountAssessment(acct, score, pr, sorted(fs, key=lambda f: -f.weight)))
    return sorted(res, key=lambda a: (-a.score, a.account))
