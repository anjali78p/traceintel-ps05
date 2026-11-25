"""Multi-hop money-trail reconstruction from actual transfer records.

Rules: (1) paths are time-respecting (each hop at/after the previous one, within max_gap);
(2) every transfer stays an individual edge; (3) results are POSSIBLE transaction paths, never proven
fund movement. 'carried' is an upper bound (min of amounts along the path); 'commingled' marks hops where the
account also received other money shortly before forwarding, so attribution is ambiguous.
"""
from __future__ import annotations
from collections import defaultdict
from datetime import timedelta

from .models import inr

LABEL = "Possible transaction paths reconstructed from records; not proven fund movement."


def reconstruct(transfers, cfg, utr=None, account=None, max_hops=None):
    tc = cfg["trail"]
    max_hops = max_hops or tc["max_hops"]
    max_gap = timedelta(hours=tc["max_gap_hours"])
    lookback = timedelta(hours=tc["lookback_hours"])
    tmap = {t.transfer_id: t for t in transfers}
    out_by, in_by = defaultdict(list), defaultdict(list)
    for t in sorted(transfers, key=lambda t: (t.ts_utc, t.transfer_id)):
        out_by[t.from_key].append(t)
        in_by[t.to_key].append(t)

    if utr:
        seeds = [t for t in transfers if t.utr == utr]
    elif account:
        seeds = list(out_by.get(account, []))
    else:
        raise ValueError("provide utr or account")
    if not seeds:
        return {"found": False, "label": LABEL, "paths": [], "graph": {"nodes": [], "edges": []},
                "message": "No transfer matches the given UTR/account."}

    raw_paths, truncated = [], False

    def dfs(path):
        nonlocal truncated
        if len(raw_paths) >= tc["max_paths"]:
            truncated = True
            return
        last = path[-1]
        in_path = {path[0].from_key} | {t.to_key for t in path}
        ids = {t.transfer_id for t in path}
        nxt = []
        if len(path) < max_hops:
            nxt = [n for n in out_by.get(last.to_key, []) if n.transfer_id not in ids
                   and last.ts_utc <= n.ts_utc <= last.ts_utc + max_gap]
        if not nxt:
            raw_paths.append((path, False))
            return
        for n in nxt:
            if n.to_key in in_path:
                raw_paths.append((path + [n], True))   # loop closes: stop here
            else:
                dfs(path + [n])

    for s in seeds:
        dfs([s])

    paths = []
    for path, circular in raw_paths:
        carried, ambiguous = [path[0].amount_paise], []
        for i in range(1, len(path)):
            carried.append(min(carried[-1], path[i].amount_paise))
            arrival, leave = path[i - 1], path[i]
            others = [x for x in in_by.get(leave.from_key, []) if x.transfer_id != arrival.transfer_id
                      and arrival.ts_utc - lookback <= x.ts_utc <= leave.ts_utc]
            if others:
                ambiguous.append({"hop": i, "account": leave.from_key, "other_inflow_count": len(others),
                                  "other_inflow_inr": inr(sum(x.amount_paise for x in others))})
        paths.append({
            "transfer_ids": [t.transfer_id for t in path],
            "accounts": [path[0].from_key] + [t.to_key for t in path],
            "hops": len(path), "circular": circular,
            "span_minutes": round((path[-1].ts_utc - path[0].ts_utc).total_seconds() / 60, 1),
            "carried_upper_bound_inr": [inr(c) for c in carried],
            "commingled_hops": ambiguous,
            "attribution": "commingled - ambiguous" if ambiguous else "single-source on this path",
            "min_method": min((t.method for t in path), key=lambda m: ["utr_both_sides", "utr_one_side", "counterparty_only"].index(m)),
        })
    paths.sort(key=lambda p: (-p["hops"], p["transfer_ids"]))

    used = sorted({i for p in paths for i in p["transfer_ids"]})
    nodes = defaultdict(lambda: {"in": set(), "out": set()})
    for i in used:
        t = tmap[i]
        nodes[t.from_key]["out"].add(i)
        nodes[t.to_key]["in"].add(i)
    start_acc = {s.from_key for s in seeds}
    graph_nodes = []
    for a, d in sorted(nodes.items()):
        roles = []
        if a in start_acc and not d["in"]:
            roles.append("origin")
        if len(d["in"]) >= 2:
            roles.append("convergence")
        if len(d["out"]) >= tc["dispersal_min_out"]:
            roles.append("dispersal")
        if d["in"] and not d["out"]:
            roles.append("terminal")
        graph_nodes.append({"id": a, "roles": roles, "in_edges": len(d["in"]), "out_edges": len(d["out"])})
    edges = [{"id": f"T{i}", "transfer_id": i, "source": tmap[i].from_key, "target": tmap[i].to_key,
              "amount_inr": inr(tmap[i].amount_paise), "ts_utc": tmap[i].ts_utc.isoformat(), "utr": tmap[i].utr,
              "method": tmap[i].method, "confidence": tmap[i].confidence,
              "observed": tmap[i].method == "utr_both_sides"} for i in used]
    return {"found": True, "label": LABEL, "seed_transfer_ids": [s.transfer_id for s in seeds], "paths": paths,
            "truncated": truncated, "graph": {"nodes": graph_nodes, "edges": edges},
            "params": {"max_hops": max_hops, "max_gap_hours": tc["max_gap_hours"], "lookback_hours": tc["lookback_hours"]}}
