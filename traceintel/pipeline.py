from __future__ import annotations
from pathlib import Path

from .ingest import ingest_file
from .transfers import build_transfers
from .rules import run_rules, score_accounts
from .trail import reconstruct


def analyze_files(paths, cfg, default_accounts=None):
    """paths -> dict(entries, problems, transfers, findings, assessments). Entry ids are unique across files."""
    default_accounts = default_accounts or {}
    entries, problems, files, nxt = [], [], [], 1
    for p in paths:
        r = ingest_file(p, cfg, default_account=default_accounts.get(Path(p).name), start_id=nxt)
        nxt += len(r.entries)
        entries += r.entries
        problems += [{**x, "file": r.file_name} for x in r.problems]
        files.append({"file": r.file_name, "sha256": r.sha256, **r.counts()})
    transfers, unresolved = build_transfers(entries)
    findings = run_rules(entries, transfers, cfg)
    return {"files": files, "entries": entries, "problems": problems, "transfers": transfers,
            "unresolved": unresolved, "findings": findings, "assessments": score_accounts(findings, cfg)}
