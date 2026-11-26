"""Case service: persistence (sqlite3), evidence register, hash-chained audit log, analysis runs, enrichment storage.

Audit chain = tamper-evidence only (each row hashes the previous one). It is NOT legal chain-of-custody certification.
"""
from __future__ import annotations
import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

from .config import load_config
from .ingest import ingest_file, sha256_file
from .infra.correlate import suggest_relationships
from .models import LedgerEntry, Transfer
from .rules import Finding, run_rules, score_accounts
from .trail import reconstruct
from .transfers import build_transfers

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY, case_number TEXT UNIQUE, title TEXT, is_synthetic INTEGER, created_at TEXT);
CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY, case_id INTEGER REFERENCES cases(id), filename TEXT, sha256 TEXT,
  bank_name TEXT, uploaded_at TEXT, total INTEGER, ok INTEGER, invalid INTEGER, duplicate INTEGER, UNIQUE(case_id, sha256));
CREATE TABLE IF NOT EXISTS ledger_entries(entry_id INTEGER PRIMARY KEY, case_id INTEGER, file_id INTEGER REFERENCES files(id),
  source_row_ref TEXT, account_raw TEXT, account_key TEXT, bank TEXT, ts_raw TEXT, ts_utc TEXT, direction TEXT, amount_paise INTEGER,
  balance_paise INTEGER, counterparty_raw TEXT, counterparty_key TEXT, utr TEXT, narration TEXT, status TEXT, warnings TEXT);
CREATE INDEX IF NOT EXISTS ix_le_case ON ledger_entries(case_id, account_key);
CREATE INDEX IF NOT EXISTS ix_le_utr ON ledger_entries(utr);
CREATE TABLE IF NOT EXISTS import_problems(id INTEGER PRIMARY KEY, file_id INTEGER, row_ref TEXT, code TEXT, severity TEXT, message TEXT);
CREATE TABLE IF NOT EXISTS analysis_runs(id INTEGER PRIMARY KEY, case_id INTEGER, started_at TEXT, config_json TEXT, summary_json TEXT);
CREATE TABLE IF NOT EXISTS transfers(run_id INTEGER, transfer_id INTEGER, case_id INTEGER, from_key TEXT, to_key TEXT, amount_paise INTEGER,
  ts_utc TEXT, utr TEXT, method TEXT, confidence TEXT, debit_entry_id INTEGER, credit_entry_id INTEGER, notes TEXT, PRIMARY KEY(run_id, transfer_id));
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, run_id INTEGER, case_id INTEGER, account TEXT, rule TEXT, data TEXT);
CREATE TABLE IF NOT EXISTS enrichments(case_id INTEGER, type TEXT, indicator TEXT, retrieved_at TEXT, data TEXT, PRIMARY KEY(case_id, type, indicator));
CREATE TABLE IF NOT EXISTS evidence(case_id INTEGER, evidence_id TEXT, type TEXT, description TEXT, source TEXT, sha256 TEXT,
  created_at TEXT, related TEXT, PRIMARY KEY(case_id, evidence_id));
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY, case_id INTEGER, ts TEXT, actor TEXT, action TEXT, payload TEXT, prev_hash TEXT, hash TEXT);
"""


class CaseNotFound(KeyError):
    pass


class CaseService:
    def __init__(self, db_path=":memory:", cfg=None):
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.cfg = cfg or load_config()

    # ---------- helpers ----------
    @staticmethod
    def _now():
        return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")

    def _case(self, case_id):
        r = self.db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not r:
            raise CaseNotFound(f"case {case_id} not found")
        return dict(r)

    def audit(self, case_id, action, detail, actor="investigator"):
        last = self.db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev = last["hash"] if last else "0" * 64
        payload = json.dumps({"ts": self._now(), "case_id": case_id, "actor": actor, "action": action, "detail": detail},
                             sort_keys=True, default=str)
        h = hashlib.sha256((prev + payload).encode()).hexdigest()
        self.db.execute("INSERT INTO audit_log(case_id, ts, actor, action, payload, prev_hash, hash) VALUES(?,?,?,?,?,?,?)",
                        (case_id, self._now(), actor, action, payload, prev, h))
        self.db.commit()

    def verify_audit(self):
        prev = "0" * 64
        for r in self.db.execute("SELECT * FROM audit_log ORDER BY id"):
            if r["prev_hash"] != prev or hashlib.sha256((prev + r["payload"]).encode()).hexdigest() != r["hash"]:
                return {"valid": False, "first_bad_id": r["id"]}
            prev = r["hash"]
        return {"valid": True, "note": "tamper-evidence check only; not legal chain-of-custody certification"}

    def get_audit(self, case_id):
        return [{"id": r["id"], "ts": r["ts"], "actor": r["actor"], "action": r["action"], "detail": json.loads(r["payload"])["detail"],
                 "hash": r["hash"]} for r in self.db.execute("SELECT * FROM audit_log WHERE case_id=? ORDER BY id", (case_id,))]

    def _evidence(self, case_id, etype, description, source="", sha256="", related=None):
        n = self.db.execute("SELECT COUNT(*) FROM evidence WHERE case_id=?", (case_id,)).fetchone()[0] + 1
        eid = f"EV-{n:04d}"
        self.db.execute("INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?)",
                        (case_id, eid, etype, description, source, sha256, self._now(), json.dumps(related or {})))
        return eid

    def get_evidence(self, case_id):
        self._case(case_id)
        return [{**dict(r), "related": json.loads(r["related"])} for r in
                self.db.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY evidence_id", (case_id,))]

    # ---------- cases ----------
    def create_case(self, title, case_number=None, is_synthetic=True):
        cur = self.db.execute("INSERT INTO cases(case_number, title, is_synthetic, created_at) VALUES(?,?,?,?)",
                              (case_number or f"TMP-{self._now()}", title, int(is_synthetic), self._now()))
        cid = cur.lastrowid
        if not case_number:
            self.db.execute("UPDATE cases SET case_number=? WHERE id=?", (f"CASE-{cid:04d}", cid))
        self.db.commit()
        self.audit(cid, "CASE_CREATED", {"title": title, "synthetic": is_synthetic})
        return cid

    def get_case(self, case_id):
        c = self._case(case_id)
        c["files"] = [dict(r) for r in self.db.execute("SELECT * FROM files WHERE case_id=?", (case_id,))]
        c["is_synthetic"] = bool(c["is_synthetic"])
        return c

    def list_cases(self):
        return [dict(r) for r in self.db.execute("SELECT id, case_number, title, is_synthetic, created_at FROM cases ORDER BY id")]

    # ---------- statements ----------
    def add_statement(self, case_id, path, bank_name="UNSPECIFIED", default_account=None):
        self._case(case_id)
        path = Path(path)
        sha = sha256_file(path)
        dup = self.db.execute("SELECT id FROM files WHERE case_id=? AND sha256=?", (case_id, sha)).fetchone()
        if dup:
            self.audit(case_id, "FILE_REJECTED_DUPLICATE", {"filename": path.name, "sha256": sha, "existing_file_id": dup["id"]})
            return {"status": "duplicate_file", "file_id": dup["id"], "message": "identical file already imported in this case"}
        start = self.db.execute("SELECT COALESCE(MAX(entry_id),0)+1 FROM ledger_entries").fetchone()[0]
        res = ingest_file(path, self.cfg, bank_name=bank_name, default_account=default_account, start_id=start)
        c = res.counts()
        fid = self.db.execute("INSERT INTO files(case_id, filename, sha256, bank_name, uploaded_at, total, ok, invalid, duplicate) VALUES(?,?,?,?,?,?,?,?,?)",
                              (case_id, path.name, sha, bank_name, self._now(), c["total"], c["ok"], c["invalid"], c["duplicate"])).lastrowid
        self.db.executemany("INSERT INTO ledger_entries VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", [
            (e.entry_id, case_id, fid, e.source_row_ref, e.account_raw, e.account_key, e.bank, e.ts_raw,
             e.ts_utc.isoformat() if e.ts_utc else None, e.direction, e.amount_paise, e.balance_paise, e.counterparty_raw,
             e.counterparty_key, e.utr, e.narration, e.status, json.dumps(e.warnings)) for e in res.entries])
        self.db.executemany("INSERT INTO import_problems(file_id, row_ref, code, severity, message) VALUES(?,?,?,?,?)",
                            [(fid, p["row_ref"], p["code"], p["severity"], p["message"]) for p in res.problems])
        eid = self._evidence(case_id, "bank_statement", f"Statement {path.name} ({c['total']} rows)", path.name, sha,
                             {"file_id": fid, "counts": c})
        self.db.commit()
        self.audit(case_id, "FILE_IMPORTED", {"file_id": fid, "filename": path.name, "sha256": sha, "counts": c, "evidence_id": eid})
        return {"status": "imported", "file_id": fid, "evidence_id": eid, "counts": c, "problem_count": len(res.problems)}

    def get_problems(self, case_id):
        self._case(case_id)
        return [dict(r) for r in self.db.execute(
            "SELECT f.filename, p.row_ref, p.code, p.severity, p.message FROM import_problems p JOIN files f ON f.id=p.file_id "
            "WHERE f.case_id=? ORDER BY p.id", (case_id,))]

    def get_entries(self, case_id, status=None, account=None):
        self._case(case_id)
        q, a = "SELECT * FROM ledger_entries WHERE case_id=?", [case_id]
        if status:
            q += " AND status=?"; a.append(status)
        if account:
            q += " AND account_key=?"; a.append(account.upper())
        return [dict(r) for r in self.db.execute(q + " ORDER BY entry_id", a)]

    def _load_entries(self, case_id):
        out = []
        for r in self.db.execute("SELECT f.filename, l.* FROM ledger_entries l JOIN files f ON f.id=l.file_id WHERE l.case_id=? ORDER BY l.entry_id", (case_id,)):
            out.append(LedgerEntry(r["entry_id"], r["filename"], r["source_row_ref"], r["account_raw"], r["account_key"], r["bank"],
                                   r["ts_raw"], datetime.fromisoformat(r["ts_utc"]) if r["ts_utc"] else None, r["direction"],
                                   r["amount_paise"], r["balance_paise"], r["counterparty_raw"], r["counterparty_key"], r["utr"],
                                   r["narration"], r["status"], json.loads(r["warnings"])))
        return out

    # ---------- analysis ----------
    def run_analysis(self, case_id):
        self._case(case_id)
        entries = self._load_entries(case_id)
        if not entries:
            raise ValueError("no statements imported for this case")
        transfers, unresolved = build_transfers(entries)
        findings = run_rules(entries, transfers, self.cfg)
        assess = score_accounts(findings, self.cfg)
        summary = {"entries": len(entries), "usable_entries": sum(e.usable for e in entries), "transfers": len(transfers),
                   "unresolved_entries": len(unresolved), "findings": len(findings), "accounts_flagged": len(assess),
                   "by_method": {m: sum(t.method == m for t in transfers) for m in ("utr_both_sides", "utr_one_side", "counterparty_only")}}
        run = self.db.execute("INSERT INTO analysis_runs(case_id, started_at, config_json, summary_json) VALUES(?,?,?,?)",
                              (case_id, self._now(), json.dumps(self.cfg), json.dumps(summary))).lastrowid
        self.db.executemany("INSERT INTO transfers VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", [
            (run, t.transfer_id, case_id, t.from_key, t.to_key, t.amount_paise, t.ts_utc.isoformat(), t.utr, t.method, t.confidence,
             t.debit_entry_id, t.credit_entry_id, json.dumps(t.notes)) for t in transfers])
        self.db.executemany("INSERT INTO findings(run_id, case_id, account, rule, data) VALUES(?,?,?,?,?)",
                            [(run, case_id, f.account, f.rule, json.dumps(asdict(f), default=str)) for f in findings])
        eid = self._evidence(case_id, "analysis_run", f"Analysis run {run}: {len(findings)} indicators on {len(assess)} accounts",
                             related={"run_id": run, "summary": summary})
        self.db.commit()
        self.audit(case_id, "ANALYSIS_RUN", {"run_id": run, "summary": summary, "evidence_id": eid})
        return {"run_id": run, **summary}

    def _latest_run(self, case_id):
        r = self.db.execute("SELECT id, config_json FROM analysis_runs WHERE case_id=? ORDER BY id DESC LIMIT 1", (case_id,)).fetchone()
        if not r:
            raise ValueError("no analysis run yet; run analysis first")
        return r["id"], json.loads(r["config_json"])

    def get_run_summary(self, case_id):
        self._case(case_id)
        r = self.db.execute("SELECT * FROM analysis_runs WHERE case_id=? ORDER BY id DESC LIMIT 1", (case_id,)).fetchone()
        if not r:
            raise ValueError("no analysis run yet; run analysis first")
        return {"run_id": r["id"], "started_at": r["started_at"], "config": json.loads(r["config_json"]),
                "summary": json.loads(r["summary_json"])}

    def get_transfers(self, case_id):
        run, _ = self._latest_run(case_id)
        return [Transfer(r["transfer_id"], r["from_key"], r["to_key"], r["amount_paise"], datetime.fromisoformat(r["ts_utc"]), r["utr"],
                         r["method"], r["confidence"], r["debit_entry_id"], r["credit_entry_id"], json.loads(r["notes"]))
                for r in self.db.execute("SELECT * FROM transfers WHERE run_id=? ORDER BY transfer_id", (run,))]

    def get_findings(self, case_id):
        run, _ = self._latest_run(case_id)
        return [Finding(**json.loads(r["data"])) for r in self.db.execute("SELECT data FROM findings WHERE run_id=? ORDER BY id", (run,))]

    def get_assessments(self, case_id):
        _, cfg = self._latest_run(case_id)
        return [{"account": a.account, "score": a.score, "priority": a.priority, "rules": a.rules, "disclaimer": a.disclaimer,
                 "findings": [asdict(f) for f in a.findings]} for a in score_accounts(self.get_findings(case_id), cfg)]

    def trail(self, case_id, utr=None, account=None, max_hops=None):
        _, cfg = self._latest_run(case_id)
        res = reconstruct(self.get_transfers(case_id), cfg, utr=utr, account=account.upper() if account else None, max_hops=max_hops)
        self.audit(case_id, "TRAIL_QUERIED", {"utr": utr, "account": account, "max_hops": max_hops, "paths": len(res["paths"])})
        return res

    # ---------- infrastructure intelligence ----------
    def enrich(self, case_id, enricher, domains=(), ips=()):
        self._case(case_id)
        res = enricher.enrich_all(domains, ips)
        for e in res:
            when = max((o["retrieved_at"] for o in e["observations"].values() if o["retrieved_at"]), default=self._now())
            self.db.execute("INSERT OR REPLACE INTO enrichments VALUES(?,?,?,?,?)", (case_id, e["type"], e["indicator"], when, json.dumps(e, default=str)))
            eid = self._evidence(case_id, "domain_ip_intel", f"Passive intelligence for {e['type']} {e['indicator']}",
                                 related={"statuses": {k: v["status"] for k, v in e["observations"].items()}})
        self.db.commit()
        self.audit(case_id, "ENRICHMENT_RUN", {"domains": list(domains), "ips": list(ips), "indicators_stored": len(res)})
        return {"stored": len(res)}

    def get_enrichments(self, case_id):
        self._case(case_id)
        return [json.loads(r["data"]) for r in self.db.execute("SELECT data FROM enrichments WHERE case_id=? ORDER BY type, indicator", (case_id,))]

    def get_relationships(self, case_id):
        return suggest_relationships(self.get_enrichments(case_id))


def seed_demo(svc, data_dir):
    """Creates a clearly-labelled SYNTHETIC demo case: statements + analysis + fixture-based infrastructure intel."""
    from .infra.cache import Cache
    from .infra.enrich import Enricher
    from .infra.fixtures import DEMO_NOW, DOMAINS, FakeHttp
    data_dir = Path(data_dir)
    cid = svc.create_case("DEMO (synthetic): victim-to-mule investigation", is_synthetic=True)
    svc.add_statement(cid, data_dir / "statements_all.csv", bank_name="SYNTH-BANK (synthetic)")
    svc.run_analysis(cid)
    svc.enrich(cid, Enricher(FakeHttp(), Cache(":memory:"), svc.cfg, now=DEMO_NOW), domains=DOMAINS)
    return cid
