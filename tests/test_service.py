import unittest
from pathlib import Path

from traceintel import synthetic as S
from traceintel.config import load_config
from traceintel.ingest import sha256_file
from traceintel.infra.cache import Cache
from traceintel.infra.enrich import Enricher
from traceintel.infra.fixtures import DEMO_NOW, DOMAINS, FakeHttp
from traceintel.pipeline import analyze_files
from traceintel.service import CaseNotFound, CaseService, seed_demo

DATA = Path(__file__).resolve().parent.parent / "data" / "synthetic"
CFG = load_config()


def setUpModule():
    S.generate(DATA)


def fresh():
    svc = CaseService(":memory:", CFG)
    cid = svc.create_case("test case")
    return svc, cid


class Cases(unittest.TestCase):
    def test_create_and_list(self):
        svc, cid = fresh()
        self.assertEqual(svc.get_case(cid)["case_number"], f"CASE-{cid:04d}")
        self.assertTrue(svc.get_case(cid)["is_synthetic"])
        self.assertEqual(len(svc.list_cases()), 1)

    def test_unknown_case(self):
        svc, _ = fresh()
        for fn in (svc.get_case, svc.run_analysis, svc.get_evidence, svc.get_problems):
            with self.assertRaises(CaseNotFound):
                fn(999)


class Import(unittest.TestCase):
    def test_import_stores_rows_problems_evidence(self):
        svc, cid = fresh()
        r = svc.add_statement(cid, DATA / "dirty_sample.csv")
        self.assertEqual(r["status"], "imported"); self.assertEqual(r["counts"]["total"], 7)
        self.assertEqual({e["status"] for e in svc.get_entries(cid)}, {"ok", "invalid", "duplicate"})
        self.assertEqual(len(svc.get_entries(cid, status="invalid")), 2)           # kept, not dropped
        codes = {p["code"] for p in svc.get_problems(cid)}
        self.assertTrue({"INVALID_DATE", "MISSING_AMOUNT", "BALANCE_MISMATCH"} <= codes)
        ev = svc.get_evidence(cid)[0]
        self.assertEqual((ev["type"], ev["sha256"]), ("bank_statement", sha256_file(DATA / "dirty_sample.csv")))

    def test_duplicate_file_rejected_and_audited(self):
        svc, cid = fresh()
        svc.add_statement(cid, DATA / "statements_all.csv")
        r = svc.add_statement(cid, DATA / "statements_all.csv")
        self.assertEqual(r["status"], "duplicate_file")
        self.assertEqual(svc.db.execute("SELECT COUNT(*) FROM ledger_entries").fetchone()[0], 57)
        self.assertIn("FILE_REJECTED_DUPLICATE", [a["action"] for a in svc.get_audit(cid)])

    def test_same_file_allowed_in_different_case(self):
        svc, c1 = fresh(); c2 = svc.create_case("other")
        svc.add_statement(c1, DATA / "dirty_sample.csv")
        self.assertEqual(svc.add_statement(c2, DATA / "dirty_sample.csv")["status"], "imported")
        ids = [e["entry_id"] for e in svc.get_entries(c1)] + [e["entry_id"] for e in svc.get_entries(c2)]
        self.assertEqual(len(ids), len(set(ids)))                                    # globally unique entry ids

    def test_multi_file_case_pdf_and_xlsx(self):
        svc, cid = fresh()
        svc.add_statement(cid, DATA / "statement_MULE02.pdf", default_account="MULE02")
        svc.add_statement(cid, DATA / "statement_SALARY01_narration_only.xlsx", default_account="SALARY01")
        self.assertEqual(len(svc.get_case(cid)["files"]), 2)


class Analysis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.svc, cls.cid = fresh()
        cls.svc.add_statement(cls.cid, DATA / "statements_all.csv")
        cls.summary = cls.svc.run_analysis(cls.cid)
        cls.direct = analyze_files([DATA / "statements_all.csv"], CFG)

    def test_persisted_results_equal_direct_pipeline(self):
        self.assertEqual(self.summary["transfers"], len(self.direct["transfers"]))
        stored = {(a["account"], tuple(a["rules"]), a["score"]) for a in self.svc.get_assessments(self.cid)}
        direct = {(a.account, tuple(a.rules), a.score) for a in self.direct["assessments"]}
        self.assertEqual(stored, direct)
        self.assertEqual([t.transfer_id for t in self.svc.get_transfers(self.cid)], [t.transfer_id for t in self.direct["transfers"]])

    def test_trail_from_database(self):
        tr = self.svc.trail(self.cid, utr=S.VICTIM_UTR)
        self.assertIn(S.CHAIN, [p["accounts"] for p in tr["paths"]])
        self.assertEqual(self.svc.trail(self.cid, account="victim01")["found"], True)    # case-insensitive account

    def test_analysis_requires_import_and_trail_requires_analysis(self):
        svc, cid = fresh()
        with self.assertRaises(ValueError): svc.run_analysis(cid)
        with self.assertRaises(ValueError): svc.trail(cid, utr="1")

    def test_rerun_creates_new_run_and_keeps_history(self):
        svc, cid = fresh()
        svc.add_statement(cid, DATA / "statements_all.csv")
        r1 = svc.run_analysis(cid); r2 = svc.run_analysis(cid)
        self.assertEqual(r2["run_id"], r1["run_id"] + 1)
        self.assertEqual(svc.db.execute("SELECT COUNT(*) FROM analysis_runs").fetchone()[0], 2)
        self.assertEqual(len(svc.get_findings(cid)), r2["findings"])

    def test_run_records_config_used(self):
        import json
        row = self.svc.db.execute("SELECT config_json FROM analysis_runs").fetchone()
        self.assertEqual(json.loads(row[0])["rules"]["fan_in"]["min_distinct_counterparties"], 5)


class AuditAndEnrichment(unittest.TestCase):
    def test_audit_chain_valid_then_detects_tampering(self):
        svc, cid = fresh()
        svc.add_statement(cid, DATA / "dirty_sample.csv")
        self.assertTrue(svc.verify_audit()["valid"])
        actions = [a["action"] for a in svc.get_audit(cid)]
        self.assertEqual(actions, ["CASE_CREATED", "FILE_IMPORTED"])
        svc.db.execute("UPDATE audit_log SET payload=replace(payload,'dirty_sample','forged') WHERE action='FILE_IMPORTED'"); svc.db.commit()
        v = svc.verify_audit(); self.assertFalse(v["valid"]); self.assertIsNotNone(v["first_bad_id"])

    def test_enrichment_stored_and_relationships_recomputed(self):
        svc, cid = fresh()
        enr = Enricher(FakeHttp(), Cache(), CFG, now=DEMO_NOW)
        self.assertEqual(svc.enrich(cid, enr, domains=DOMAINS)["stored"], 5)        # 3 domains + 2 resolved IPs
        kinds = {r["type"] for r in svc.get_relationships(cid)}
        self.assertEqual(kinds, {"shared_ip", "shared_nameserver", "shared_asn", "shared_certificate"})
        self.assertEqual(len(svc.get_enrichments(cid)), 5)
        svc.enrich(cid, enr, domains=[DOMAINS[0]])                                    # re-run: upsert, no duplicates
        self.assertEqual(len(svc.get_enrichments(cid)), 5)
        self.assertEqual(sum(e["type"] == "domain_ip_intel" for e in svc.get_evidence(cid)), 7)   # evidence keeps history

    def test_seed_demo_end_to_end(self):
        svc = CaseService(":memory:", CFG)
        cid = seed_demo(svc, DATA)
        self.assertTrue(svc.get_case(cid)["is_synthetic"])
        self.assertIn("DEMO (synthetic)", svc.get_case(cid)["title"])
        self.assertIn("MULE01", [a["account"] for a in svc.get_assessments(cid)])
        self.assertTrue(svc.get_relationships(cid)); self.assertTrue(svc.verify_audit()["valid"])
        self.assertEqual({e["type"] for e in svc.get_evidence(cid)}, {"bank_statement", "analysis_run", "domain_ip_intel"})


if __name__ == "__main__":
    unittest.main()
