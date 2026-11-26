import tempfile
import unittest
from pathlib import Path

import pdfplumber
from openpyxl import load_workbook

from traceintel import synthetic as S
from traceintel.config import load_config
from traceintel.ingest import sha256_file
from traceintel.reporting import collect, generate_reports
from traceintel.service import CaseService, seed_demo

DATA = Path(__file__).resolve().parent.parent / "data" / "synthetic"
CFG = load_config()


def setUpModule():
    S.generate(DATA)


class Report(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.svc = CaseService(":memory:", CFG)
        cls.cid = seed_demo(cls.svc, DATA)
        cls.paths = generate_reports(cls.svc, cls.cid, cls.tmp.name, victim_utr=S.VICTIM_UTR)
        with pdfplumber.open(cls.paths["pdf"]) as pdf:
            cls.pages = len(pdf.pages)
            cls.text = "\n".join(p.extract_text() or "" for p in pdf.pages)
        cls.wb = load_workbook(cls.paths["xlsx"])
        cls.data = collect(cls.svc, cls.cid, S.VICTIM_UTR)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_pdf_has_all_sections(self):
        self.assertGreaterEqual(self.pages, 5)
        for h in ("1. Case overview", "2. Data sources", "3. Transaction summary", "4. Suspicious account indicators",
                  "5. Money-trail reconstruction", "6. Digital infrastructure findings", "7. Entity relationships",
                  "8. Evidence references", "9. Methodology and limitations", "10. Investigator review notes", "Appendix A"):
            self.assertIn(h, self.text, h)

    def test_pdf_content_and_honest_labels(self):
        for needle in ("MULE01", S.VICTIM_UTR, "VICTIM01 -> MULE01 -> MULE02 -> MULE03 -> CASHOUT01", "not proven fund movement",
                       "[FACT]", "[INDICATOR]", "[SUGGESTED]", "[INVESTIGATOR]", "SYNTHETIC", "NOT established automatically",
                       "not legal chain-of-custody", "indicative", "No active scanning"):
            self.assertIn(needle, self.text, needle)
        self.assertNotRegex(self.text.lower(), r"\bguilty\b|\bconvicted\b|\bcriminal\b")

    def test_commingling_and_observed_vs_unverified_shown(self):
        self.assertIn("Exact attribution of the forwarded amount is not possible", self.text.replace("\n", " "))
        self.assertIn("FACT: both", self.text)

    def test_excel_sheets_and_row_counts(self):
        names = self.wb.sheetnames
        for n in ("Overview", "Accounts", "Findings", "Transfers", "Money trail", "Infrastructure", "Relationships", "Evidence",
                  "Import problems", "Draft requests", "Audit", "Methodology"):
            self.assertIn(n, names)
        ws = self.wb["Transfers"]
        self.assertEqual(ws.max_row - 1, len(self.data["transfers"]))              # header on row 1
        nf = sum(len(a["findings"]) for a in self.data["assessments"])
        self.assertEqual(self.wb["Findings"].max_row - 1, nf)                       # no note row on this sheet
        self.assertEqual(self.wb["Draft requests"].max_row - 3, len(self.data["requests"]))   # note + header rows
        self.assertIn("not proven fund movement", self.wb["Money trail"]["A1"].value)

    def test_excel_values_not_placeholders(self):
        rows = list(self.wb["Accounts"].iter_rows(min_row=2, values_only=True))
        self.assertEqual(rows[0][0], "MULE01"); self.assertEqual(rows[0][2], 100)

    def test_reports_registered_as_evidence_with_correct_hash_and_audited(self):
        ev = [e for e in self.svc.get_evidence(self.cid) if e["type"] == "report"]
        self.assertEqual(len(ev), 3)
        by_name = {e["source"]: e["sha256"] for e in ev}
        for p in self.paths.values():
            self.assertEqual(by_name[Path(p).name], sha256_file(p))
        self.assertEqual(sum(a["action"] == "REPORT_GENERATED" for a in self.svc.get_audit(self.cid)), 3)
        self.assertTrue(self.svc.verify_audit()["valid"])


class Requests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.svc = CaseService(":memory:", CFG)
        cls.cid = seed_demo(cls.svc, DATA)
        cls.reqs = collect(cls.svc, cls.cid, S.VICTIM_UTR)["requests"]
        cls.by = {}
        for r in cls.reqs:
            cls.by.setdefault(r["type"], []).append(r)

    def test_counts_by_type(self):
        self.assertEqual({k: len(v) for k, v in self.by.items()}, {"bank": 2, "registrar": 3, "hosting": 2})
        # banks: the synthetic bank plus an unidentified-bank group (FANOUT accounts have no statement)

    def test_every_draft_is_a_draft_through_lawful_process(self):
        for r in self.reqs:
            b = r["body"]
            self.assertIn("DRAFT - NOT ISSUED", b); self.assertIn("authorised officer", b)
            self.assertIn("lawful process", b); self.assertIn("[FIR NO.]", b); self.assertIn("SYNTHETIC DEMO", b)

    def test_bank_draft_has_utr_and_both_time_zones(self):
        b = next(r for r in self.by["bank"] if "SYNTH-BANK" in r["to"])["body"]
        self.assertIn(S.VICTIM_UTR, b)
        self.assertIn("2026-03-10 10:00:00 IST (2026-03-10 04:30:00 UTC)", b)
        self.assertIn("seen in both statements", b)
        self.assertIn("does not request or perform one", b)                       # tool never freezes funds

    def test_unverified_one_side_edges_labelled(self):
        b = next(r for r in self.by["bank"] if "to be identified" in r["to"])["body"]
        self.assertIn("unverified", b)

    def test_registrar_and_hosting_drafts(self):
        for r in self.by["registrar"]:
            self.assertEqual(r["to"], "Example Registrar Inc.")
            self.assertIn("Registrant, administrative and technical contact", r["body"])
        h = self.by["hosting"][0]["body"]
        self.assertIn("NAT/CGNAT/shared hosting", h); self.assertIn("indicative only", h); self.assertIn("ADJUST TO EXACT INCIDENT", h)

    def test_non_public_never_called_public(self):
        for r in self.reqs:
            self.assertNotIn("publicly available subscriber", r["body"].lower())


class Edge(unittest.TestCase):
    def test_report_without_trail_has_no_bank_drafts(self):
        svc = CaseService(":memory:", CFG); cid = seed_demo(svc, DATA)
        d = collect(svc, cid, None)
        self.assertNotIn("bank", {r["type"] for r in d["requests"]})
        with tempfile.TemporaryDirectory() as t:
            p = generate_reports(svc, cid, t)
            with pdfplumber.open(p["pdf"]) as pdf:
                txt = "\n".join(pg.extract_text() or "" for pg in pdf.pages)
            self.assertIn("trail not reconstructed", txt)

    def test_non_synthetic_case_not_labelled_synthetic(self):
        svc = CaseService(":memory:", CFG)
        cid = svc.create_case("real-format test", is_synthetic=False)
        svc.add_statement(cid, DATA / "statements_all.csv"); svc.run_analysis(cid)
        with tempfile.TemporaryDirectory() as t:
            with pdfplumber.open(generate_reports(svc, cid, t, S.VICTIM_UTR)["pdf"]) as pdf:
                txt = "\n".join(pg.extract_text() or "" for pg in pdf.pages)
        self.assertNotIn("SYNTHETIC / DEMO DATA", txt)

    def test_requires_analysis(self):
        svc = CaseService(":memory:", CFG); cid = svc.create_case("x")
        with self.assertRaises(ValueError):
            collect(svc, cid)

    def test_unknown_utr_graceful(self):
        svc = CaseService(":memory:", CFG); cid = seed_demo(svc, DATA)
        with tempfile.TemporaryDirectory() as t:
            with pdfplumber.open(generate_reports(svc, cid, t, "000000000000")["pdf"]) as pdf:
                txt = "\n".join(pg.extract_text() or "" for pg in pdf.pages)
        self.assertIn("No transfer matches UTR", txt)


if __name__ == "__main__":
    unittest.main()
