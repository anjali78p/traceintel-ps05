import tempfile
import unittest
from pathlib import Path

import pdfplumber
from openpyxl import load_workbook

from traceintel import synthetic as S
from traceintel.config import load_config
from traceintel.infra.fixtures import DOMAINS
from traceintel.reporting import generate_reports
from traceintel.service import CaseService, seed_demo

DATA = Path(__file__).resolve().parent.parent / "data" / "synthetic"
CFG = load_config()
A, B, H = DOMAINS
GOOD = dict(from_type="account", from_value="MULE01", to_type="domain", to_value=A, relation="payment_instruction_on_site",
            explanation="Victim complaint says the KYC page told them to pay MULE01.", source_note="Victim complaint p.2, screenshot of payment page")


def setUpModule():
    S.generate(DATA)


def demo():
    svc = CaseService(":memory:", CFG)
    return svc, seed_demo(svc, DATA)


class Add(unittest.TestCase):
    def test_link_stored_with_evidence_audit_and_origin(self):
        svc, cid = demo(); n0 = len(svc.get_evidence(cid))
        lid = svc.add_link(cid, **GOOD, observed_at="2026-03-10 10:05")
        l = svc.get_links(cid)[0]
        self.assertEqual((l["id"], l["status"], l["confidence"]), (lid, "active", "unverified"))
        self.assertEqual(l["observed_at_utc"], "2026-03-10T04:35:00")                      # IST input -> UTC
        ev = svc.get_evidence(cid)
        self.assertEqual(len(ev), n0 + 1); self.assertEqual(ev[-1]["type"], "investigator_note"); self.assertEqual(l["evidence_id"], ev[-1]["evidence_id"])
        a = [x for x in svc.get_audit(cid) if x["action"] == "LINK_ADDED"][0]
        self.assertEqual(a["detail"]["origin"], "investigator_entered"); self.assertTrue(svc.verify_audit()["valid"])

    def test_timezone_aware_input(self):
        svc, cid = demo()
        svc.add_link(cid, **GOOD, observed_at="2026-03-10T10:05:00+05:30")
        self.assertEqual(svc.get_links(cid)[0]["observed_at_utc"], "2026-03-10T04:35:00")

    def test_existing_evidence_can_be_cited_and_corroborate(self):
        svc, cid = demo()
        g = {k: v for k, v in GOOD.items() if k != "source_note"}
        svc.add_link(cid, **g, evidence_id="EV-0001", confidence="corroborated")
        self.assertEqual(svc.get_links(cid)[0]["confidence"], "corroborated")

    def test_validation_rules(self):
        svc, cid = demo()
        bad = [dict(from_type="domain"), dict(to_type="account"), dict(relation="made_up"), dict(to_value="not a domain"),
               dict(to_type="ip", to_value="999.1.1.1"), dict(explanation="  "), dict(source_note=None),
               dict(evidence_id="EV-9999"), dict(confidence="corroborated"), dict(confidence="certain"), dict(from_value=""),
               dict(observed_at="yesterday-ish")]
        for b in bad:
            with self.assertRaises(ValueError, msg=str(b)):
                svc.add_link(cid, **{**GOOD, **b})
        self.assertEqual(svc.get_links(cid), [])                                            # nothing stored
        self.assertEqual(sum(a["action"] == "LINK_ADDED" for a in svc.get_audit(cid)), 0)

    def test_duplicate_active_link_rejected(self):
        svc, cid = demo(); svc.add_link(cid, **GOOD)
        with self.assertRaises(ValueError):
            svc.add_link(cid, **GOOD)

    def test_normalisation(self):
        svc, cid = demo()
        svc.add_link(cid, **{**GOOD, "from_value": " mule-01 ", "to_value": A.upper() + "."})
        l = svc.get_links(cid)[0]; self.assertEqual((l["from_value"], l["to_value"]), ("MULE01", A))

    def test_unknown_case(self):
        svc, _ = demo()
        with self.assertRaises(KeyError):
            svc.add_link(999, **GOOD)


class Retract(unittest.TestCase):
    def test_retract_keeps_history(self):
        svc, cid = demo(); lid = svc.add_link(cid, **GOOD)
        with self.assertRaises(ValueError): svc.retract_link(cid, lid, " ")
        svc.retract_link(cid, lid, "Complaint was about a different page")
        self.assertEqual(svc.get_links(cid), [])
        self.assertEqual(svc.get_links(cid, include_retracted=True)[0]["status"], "retracted")
        self.assertEqual(svc.get_links(cid, include_retracted=True)[0]["retract_reason"], "Complaint was about a different page")
        self.assertIn("LINK_RETRACTED", [a["action"] for a in svc.get_audit(cid)])
        with self.assertRaises(ValueError): svc.retract_link(cid, lid, "again")
        with self.assertRaises(ValueError): svc.retract_link(cid, 999, "x")
        svc.add_link(cid, **GOOD)                                                          # same link may be re-entered after retraction


class Context(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.svc, cls.cid = demo()
        cls.svc.add_link(cls.cid, **GOOD)
        cls.svc.add_link(cls.cid, "utr", S.VICTIM_UTR, "domain", A, "referenced_in_complaint", "UTR in complaint next to the domain", "Complaint p.1")
        cls.svc.add_link(cls.cid, "account", "GHOST99", "ip", "203.0.113.10", "other", "Account seen in chat log", "Chat export")
        cls.c = {(x["from_value"], x["to_value"]): x for x in cls.svc.get_correlations(cls.cid)}

    def test_account_context_from_risk_engine(self):
        ctx = self.c[("MULE01", A)]["context"]["from"]
        self.assertEqual((ctx["review_priority"], ctx["score"]), ("HIGH", 100))
        self.assertIn("FAN_IN", ctx["rules"]); self.assertGreater(ctx["transfers_out"], 0)

    def test_domain_context_from_infra(self):
        ctx = self.c[("MULE01", A)]["context"]["to"]
        self.assertTrue(ctx["looked_up"]); self.assertEqual(ctx["age_days"], 11); self.assertIn("NEWLY_REGISTERED", ctx["indicators"])

    def test_suggested_leads_are_labelled_weak_and_never_strong(self):
        leads = self.c[("MULE01", A)]["suggested_leads"]
        self.assertTrue(leads); self.assertEqual({x["entity"] for x in leads}, {B})
        self.assertNotIn(H, {x["entity"] for x in leads})                                  # unrelated domain not pulled in
        for x in leads:
            self.assertEqual(x["label"], "SUGGESTED"); self.assertNotEqual(x["strength"], "strong"); self.assertTrue(x["caveat"])

    def test_utr_context_shows_transfer(self):
        t = self.c[(S.VICTIM_UTR, A)]["context"]["from"]["transfers"][0]
        self.assertEqual((t["from"], t["to"], t["amount_inr"], t["method"]), ("VICTIM01", "MULE01", 50000.0, "utr_both_sides"))

    def test_unknown_account_flagged_not_dropped(self):
        x = self.c[("GHOST99", "203.0.113.10")]
        self.assertEqual(x["endpoint_status"], {"from": "not_in_imported_data", "to": "looked_up"})
        self.assertEqual(x["context"]["from"]["review_priority"], None)
        self.assertEqual(x["context"]["to"]["asn"], "64496")
        self.assertEqual({y["entity"] for y in x["suggested_leads"]}, {A, B})              # domains resolving to that IP (DNS observation)

    def test_everything_marked_investigator_entered(self):
        for x in self.c.values():
            self.assertEqual(x["origin"], "investigator_entered")

    def test_links_do_not_change_automatic_relationships(self):
        svc, cid = demo(); before = svc.get_relationships(cid)
        svc.add_link(cid, **GOOD); self.assertEqual(svc.get_relationships(cid), before)


class InReports(unittest.TestCase):
    def test_pdf_and_excel_contain_links(self):
        svc, cid = demo(); svc.add_link(cid, **GOOD, observed_at="2026-03-10 10:05")
        with tempfile.TemporaryDirectory() as t:
            p = generate_reports(svc, cid, t, S.VICTIM_UTR)
            with pdfplumber.open(p["pdf"]) as pdf:
                txt = " ".join((pg.extract_text() or "").replace("\n", " ") for pg in pdf.pages)
            ws = load_workbook(p["xlsx"])["Fin-Digital links"]
            rows = list(ws.iter_rows(min_row=4, values_only=True))
        for needle in ("INVESTIGATOR-ENTERED", "Not inferred by this tool", "EV-0008", "unverified", "MULE01", "10:05:00 IST"):
            self.assertIn(needle, txt, needle)
        self.assertEqual(len(rows), 1); self.assertEqual(rows[0][8], "investigator_entered"); self.assertEqual(rows[0][3], "payment_instruction_on_site"); self.assertEqual(rows[0][5], "2026-03-10 10:05:00 IST")
        self.assertEqual(txt.count("quick-loan-bonus.example via secure-kyc-update.example"), 1)   # leads merged per entity

    def test_no_links_report_says_none_entered(self):
        svc, cid = demo()
        with tempfile.TemporaryDirectory() as t:
            with pdfplumber.open(generate_reports(svc, cid, t, S.VICTIM_UTR)["pdf"]) as pdf:
                txt = " ".join((pg.extract_text() or "").replace("\n", " ") for pg in pdf.pages)
        self.assertIn("none has been entered for this case", txt)


if __name__ == "__main__":
    unittest.main()
