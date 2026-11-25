import unittest
from datetime import datetime, timedelta
from pathlib import Path

from traceintel import synthetic as S
from traceintel.config import load_config
from traceintel.ingest import ingest_file, parse_amount, normalize_account, parse_ts
from traceintel.models import Transfer
from traceintel.pipeline import analyze_files
from traceintel.rules import run_rules, score_accounts
from traceintel.trail import reconstruct

DATA = Path(__file__).resolve().parent.parent / "data" / "synthetic"
CFG = load_config()


def setUpModule():
    S.generate(DATA)   # reproducible: tests always regenerate the synthetic data


def T(i, a, b, amt, minutes, utr=None, base=datetime(2026, 1, 1)):
    return Transfer(i, a, b, amt * 100, base + timedelta(minutes=minutes), utr or f"U{i}", "utr_both_sides", "high", None, None)


class Ingest(unittest.TestCase):
    def test_parse_amount(self):
        self.assertEqual(parse_amount("1,00,000.50"), 10000050)
        self.assertEqual(parse_amount("Rs. 500"), 50000)
        self.assertIsNone(parse_amount(""))
        with self.assertRaises(ValueError):
            parse_amount("abc")

    def test_timezone_ist_to_utc(self):
        ts, d = parse_ts("10-03-2026 10:00:00", "Asia/Kolkata")
        self.assertEqual(ts, datetime(2026, 3, 10, 4, 30)); self.assertFalse(d)
        self.assertIsNone(parse_ts("31-02-2026 10:00", "Asia/Kolkata")[0])

    def test_account_normalisation_keeps_raw(self):
        self.assertEqual(normalize_account(" ab-12 34 "), "AB1234")
        self.assertEqual(normalize_account("Foo@UPI"), "foo@upi")

    def test_clean_synthetic_has_no_problems(self):
        r = ingest_file(DATA / "statements_all.csv", CFG)
        self.assertEqual(r.counts()["invalid"] + r.counts()["duplicate"], 0)
        self.assertEqual([p for p in r.problems if p["code"] == "BALANCE_MISMATCH"], [])

    def test_dirty_rows_flagged_never_dropped(self):
        r = ingest_file(DATA / "dirty_sample.csv", CFG)
        self.assertEqual(len(r.entries), 7)                       # nothing dropped
        st = [e.status for e in r.entries]
        self.assertEqual(st, ["ok", "duplicate", "invalid", "invalid", "ok", "ok", "ok"])
        codes = {p["code"] for p in r.problems}
        self.assertTrue({"DUPLICATE_UTR_SAME_SIDE", "INVALID_DATE", "MISSING_AMOUNT", "BALANCE_MISMATCH",
                         "DATE_ONLY_TIME_UNKNOWN"} <= codes)
        self.assertTrue(all(e.source_row_ref for e in r.entries))

    def test_xlsx_narration_only(self):
        r = ingest_file(DATA / "statement_SALARY01_narration_only.xlsx", CFG, default_account="SALARY01")
        e = r.entries[0]
        self.assertEqual((e.account_key, e.counterparty_key), ("SALARY01", "EXTEMPLOYER"))
        self.assertRegex(e.utr, r"^\d{12}$")
        self.assertEqual(r.counts()["invalid"], 0)

    def test_pdf_table(self):
        r = ingest_file(DATA / "statement_MULE02.pdf", CFG, default_account="MULE02")
        self.assertEqual(len(r.entries), 2)
        self.assertEqual([e.direction for e in r.entries], ["CR", "DR"])
        self.assertTrue(r.entries[0].source_row_ref.startswith("p1"))


class Pipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = analyze_files([DATA / "statements_all.csv"], CFG)
        cls.by = {a.account: a for a in cls.res["assessments"]}

    def rules(self, acct):
        return set(self.by[acct].rules) if acct in self.by else set()

    def test_both_sides_match_for_victim_utr(self):
        t = [x for x in self.res["transfers"] if x.utr == S.VICTIM_UTR]
        self.assertEqual(len(t), 1)
        self.assertEqual((t[0].from_key, t[0].to_key, t[0].method), ("VICTIM01", "MULE01", "utr_both_sides"))
        self.assertTrue(t[0].debit_entry_id and t[0].credit_entry_id)

    def test_external_counterparty_is_one_side(self):
        t = [x for x in self.res["transfers"] if x.to_key == "FANOUT01"][0]
        self.assertEqual(t.method, "utr_one_side"); self.assertEqual(t.confidence, "medium")

    def test_fan_in_and_out(self):
        self.assertTrue({"FAN_IN", "FAN_OUT"} <= self.rules("MULE01"))
        fin = [f for f in self.by["MULE01"].findings if f.rule == "FAN_IN"][0]
        self.assertEqual(set(fin.evidence["counterparties"]), {s.replace("-", "") for s in S.SENDERS} | {"VICTIM01"})
        self.assertEqual(len(fin.transfer_ids), 9)

    def test_pass_through_chain(self):
        for a in ("MULE01", "MULE02", "MULE03"):
            self.assertIn("RAPID_PASS_THROUGH", self.rules(a))
        self.assertNotIn("RAPID_PASS_THROUGH", self.rules("CASHOUT01"))

    def test_layering_on_intermediates_only(self):
        for a in ("MULE01", "MULE02", "MULE03"):
            self.assertIn("LAYERING", self.rules(a))
        self.assertNotIn("LAYERING", self.rules("CASHOUT01"))
        self.assertNotIn("LAYERING", self.rules("VICTIM01"))

    def test_circular(self):
        for a in S.LOOP:
            self.assertIn("CIRCULAR_FLOW", self.rules(a))

    def test_dormant_and_round(self):
        self.assertIn("DORMANT_TO_ACTIVE", self.rules("DORM01"))
        self.assertIn("ROUND_FIGURE", self.rules("ROUND01"))

    def test_negative_control_salary_account_clean(self):
        self.assertNotIn("SALARY01", self.by)

    def test_senders_and_victim_not_flagged(self):
        for a in S.SENDERS + ["VICTIM01"]:
            self.assertNotIn(a, self.by)

    def test_every_finding_has_evidence_and_limitation(self):
        for f in self.res["findings"]:
            self.assertTrue(f.explanation and f.limitation)
            self.assertTrue(f.transfer_ids or f.entry_ids)

    def test_threshold_change_changes_result(self):
        cfg = load_config(overrides={"rules": {"fan_in": {"min_distinct_counterparties": 20}}})
        res = analyze_files([DATA / "statements_all.csv"], cfg)
        self.assertNotIn("FAN_IN", {r for a in res["assessments"] for r in a.rules})


class Trail(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = analyze_files([DATA / "statements_all.csv"], CFG)

    def test_victim_utr_full_path(self):
        tr = reconstruct(self.res["transfers"], CFG, utr=S.VICTIM_UTR)
        accts = [p["accounts"] for p in tr["paths"]]
        self.assertIn(S.CHAIN, accts)
        main = [p for p in tr["paths"] if p["accounts"] == S.CHAIN][0]
        self.assertEqual(main["hops"], 4)
        self.assertEqual(main["carried_upper_bound_inr"], [50000, 49500, 49000, 48500][:1] + [49500, 49000, 48500])
        self.assertIn("not proven", tr["label"])

    def test_commingling_flagged_at_mule01(self):
        tr = reconstruct(self.res["transfers"], CFG, utr=S.VICTIM_UTR)
        main = [p for p in tr["paths"] if p["accounts"] == S.CHAIN][0]
        self.assertEqual([h["account"] for h in main["commingled_hops"]], ["MULE01"])
        self.assertEqual(main["commingled_hops"][0]["other_inflow_count"], 8)

    def test_graph_roles(self):
        g = reconstruct(self.res["transfers"], CFG, utr=S.VICTIM_UTR)["graph"]
        roles = {n["id"]: n["roles"] for n in g["nodes"]}
        self.assertIn("origin", roles["VICTIM01"]); self.assertIn("dispersal", roles["MULE01"])
        self.assertIn("terminal", roles["CASHOUT01"])
        self.assertTrue(any(e["observed"] for e in g["edges"]))

    def test_time_order_enforced(self):
        ts = [T(1, "A", "B", 1000, 60), T(2, "B", "C", 1000, 0)]      # B->C happened BEFORE A->B
        tr = reconstruct(ts, CFG, utr="U1")
        self.assertEqual([p["accounts"] for p in tr["paths"]], [["A", "B"]])

    def test_gap_limit(self):
        ts = [T(1, "A", "B", 1000, 0), T(2, "B", "C", 1000, 60 * 100)]  # 100h later > 72h
        self.assertEqual([p["accounts"] for p in reconstruct(ts, CFG, utr="U1")["paths"]], [["A", "B"]])

    def test_multiple_transfers_stay_individual(self):
        ts = [T(1, "A", "B", 1000, 0), T(2, "A", "B", 2000, 5), T(3, "B", "C", 500, 10)]
        tr = reconstruct(ts, CFG, account="A")
        self.assertEqual(len(tr["graph"]["edges"]), 3)
        self.assertEqual(len({tuple(p["transfer_ids"]) for p in tr["paths"]}), 2)

    def test_loop_terminates_and_is_marked(self):
        ts = [T(1, "A", "B", 1000, 0), T(2, "B", "C", 990, 5), T(3, "C", "A", 980, 10)]
        p = reconstruct(ts, CFG, utr="U1")["paths"]
        self.assertTrue(p[0]["circular"]); self.assertEqual(p[0]["hops"], 3)

    def test_hop_cap(self):
        ts = [T(i, chr(64 + i), chr(65 + i), 1000, i) for i in range(1, 9)]
        tr = reconstruct(ts, CFG, utr="U1", max_hops=3)
        self.assertEqual(max(p["hops"] for p in tr["paths"]), 3)

    def test_unknown_utr(self):
        self.assertFalse(reconstruct(self.res["transfers"], CFG, utr="000")["found"])


class Rules(unittest.TestCase):
    def test_rent_style_monthly_round_amounts_not_flagged(self):
        ts = [T(i, "TENANT", "LANDLORD", 15000, i * 60 * 24 * 30) for i in range(1, 6)]
        self.assertEqual([f for f in run_rules([], ts, CFG) if f.rule == "ROUND_FIGURE"], [])

    def test_refund_to_sender_is_not_pass_through(self):
        ts = [T(1, "S", "A", 20000, 0), T(2, "A", "S", 20000, 5)]
        self.assertEqual([f for f in run_rules([], ts, CFG) if f.rule == "RAPID_PASS_THROUGH"], [])


if __name__ == "__main__":
    unittest.main()
