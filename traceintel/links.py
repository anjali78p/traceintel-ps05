"""Investigator-entered financial <-> digital links. Never created automatically; every link carries explanation + source evidence.
The tool adds context (risk indicators, shared infrastructure) as SUGGESTED leads only; it never upgrades a link by itself."""
from __future__ import annotations
import ipaddress
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from .infra.correlate import CAVEATS
from .infra.enrich import DOMAIN_RE
from .ingest import normalize_account

RELATIONS = {
    "referenced_in_complaint": "Domain/IP is named in the victim complaint or other case document that also names this account/UTR",
    "payment_instruction_on_site": "The site/app instructed the victim to pay this account/UTR",
    "account_listed_on_site": "This account is shown on the site/app (payment page, QR, form)",
    "same_actor_per_evidence": "Evidence (cited) indicates the same operator; not proven by this tool",
    "other": "Other relationship, described in the explanation",
}
FROM_TYPES, TO_TYPES, CONFIDENCE = ("account", "utr"), ("domain", "ip"), ("unverified", "corroborated")


class LinkMixin:
    def _norm_endpoint(self, kind, value, side):
        v = str(value or "").strip()
        if not v:
            raise ValueError(f"{side} value is required")
        if kind == "account":
            return normalize_account(v)
        if kind == "utr":
            return v
        if kind == "domain":
            d = v.lower().rstrip(".")
            if not DOMAIN_RE.match(d):
                raise ValueError(f"invalid domain: {value!r}")
            return d
        if kind == "ip":
            try:
                return str(ipaddress.ip_address(v))
            except ValueError:
                raise ValueError(f"invalid IP address: {value!r}")
        raise ValueError(f"unsupported {side} type: {kind!r}")

    def _user_ts(self, s):
        """Naive input is read in the configured statement time zone; stored as UTC."""
        if not s:
            return None, None
        try:
            dt = datetime.fromisoformat(str(s).strip().replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"observed_at not understood: {s!r} (use e.g. 2026-03-10 10:05 or 2026-03-10T10:05:00+05:30)")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=ZoneInfo(self.cfg["ingest"]["timezone"]))
        return dt.astimezone(timezone.utc).replace(tzinfo=None).isoformat(), str(s)

    def add_link(self, case_id, from_type, from_value, to_type, to_value, relation, explanation, source_note=None,
                 evidence_id=None, observed_at=None, confidence="unverified", actor="investigator"):
        self._case(case_id)
        if from_type not in FROM_TYPES or to_type not in TO_TYPES:
            raise ValueError(f"link must go from {FROM_TYPES} to {TO_TYPES}")
        if relation not in RELATIONS:
            raise ValueError(f"relation must be one of {sorted(RELATIONS)}")
        if confidence not in CONFIDENCE:
            raise ValueError(f"confidence must be one of {CONFIDENCE}")
        explanation = (explanation or "").strip()
        if not explanation:
            raise ValueError("explanation is required")
        fv, tv = self._norm_endpoint(from_type, from_value, "from"), self._norm_endpoint(to_type, to_value, "to")
        evidence_id, source_note = (evidence_id or "").strip() or None, (source_note or "").strip() or None
        if evidence_id and not self.db.execute("SELECT 1 FROM evidence WHERE case_id=? AND evidence_id=?", (case_id, evidence_id)).fetchone():
            raise ValueError(f"evidence {evidence_id} does not exist in this case")
        if not evidence_id and not source_note:
            raise ValueError("a source is required: cite an existing evidence_id or describe the source in source_note")
        if confidence == "corroborated" and not evidence_id:
            raise ValueError("'corroborated' requires an existing evidence_id")
        ts_utc, ts_in = self._user_ts(observed_at)
        if self.db.execute("SELECT 1 FROM links WHERE case_id=? AND from_type=? AND from_value=? AND to_type=? AND to_value=? AND relation=? AND status='active'",
                           (case_id, from_type, fv, to_type, tv, relation)).fetchone():
            raise ValueError("an identical active link already exists")
        if not evidence_id:
            evidence_id = self._evidence(case_id, "investigator_note", source_note[:300], "investigator",
                                         related={"for_link": f"{from_type}:{fv} -> {to_type}:{tv}"})
        lid = self.db.execute("INSERT INTO links(case_id, from_type, from_value, to_type, to_value, relation, explanation, evidence_id, source_note,"
                              " observed_at_utc, observed_at_input, confidence, status, actor, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                              (case_id, from_type, fv, to_type, tv, relation, explanation, evidence_id, source_note, ts_utc, ts_in,
                               confidence, "active", actor, self._now())).lastrowid
        self.db.commit()
        self.audit(case_id, "LINK_ADDED", {"link_id": lid, "from": f"{from_type}:{fv}", "to": f"{to_type}:{tv}", "relation": relation,
                                           "evidence_id": evidence_id, "confidence": confidence, "origin": "investigator_entered"}, actor)
        return lid

    def retract_link(self, case_id, link_id, reason, actor="investigator"):
        self._case(case_id)
        reason = (reason or "").strip()
        if not reason:
            raise ValueError("a reason is required to retract a link")
        r = self.db.execute("SELECT status FROM links WHERE case_id=? AND id=?", (case_id, link_id)).fetchone()
        if not r:
            raise ValueError(f"link {link_id} not found in this case")
        if r["status"] != "active":
            raise ValueError("link is already retracted")
        self.db.execute("UPDATE links SET status='retracted', retracted_at=?, retract_reason=? WHERE id=?", (self._now(), reason, link_id))
        self.db.commit()
        self.audit(case_id, "LINK_RETRACTED", {"link_id": link_id, "reason": reason}, actor)

    def get_links(self, case_id, include_retracted=False):
        self._case(case_id)
        q = "SELECT * FROM links WHERE case_id=?" + ("" if include_retracted else " AND status='active'") + " ORDER BY id"
        return [dict(r) for r in self.db.execute(q, (case_id,))]

    def _known(self, case_id, kind, value):
        if kind == "account":
            return bool(self.db.execute("SELECT 1 FROM ledger_entries WHERE case_id=? AND (account_key=? OR counterparty_key=?) LIMIT 1", (case_id, value, value)).fetchone())
        if kind == "utr":
            return bool(self.db.execute("SELECT 1 FROM ledger_entries WHERE case_id=? AND utr=? LIMIT 1", (case_id, value)).fetchone())
        return bool(self.db.execute("SELECT 1 FROM enrichments WHERE case_id=? AND type=? AND indicator=?", (case_id, kind, value)).fetchone())

    def get_correlations(self, case_id, include_retracted=False):
        """Links + context. Context and leads are derived at read time and labelled SUGGESTED; the link itself stays investigator-entered."""
        links = self.get_links(case_id, include_retracted)
        try:
            assess = {a["account"]: a for a in self.get_assessments(case_id)}
            transfers = self.get_transfers(case_id)
        except ValueError:
            assess, transfers = {}, []
        enr = {(e["type"], e["indicator"]): e for e in self.get_enrichments(case_id)}
        rels = self.get_relationships(case_id)
        out = []
        for l in links:
            fk, fv, tk, tv = l["from_type"], l["from_value"], l["to_type"], l["to_value"]
            if fk == "account":
                a = assess.get(fv)
                fctx = {"review_priority": a["priority"] if a else None, "score": a["score"] if a else None, "rules": a["rules"] if a else [],
                        "transfers_in": sum(t.to_key == fv for t in transfers), "transfers_out": sum(t.from_key == fv for t in transfers)}
            else:
                fctx = {"transfers": [{"from": t.from_key, "to": t.to_key, "amount_inr": t.amount_paise / 100, "ts_utc": t.ts_utc.isoformat(),
                                       "method": t.method} for t in transfers if t.utr == fv]}
            e = enr.get((tk, tv))
            leads = []
            if tk == "domain":
                for r in rels:
                    if tv in r["entities"]:
                        for other in r["entities"]:
                            if other != tv:
                                leads.append({"entity": other, "via": r["type"], "value": r["value"], "strength": r["strength"], "caveat": r["caveat"]})
                tctx = {"looked_up": bool(e), "registered": e and e["summary"].get("registered"), "age_days": e and e["summary"].get("age_days"),
                        "ips": e["summary"].get("ips") if e else [], "indicators": [i["code"] for i in e["indicators"]] if e else []}
            else:
                for (k, ind), d in enr.items():
                    if k == "domain" and tv in d["summary"].get("ips", []):
                        leads.append({"entity": ind, "via": "dns_resolution", "value": tv, "strength": "weak", "caveat": CAVEATS["shared_ip"]})
                tctx = {"looked_up": bool(e), "asn": e and e["summary"].get("asn"), "as_name": e and e["summary"].get("as_name"),
                        "reverse_dns": e["summary"].get("reverse_dns") if e else []}
            out.append({**l, "origin": "investigator_entered",
                        "endpoint_status": {"from": "found_in_imported_data" if self._known(case_id, fk, fv) else "not_in_imported_data",
                                            "to": "looked_up" if e else "not_looked_up"},
                        "context": {"from": fctx, "to": tctx},
                        "suggested_leads": [{**x, "label": "SUGGESTED", "derived_from": "investigator link + automatic correlation; not proof"} for x in leads]})
        return out
