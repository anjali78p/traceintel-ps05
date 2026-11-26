"""Evidence-backed investigation report (PDF + Excel + draft requests).

Every statement is labelled: FACT (record as observed), INDICATOR (rule-based, configurable), SUGGESTED (inferred / possible),
INVESTIGATOR (left blank for the authorised officer). Nothing here is a finding of guilt.
"""
from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo

from .requests_draft import draft_requests

LIMITATIONS = [
    "Risk scores are review-priority indicators from configurable heuristics; they are not evidence of wrongdoing and can flag legitimate activity.",
    "Transaction paths are possible paths reconstructed from records. Amounts carried are upper bounds; where an account received other money shortly before forwarding, the hop is marked commingled and exact fund attribution is not claimed.",
    "Transfers marked one-side or counterparty-only rely on counterparty text in a single statement and are unverified until the other bank's records are obtained.",
    "Statement timestamps are assumed to be in the configured time zone; confirm against the bank's records before relying on exact times.",
    "Dormancy and velocity indicators only see the supplied statements; absence of earlier activity in the file is not proof of dormancy.",
    "Domain/IP data comes from public passive sources at the stated retrieval time. Shared hosting, CDNs, VPNs and common name servers do not imply common ownership. Geolocation/ASN attribution is indicative, not proof of identity or location.",
    "Subscriber, login, KYC and other non-public records are not available from public sources and must be requested through the applicable legal process (see draft requests).",
    "No financial-to-digital link is asserted automatically. Such links require investigator-supplied evidence.",
    "The audit log is hash-chained for tamper-evidence only and is not legal chain-of-custody certification.",
]
LABELS = [("FACT", "A record exactly as observed in a source (statement row, public registry/DNS record) with source and time."),
          ("INDICATOR", "Rule-based, configurable heuristic flag. A prompt for review, not a conclusion."),
          ("SUGGESTED", "Inferred or possible relationship/path; unverified lead."),
          ("INVESTIGATOR", "Conclusion or note entered by the authorised investigator (blank in this draft).")]


def _local(iso, tz):
    if not iso:
        return ""
    dt = datetime.fromisoformat(iso).replace(tzinfo=ZoneInfo("UTC"))
    return dt.astimezone(ZoneInfo(tz)).strftime("%Y-%m-%d %H:%M:%S %Z")


def _flat(cfg):
    for sect in ("ingest", "rules", "scoring", "trail"):
        v = cfg.get(sect, {})
        for k, x in v.items():
            if isinstance(x, dict):
                yield f"{sect}.{k}", ", ".join(f"{a}={b}" for a, b in x.items())
            else:
                yield f"{sect}.{k}", str(x)


def collect(svc, case_id, victim_utr=None):
    case = svc.get_case(case_id)
    run = svc.get_run_summary(case_id)
    cfg = run["config"]; tz = cfg["ingest"]["timezone"]
    entries = svc.get_entries(case_id)
    usable_ts = sorted(e["ts_utc"] for e in entries if e["status"] == "ok" and e["ts_utc"])
    trail = svc.trail(case_id, utr=victim_utr) if victim_utr else None
    data = {
        "case": case, "run": run, "tz": tz, "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "entries": entries, "problems": svc.get_problems(case_id), "transfers": svc.get_transfers(case_id),
        "assessments": svc.get_assessments(case_id), "trail": trail, "victim_utr": victim_utr,
        "enrichments": svc.get_enrichments(case_id), "relationships": svc.get_relationships(case_id),
        "evidence": svc.get_evidence(case_id), "audit": svc.get_audit(case_id), "audit_check": svc.verify_audit(),
        "date_range": (usable_ts[0], usable_ts[-1]) if usable_ts else (None, None),
        "bank_of": {e["account_key"]: e["bank"] for e in entries},
        "config_rows": list(_flat(cfg)),
    }
    data["requests"] = draft_requests(data)
    return data


# ------------------------------------------------------------------ PDF
def build_pdf(data, path):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import CondPageBreak, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    tz, case = data["tz"], data["case"]
    ss = getSampleStyleSheet()
    H1 = ParagraphStyle("H1", parent=ss["Heading1"], fontSize=15, spaceAfter=6)
    H2 = ParagraphStyle("H2", parent=ss["Heading2"], fontSize=11.5, spaceBefore=10, spaceAfter=4, textColor=colors.HexColor("#1F3A5F"))
    H3 = ParagraphStyle("H3", parent=ss["Heading3"], fontSize=9.5, spaceBefore=6, spaceAfter=2)
    B = ParagraphStyle("B", parent=ss["BodyText"], fontSize=8.5, leading=11)
    S = ParagraphStyle("S", parent=B, fontSize=7.5, leading=9.5)
    TAG = ParagraphStyle("TAG", parent=B, fontSize=7.5, textColor=colors.HexColor("#555555"))

    def P(t, st=B):
        return Paragraph(escape(str(t)).replace("\n", "<br/>"), st)

    def tag(label):
        col = {"FACT": "#1B6B3A", "INDICATOR": "#A15C00", "SUGGESTED": "#7A2E8E", "INVESTIGATOR": "#1F3A5F"}[label]
        return Paragraph(f'<font color="{col}"><b>[{label}]</b></font>', TAG)

    def table(rows, widths, header=True):
        t = Table([[c if not isinstance(c, str) else P(c, S) for c in r] for r in rows],
                  colWidths=[w * 17.4 * cm for w in widths], repeatRows=1 if header else 0)
        st = [("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#999999")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
              ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3)]
        if header:
            st += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E6ECF3"))]
        t.setStyle(TableStyle(st))
        return t

    def footer(c, doc):
        c.saveState(); c.setFont("Helvetica", 7); c.setFillColor(colors.HexColor("#555555"))
        syn = "SYNTHETIC DEMO DATA  |  " if case["is_synthetic"] else ""
        c.drawString(1.8 * cm, 1.0 * cm, f"TRACEINTEL  |  {case['case_number']}  |  {syn}Investigation-support output; indicators are not proof of wrongdoing.")
        c.drawRightString(A4[0] - 1.8 * cm, 1.0 * cm, f"Page {doc.page}")
        c.restoreState()

    st = []
    st += [P("TRACEINTEL - Investigation Report", H1), P(f"{case['case_number']}: {case['title']}"),
           P(f"Generated {data['generated_at']}  |  Analysis run #{data['run']['run_id']} ({data['run']['started_at']} UTC)  |  Times shown in {tz} with UTC where noted", S), Spacer(1, 4)]
    if case["is_synthetic"]:
        st.append(table([["SYNTHETIC / DEMO DATA: all accounts, people, domains and IPs in this report are fictional or reserved examples."]], [1], header=False))
    st += [Spacer(1, 4), P("How to read this report", H3)]
    st.append(table([[f"{k}", d] for k, d in LABELS], [0.2, 0.8], header=False))

    # 1 overview
    ev_n = len(data["evidence"])
    st += [CondPageBreak(5 * cm), P("1. Case overview", H2), tag("FACT"),
           table([["Case number", case["case_number"]], ["Title", case["title"]], ["Created (UTC)", case["created_at"]],
                  ["Synthetic data", "Yes" if case["is_synthetic"] else "No"], ["Victim UTR used for trail", data["victim_utr"] or "not specified"],
                  ["Evidence items", str(ev_n)], ["Transaction period (UTC)", f"{data['date_range'][0] or '-'}  to  {data['date_range'][1] or '-'}"]],
                 [0.3, 0.7], header=False)]

    # 2 data sources
    st += [CondPageBreak(5 * cm), P("2. Data sources", H2), tag("FACT")]
    rows = [["File", "Bank", "SHA-256 (first 16)", "Rows", "OK", "Invalid", "Dup."]]
    for f in case["files"]:
        rows.append([f["filename"], f["bank_name"], f["sha256"][:16], str(f["total"]), str(f["ok"]), str(f["invalid"]), str(f["duplicate"])])
    st.append(table(rows, [0.3, 0.2, 0.22, 0.07, 0.07, 0.07, 0.07]))
    srcs = sorted({o["source"] for e in data["enrichments"] for o in e["observations"].values()})
    st.append(P("Passive public sources used: " + (", ".join(srcs) if srcs else "none (no enrichment run)") + ". No active scanning or probing of third-party systems was performed.", S))

    # 3 transaction summary
    c = data["run"]["summary"]; by = c["by_method"]
    st += [CondPageBreak(5 * cm), P("3. Transaction summary", H2), tag("FACT"),
           table([["Ledger rows imported", str(c["entries"])], ["Rows usable for analysis", str(c["usable_entries"])],
                  ["Derived transfers", str(c["transfers"])],
                  ["- seen in both statements (observed)", str(by["utr_both_sides"])],
                  ["- one side only (counterparty text, unverified)", str(by["utr_one_side"])],
                  ["- counterparty text only, no UTR (weak)", str(by["counterparty_only"])],
                  ["Rows that could not be resolved to a transfer", str(c["unresolved_entries"])]], [0.6, 0.4], header=False)]
    if data["problems"]:
        codes = {}
        for p in data["problems"]:
            codes[p["code"]] = codes.get(p["code"], 0) + 1
        st += [P("Import warnings/errors (rows are kept and flagged, never silently dropped):", S),
               table([["Code", "Count"]] + [[k, str(v)] for k, v in sorted(codes.items())], [0.7, 0.3])]

    # 4 indicators
    st += [CondPageBreak(5 * cm), P("4. Suspicious account indicators", H2), tag("INDICATOR"),
           P("Review-priority only. Scores add configured weights per triggered rule. Each indicator lists its supporting transfers/UTRs and limitation.", S)]
    if data["assessments"]:
        st.append(table([["Account", "Priority", "Score", "Rules triggered"]] +
                        [[a["account"], a["priority"], str(a["score"]), ", ".join(a["rules"])] for a in data["assessments"]], [0.2, 0.12, 0.1, 0.58]))
        for a in data["assessments"][:8]:
            block = [P(f"{a['account']}  -  {a['priority']} review priority (score {a['score']})", H3)]
            for f in a["findings"]:
                refs = f"transfers {f['transfer_ids'][:12]}" if f["transfer_ids"] else f"ledger entries {f['entry_ids'][:12]}"
                block += [P(f"{f['rule']}: {f['title']}", S), P(f["explanation"], S),
                          P(f"Evidence: {refs}; UTRs: {', '.join(f['utrs'][:8]) or 'n/a'}", S), P(f"Limitation: {f['limitation']}", TAG), Spacer(1, 2)]
            st.append(KeepTogether(block[:4]))
            st += block[4:]
    else:
        st.append(P("No indicators triggered at the configured thresholds.", B))

    # 5 trail
    st += [CondPageBreak(5 * cm), P("5. Money-trail reconstruction", H2), tag("SUGGESTED")]
    tr = data["trail"]
    if not tr:
        st.append(P("No victim UTR/account was specified; trail not reconstructed.", B))
    elif not tr.get("found"):
        st.append(P(f"No transfer matches UTR {data['victim_utr']}.", B))
    else:
        st.append(P(tr["label"] + f" Parameters: max {tr['params']['max_hops']} hops, max gap {tr['params']['max_gap_hours']} h between hops.", S))
        rows = [["Possible path", "Hops", "Span (min)", "Upper-bound INR carried", "Attribution"]]
        for p in tr["paths"][:12]:
            rows.append([" -> ".join(p["accounts"]), str(p["hops"]), str(p["span_minutes"]),
                         " > ".join(f"{x:,.0f}" for x in p["carried_upper_bound_inr"]),
                         p["attribution"] + ("; circular" if p["circular"] else "")])
        st.append(table(rows, [0.4, 0.07, 0.1, 0.23, 0.2]))
        main = tr["paths"][0]
        edges = {e["transfer_id"]: e for e in tr["graph"]["edges"]}
        rows = [["Transfer", "From -> To", "INR", f"Time ({tz})", "UTR", "Basis"]]
        for i in main["transfer_ids"]:
            e = edges[i]
            rows.append([f"T{i}", f"{e['source']} -> {e['target']}", f"{e['amount_inr']:,.2f}", _local(e["ts_utc"], tz), e["utr"] or "n/a",
                         "FACT: both statements" if e["observed"] else "unverified: one side"])
        st += [P(f"Hop detail of the longest path ({' -> '.join(main['accounts'])}):", H3), table(rows, [0.08, 0.27, 0.12, 0.2, 0.17, 0.16])]
        if main["commingled_hops"]:
            st.append(P("Commingling: " + "; ".join(f"{h['account']} also received INR {h['other_inflow_inr']:,.2f} in {h['other_inflow_count']} other transfer(s) shortly before forwarding"
                                                    for h in main["commingled_hops"]) + ". Exact attribution of the forwarded amount is not possible.", S))
        roles = [f"{n['id']}: {', '.join(n['roles'])}" for n in tr["graph"]["nodes"] if n["roles"]]
        if roles:
            st.append(P("Structural roles in trail: " + "; ".join(roles), S))

    # 6 infrastructure
    st += [CondPageBreak(5 * cm), P("6. Digital infrastructure findings", H2), tag("FACT"),
           P("Public passive data as retrieved at the stated time. Hosting/ASN/geolocation is indicative, not proof of identity or location.", S)]
    if not data["enrichments"]:
        st.append(P("No domain/IP enrichment has been run for this case.", B))
    for e in data["enrichments"]:
        s = e["summary"]
        stat = ", ".join(f"{k}:{o['status']}" for k, o in e["observations"].items())
        when = max((o["retrieved_at"] for o in e["observations"].values() if o["retrieved_at"]), default="n/a")
        if e["type"] == "domain":
            rows = [["Registered / expires (UTC)", f"{s['registered']} / {s['expires']}  (age {s['age_days']} days)"], ["Registrar", str(s["registrar"])],
                    ["Registrant data in public record", str(s["registrant_info"])], ["Name servers", ", ".join(s["nameservers"])],
                    ["Resolved IPs", ", ".join(s["ips"])], ["Certificates (CT)", f"{s['certificate_count']}; names: {', '.join(s['certificate_names'][:6])}"]]
        else:
            rows = [["ASN / network", f"AS{s['asn']} {s['as_name']}; {s['bgp_prefix']}; {s['network_name']}"], ["Organisation (registry)", str(s["organisation"])],
                    ["Registered country (indicative)", str(s["registered_country"])], ["Reverse DNS", ", ".join(s["reverse_dns"]) or "none"]]
        rows += [["Retrieved (UTC) / source status", f"{when}  |  {stat}"]]
        for i in e["indicators"]:
            rows.append([f"Indicator {i['code']} ({i['severity']})", i["explanation"]])
        st += [KeepTogether([P(f"{e['type'].upper()}: {e['indicator']}", H3), table(rows, [0.3, 0.7], header=False)])]

    # 7 relationships
    st += [CondPageBreak(5 * cm), P("7. Entity relationships", H2), tag("SUGGESTED")]
    if data["relationships"]:
        rows = [["Type", "Strength", "Entities", "Via", "Caveat"]]
        for r in data["relationships"]:
            rows.append([r["type"], r["strength"], ", ".join(r["entities"]), r["value"], r["caveat"]])
        st.append(table(rows, [0.14, 0.1, 0.24, 0.2, 0.32]))
    else:
        st.append(P("No infrastructure relationships were suggested.", B))
    st.append(P("Links between bank accounts/UTRs and domains/IPs are NOT established automatically. They require investigator-supplied evidence and are recorded as such.", S))

    # 8 evidence
    st += [CondPageBreak(5 * cm), P("8. Evidence references", H2), tag("FACT")]
    rows = [["ID", "Type", "Description", "SHA-256 (first 16)", "Created (UTC)"]]
    for e in data["evidence"]:
        rows.append([e["evidence_id"], e["type"], e["description"], (e["sha256"] or "")[:16], e["created_at"]])
    st.append(table(rows, [0.09, 0.16, 0.45, 0.16, 0.14]))
    ac = data["audit_check"]
    st.append(P(f"Audit log: {len(data['audit'])} entries for this case; hash-chain check: {'valid' if ac['valid'] else 'INVALID'}. (Tamper-evidence only; not legal chain-of-custody certification.)", S))

    # 9 methodology
    st += [CondPageBreak(5 * cm), P("9. Methodology and limitations", H2),
           P("Pipeline: statement rows (kept as observed) -> derived transfers (matched by UTR across statements; unmatched rows use counterparty text) -> "
             "rule engine (fan-in, fan-out, rapid pass-through, velocity, 24h turnover, dormant-to-active, layering, circular flow, round-figure) -> "
             "time-respecting path search -> passive public lookups -> suggested infrastructure correlations.", S),
           P("Configuration used in this run:", H3), table([["Setting", "Value"]] + [[k, v] for k, v in data["config_rows"]], [0.4, 0.6]),
           P("Limitations", H3)]
    st += [P(f"{i}. {t}", S) for i, t in enumerate(LIMITATIONS, 1)]

    # 10 investigator
    st += [CondPageBreak(5 * cm), P("10. Investigator review notes", H2), tag("INVESTIGATOR"),
           table([["Reviewed by (name, rank)", ""], ["Date", ""], ["Findings accepted / rejected and reasons", "\n\n\n"], ["Conclusions", "\n\n\n"],
                  ["Follow-up (requests, further evidence)", "\n\n"]], [0.3, 0.7], header=False)]

    # appendix
    st += [PageBreak(), P("Appendix A. Draft information requests", H2), tag("INVESTIGATOR"),
           P("Drafts for review by an authorised officer. They must be completed and issued through the applicable legal process.", S)]
    for r in data["requests"]:
        st += [KeepTogether([P(f"{r['id']}  ({r['type']}) to: {r['to']}", H3), table([[r["body"]]], [1], header=False)]), Spacer(1, 4)]
    if not data["requests"]:
        st.append(P("No drafts generated (no trail or enrichment available).", S))

    SimpleDocTemplate(str(path), pagesize=A4, leftMargin=1.8 * cm, rightMargin=1.8 * cm, topMargin=1.6 * cm, bottomMargin=1.6 * cm,
                      title=f"TRACEINTEL {case['case_number']}", author="TRACEINTEL").build(st, onFirstPage=footer, onLaterPages=footer)
    return path


# ------------------------------------------------------------------ Excel
def build_xlsx(data, path):
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    tz, case = data["tz"], data["case"]
    wb = Workbook()
    hdr = PatternFill("solid", fgColor="1F3A5F")

    def sheet(name, header, rows, note=None, first=False):
        ws = wb.active if first else wb.create_sheet()
        ws.title = name
        r0 = 1
        if note:
            ws.cell(1, 1, note).font = Font(italic=True, color="7A2E00"); r0 = 3
        for j, h in enumerate(header, 1):
            c = ws.cell(r0, j, h); c.font = Font(bold=True, color="FFFFFF"); c.fill = hdr
        for i, row in enumerate(rows, r0 + 1):
            for j, v in enumerate(row, 1):
                c = ws.cell(i, j, v if isinstance(v, (int, float)) or v is None else str(v)); c.alignment = Alignment(wrap_text=True, vertical="top")
        for j in range(1, len(header) + 1):
            w = max([len(str(header[j - 1]))] + [min(len(str(r[j - 1])), 60) for r in rows if j - 1 < len(r)] or [10])
            ws.column_dimensions[get_column_letter(j)].width = min(max(w + 2, 10), 62)
        ws.freeze_panes = ws.cell(r0 + 1, 1)
        return ws

    syn = "SYNTHETIC DEMO DATA - fictional records. " if case["is_synthetic"] else ""
    sheet("Overview", ["Item", "Value"], [
        ["Case number", case["case_number"]], ["Title", case["title"]], ["Generated", data["generated_at"]], ["Synthetic data", case["is_synthetic"]],
        ["Analysis run", data["run"]["run_id"]], ["Victim UTR", data["victim_utr"] or ""],
        ["Period (UTC)", f"{data['date_range'][0]} to {data['date_range'][1]}"], ["Evidence items", len(data["evidence"])],
        ["Audit chain valid", data["audit_check"]["valid"]], ["Labels", "FACT = observed record; INDICATOR = rule-based heuristic; SUGGESTED = inferred/possible; INVESTIGATOR = to be completed by officer"],
        ["Disclaimer", "Indicators are review-priority aids, not evidence of wrongdoing."]], note=syn + "Investigation-support output.", first=True)
    sheet("Accounts", ["Account", "Priority", "Score", "Rules", "Label"],
          [[a["account"], a["priority"], a["score"], ", ".join(a["rules"]), "INDICATOR"] for a in data["assessments"]])
    sheet("Findings", ["Account", "Rule", "Weight", "Title", "Explanation", "Transfer IDs", "Entry IDs", "UTRs", "Limitation", "Label"],
          [[a["account"], f["rule"], f["weight"], f["title"], f["explanation"], ", ".join(map(str, f["transfer_ids"])),
            ", ".join(map(str, f["entry_ids"])), ", ".join(f["utrs"]), f["limitation"], "INDICATOR"]
           for a in data["assessments"] for f in a["findings"]])
    sheet("Transfers", ["ID", "From", "To", "INR", f"Time ({tz})", "Time (UTC)", "UTR", "Method", "Confidence", "Debit entry", "Credit entry", "Notes"],
          [[t.transfer_id, t.from_key, t.to_key, t.amount_paise / 100, _local(t.ts_utc.isoformat(), tz), t.ts_utc.isoformat(), t.utr, t.method,
            t.confidence, t.debit_entry_id, t.credit_entry_id, "; ".join(t.notes)] for t in data["transfers"]])
    tr = data["trail"]
    rows = []
    if tr and tr.get("found"):
        rows = [[" -> ".join(p["accounts"]), p["hops"], p["span_minutes"], " > ".join(f"{x:,.0f}" for x in p["carried_upper_bound_inr"]),
                 p["attribution"], p["circular"], ", ".join(map(str, p["transfer_ids"])), "SUGGESTED"] for p in tr["paths"]]
    sheet("Money trail", ["Possible path", "Hops", "Span (min)", "Upper-bound INR carried", "Attribution", "Circular", "Transfer IDs", "Label"], rows,
          note="Possible transaction paths reconstructed from records; not proven fund movement.")
    sheet("Infrastructure", ["Type", "Indicator", "Summary", "Source status", "Retrieved (UTC)", "Indicators", "Label"],
          [[e["type"], e["indicator"], "; ".join(f"{k}={v}" for k, v in e["summary"].items()),
            ", ".join(f"{k}:{o['status']}" for k, o in e["observations"].items()),
            max((o["retrieved_at"] for o in e["observations"].values() if o["retrieved_at"]), default=""),
            "; ".join(i["code"] for i in e["indicators"]), "FACT"] for e in data["enrichments"]],
          note="Public passive data; hosting/ASN/geolocation is indicative, not proof of identity or location.")
    sheet("Relationships", ["Type", "Strength", "Entities", "Via", "Caveat", "Evidence refs", "Label"],
          [[r["type"], r["strength"], ", ".join(r["entities"]), r["value"], r["caveat"], ", ".join(r["evidence_refs"]), "SUGGESTED"] for r in data["relationships"]])
    sheet("Evidence", ["ID", "Type", "Description", "SHA-256", "Created (UTC)"],
          [[e["evidence_id"], e["type"], e["description"], e["sha256"], e["created_at"]] for e in data["evidence"]])
    sheet("Import problems", ["File", "Row", "Code", "Severity", "Message"],
          [[p["filename"], p["row_ref"], p["code"], p["severity"], p["message"]] for p in data["problems"]])
    sheet("Draft requests", ["ID", "Type", "To", "Subject", "Draft text"], [[r["id"], r["type"], r["to"], r["subject"], r["body"]] for r in data["requests"]],
          note="DRAFTS - to be reviewed and issued by an authorised officer through the applicable legal process.")
    sheet("Audit", ["ID", "Time (UTC)", "Actor", "Action", "Detail"], [[a["id"], a["ts"], a["actor"], a["action"], str(a["detail"])] for a in data["audit"]])
    sheet("Methodology", ["Setting / limitation", "Value"], [[k, v] for k, v in data["config_rows"]] + [["Limitation", t] for t in LIMITATIONS])
    wb.save(path)
    return path


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def generate_reports(svc, case_id, out_dir, victim_utr=None):
    """Writes PDF, XLSX and draft-requests text; registers each as evidence and logs it in the audit trail."""
    out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    data = collect(svc, case_id, victim_utr)
    base = out / data["case"]["case_number"]
    paths = {"pdf": build_pdf(data, f"{base}_report.pdf"), "xlsx": build_xlsx(data, f"{base}_report.xlsx")}
    txt = Path(f"{base}_info_requests.txt")
    txt.write_text("\n\n" + ("=" * 78 + "\n\n").join(r["body"] for r in data["requests"]) if data["requests"] else "No drafts.", encoding="utf-8")
    paths["requests"] = txt
    for kind, p in paths.items():
        h = _sha(p)
        eid = svc._evidence(case_id, "report", f"Generated {kind} ({Path(p).name})", Path(p).name, h)
        svc.audit(case_id, "REPORT_GENERATED", {"format": kind, "file": Path(p).name, "sha256": h, "evidence_id": eid})
    svc.db.commit()
    return paths
