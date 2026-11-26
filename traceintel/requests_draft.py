"""Drafts of information requests for banks, registrars and hosting providers.

DRAFTS ONLY: they must be reviewed, completed and issued by an authorised officer under the applicable legal process.
Subscriber, login and other non-public records are requested via that process; they are never presented as public data.
"""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime
from zoneinfo import ZoneInfo

BANNER = "DRAFT - NOT ISSUED. For review and issuance by an authorised officer through the applicable legal process."
LEGAL = ("Legal basis / order reference: [TO BE FILLED BY ISSUING OFFICER]. This request is made through the applicable lawful "
         "process. Non-public records (subscriber, KYC, login, session and device data) are requested only under that authority.")
SIGN = "Issuing officer: [NAME, RANK, UNIT]   FIR/Case No.: [FIR NO.]   Date: [DATE]   Contact: [OFFICIAL CONTACT]"


def _both(iso, tz):
    dt = datetime.fromisoformat(iso).replace(tzinfo=ZoneInfo("UTC"))
    return f"{dt.astimezone(ZoneInfo(tz)).strftime('%Y-%m-%d %H:%M:%S %Z')} ({dt.strftime('%Y-%m-%d %H:%M:%S')} UTC)"


def draft_requests(data):
    """data = reporting.collect(...). Returns list of draft dicts."""
    tz = data["tz"]
    case = data["case"]
    tag = " [SYNTHETIC DEMO - not a real request]" if case["is_synthetic"] else ""
    ref = case["case_number"]
    out = []

    # ---- banks: group all accounts in the reconstructed trail by bank ----
    trail = data["trail"]
    if trail and trail.get("found") and trail["paths"]:
        used = list(trail["graph"]["edges"])          # every transfer in the reconstructed trail, not only the longest path
        bank_of = data["bank_of"]
        groups = defaultdict(lambda: {"accounts": set(), "edges": []})
        for e in used:
            for acct in (e["source"], e["target"]):
                groups[bank_of.get(acct, "[bank to be identified]")]["accounts"].add(acct)
                groups[bank_of.get(acct, "[bank to be identified]")]["edges"].append(e)
        for bank, g in sorted(groups.items()):
            rows = "\n".join(
                f"  - UTR {e['utr'] or 'n/a'} | {_both(e['ts_utc'], tz)} | {e['source']} -> {e['target']} | INR {e['amount_inr']:,.2f} | "
                f"basis: {'seen in both statements' if e['observed'] else 'one side only / from counterparty text (unverified)'}"
                for e in {x["transfer_id"]: x for x in g["edges"]}.values())
            body = f"""{BANNER}{tag}

To: The Nodal Officer, {bank}
Subject: Request for information - suspected cyber-enabled financial fraud - Ref. {ref} / [FIR NO.]

{LEGAL}

Accounts concerned: {', '.join(sorted(g['accounts']))}
Transactions (timestamps as recorded in statements, assumed {tz}; please confirm time zone of your records):
{rows}

Information requested for the above accounts and transactions:
  1. Account opening form, KYC documents, nominee and linked-mobile/e-mail details.
  2. Complete statement from [FROM DATE] to [TO DATE].
  3. Remitter/beneficiary details for each UTR above, including onward transfers and cash withdrawals (ATM/branch, with location and time).
  4. IP address, device identifier and login/session logs for each transaction above, with exact timestamp and time zone.
  5. Please preserve all related records and CCTV for the period. Any lien or freeze is to be applied only under an order of the competent authority; this draft does not request or perform one.

{SIGN}"""
            out.append({"id": f"REQ-BANK-{len(out)+1}", "type": "bank", "to": bank, "subject": f"Information request - {ref}",
                        "body": body, "placeholders": ["FIR NO.", "legal basis", "FROM/TO DATE", "officer details"]})

    # ---- registrars ----
    for e in data["enrichments"]:
        if e["type"] != "domain":
            continue
        s = e["summary"]
        reg = s.get("registrar") or "[registrar not identified from public record]"
        body = f"""{BANNER}{tag}

To: Compliance / Legal Contact, {reg}
Subject: Request for information - domain {e['indicator']} - Ref. {ref} / [FIR NO.]

{LEGAL}

Domain: {e['indicator']}
Public record (retrieved via RDAP; indicative): registered {s.get('registered') or 'unknown'} UTC, expires {s.get('expires') or 'unknown'} UTC,
name servers: {', '.join(s.get('nameservers') or []) or 'unknown'}; registrant data in public record: {s.get('registrant_info') or 'unknown'}.

Information requested:
  1. Registrant, administrative and technical contact details and account holder identity.
  2. Payment instrument and billing records for the registration/renewals.
  3. Account creation, login and change history with IP addresses, timestamps and time zone.
  4. Other domains registered from the same account (if permitted under the legal process).
  5. Please preserve all related records.

{SIGN}"""
        out.append({"id": f"REQ-REG-{len(out)+1}", "type": "registrar", "to": reg, "subject": f"Domain {e['indicator']} - {ref}",
                    "body": body, "placeholders": ["FIR NO.", "legal basis", "officer details"]})

    # ---- hosting / network providers ----
    reg_dates = defaultdict(list)
    for e in data["enrichments"]:
        if e["type"] == "domain" and e["summary"].get("registered"):
            for ip in e["summary"]["ips"]:
                reg_dates[ip].append(e["summary"]["registered"])
    for e in data["enrichments"]:
        if e["type"] != "ip":
            continue
        s = e["summary"]
        prov = s.get("organisation") or s.get("as_name") or "[provider not identified]"
        seen = max((o["retrieved_at"] for o in e["observations"].values() if o["retrieved_at"]), default=None)
        start = min(reg_dates.get(e["indicator"], [None]) or [None]) or "[START TIMESTAMP]"
        body = f"""{BANNER}{tag}

To: Legal / Abuse & Law-Enforcement Contact, {prov}
Subject: Request for information - IP address {e['indicator']} - Ref. {ref} / [FIR NO.]

{LEGAL}

IP address: {e['indicator']}   ASN: {s.get('asn') or 'unknown'} ({s.get('as_name') or 'unknown'})   Prefix: {s.get('bgp_prefix') or 'unknown'}
Observed (public lookup, indicative): at {_both(seen, tz) if seen else '[OBSERVATION TIMESTAMP]'}.
Period of interest: from {start} UTC to {seen or '[END TIMESTAMP]'} UTC - [ADJUST TO EXACT INCIDENT TIMESTAMPS AND TIME ZONE].

Information requested:
  1. Subscriber/customer identity, billing and contact records for the service assigned this IP address during the period.
  2. Assignment/allocation history and, for shared or translated addresses (NAT/CGNAT/shared hosting), the port and exact-timestamp mapping needed to identify the customer.
  3. Account login/access logs (with IP, timestamp, time zone) and server provisioning/rental records.
  4. Please preserve all related logs.

Note: geolocation and hosting attribution from public data is indicative only and is not proof of any person's identity or location.

{SIGN}"""
        out.append({"id": f"REQ-HOST-{len(out)+1}", "type": "hosting", "to": prov, "subject": f"IP {e['indicator']} - {ref}",
                    "body": body, "placeholders": ["FIR NO.", "legal basis", "period of interest", "officer details"]})
    return out
