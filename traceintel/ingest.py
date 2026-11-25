"""Statement ingestion: CSV / XLSX / PDF(table) -> LedgerEntry rows.

Rules: never silently drop a row. Problem rows are kept with status invalid/duplicate and a warning code.
"""
from __future__ import annotations
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Optional
from zoneinfo import ZoneInfo

import pandas as pd

from .models import LedgerEntry

HEADER_ALIASES = {
    "account": ["account", "account no", "account number", "account_ref", "account ref", "a/c no"],
    "bank": ["bank", "bank name"],
    "date": ["date", "txn date", "transaction date", "value date", "timestamp", "datetime", "date time"],
    "time": ["time", "txn time"],
    "narration": ["narration", "description", "particulars", "remarks", "transaction remarks"],
    "debit": ["debit", "withdrawal", "withdrawals", "dr", "debit amount", "withdrawal amt."],
    "credit": ["credit", "deposit", "deposits", "cr", "credit amount", "deposit amt."],
    "amount": ["amount", "txn amount", "transaction amount"],
    "type": ["type", "dr/cr", "txn type", "transaction type"],
    "balance": ["balance", "closing balance", "running balance", "bal"],
    "utr": ["utr", "utr no", "utr number", "reference no", "ref no", "chq/ref no", "reference number"],
    "counterparty": ["counterparty", "beneficiary", "payee", "remitter", "counter party"],
}

TS_FORMATS = [
    ("%d-%m-%Y %H:%M:%S", False), ("%d-%m-%Y %H:%M", False),
    ("%d/%m/%Y %H:%M:%S", False), ("%d/%m/%Y %H:%M", False),
    ("%Y-%m-%d %H:%M:%S", False), ("%Y-%m-%d %H:%M", False),
    ("%d-%b-%Y %H:%M:%S", False), ("%d-%b-%Y %H:%M", False),
    ("%d-%m-%Y", True), ("%d/%m/%Y", True), ("%Y-%m-%d", True), ("%d-%b-%Y", True),
]
UTR_PATTERNS = [re.compile(r"\b(\d{12})\b"), re.compile(r"\b([A-Z]{4}[0-9A-Z]{12,18})\b")]
NARRATION_PREFIXES = {"UPI", "NEFT", "IMPS", "RTGS", "ATM", "POS"}


def normalize_account(raw) -> str:
    """Normalised lookup key. The raw source value is always preserved separately."""
    s = str(raw or "").strip()
    if not s:
        return ""
    if "@" in s:
        return s.lower()
    return re.sub(r"[\s\-]", "", s).upper()


def parse_amount(s) -> Optional[int]:
    """Parse money string to integer paise. None if blank; ValueError if malformed."""
    if s is None:
        return None
    t = str(s).strip()
    if t.lower() in ("", "-", "nan", "none", "null"):
        return None
    t = re.sub(r"(?i)(rs\.?|inr|₹|,|\s)", "", t)
    t = re.sub(r"(?i)(cr|dr)$", "", t)
    try:
        d = Decimal(t)
    except InvalidOperation:
        raise ValueError(f"cannot parse amount {s!r}")
    return int((d * 100).to_integral_value(ROUND_HALF_UP))


def parse_ts(raw: str, tz_name: str):
    """Returns (naive UTC datetime or None, date_only flag)."""
    raw = (raw or "").strip()
    for fmt, date_only in TS_FORMATS:
        try:
            dt = datetime.strptime(raw, fmt)
        except ValueError:
            continue
        local = dt.replace(tzinfo=ZoneInfo(tz_name))
        return local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None), date_only
    return None, False


def _norm_header(h) -> str:
    return re.sub(r"\s+", " ", str(h).strip().lower())


def resolve_columns(headers) -> dict:
    norm = {_norm_header(h): h for h in headers}
    out = {}
    for field_name, aliases in HEADER_ALIASES.items():
        for a in aliases:
            if a in norm:
                out[field_name] = norm[a]
                break
    return out


def narration_hints(narration: str):
    """Best-effort (utr, counterparty) from e.g. 'UPI/412345678901/NAME'. Hints only, not authoritative."""
    utr = None
    for p in UTR_PATTERNS:
        m = p.search(narration or "")
        if m:
            utr = m.group(1)
            break
    cp = ""
    parts = [p.strip() for p in (narration or "").split("/")]
    if len(parts) >= 3 and parts[0].upper() in NARRATION_PREFIXES:
        cp = parts[2]
    return utr, cp


# ---------- readers ----------
def read_rows(path: Path):
    """Returns (rows[(ref, dict)], problems[list])."""
    ext = path.suffix.lower()
    problems = []
    if ext in (".csv", ".txt"):
        df = pd.read_csv(path, dtype=str, keep_default_na=False)
        return [(f"row{i + 2}", r) for i, r in enumerate(df.to_dict("records"))], problems
    if ext in (".xlsx", ".xlsm", ".xls"):
        df = pd.read_excel(path, dtype=str).fillna("")
        return [(f"row{i + 2}", r) for i, r in enumerate(df.to_dict("records"))], problems
    if ext == ".pdf":
        return _read_pdf(path, problems)
    raise ValueError(f"unsupported file type: {ext}")


def _read_pdf(path: Path, problems):
    import pdfplumber
    rows, header = [], None
    with pdfplumber.open(path) as pdf:
        for pno, page in enumerate(pdf.pages, 1):
            n = 0
            for table in page.extract_tables():
                for r in table:
                    cells = [(c or "").replace("\n", " ").strip() for c in r]
                    if header is None:
                        res = resolve_columns(cells)
                        if "date" in res and len(res) >= 3:
                            header = cells
                        continue
                    if cells == header:
                        continue
                    n += 1
                    rows.append((f"p{pno}r{n}", dict(zip(header, cells))))
    if header is None or not rows:
        problems.append({"row_ref": "-", "code": "NO_TABLE_FOUND", "severity": "error",
                         "message": "No transaction table detected in PDF (scanned/text-only PDFs are not supported)."})
    return rows, problems


@dataclass
class IngestResult:
    file_name: str
    sha256: str
    entries: list
    problems: list = field(default_factory=list)

    def counts(self):
        c = {"total": len(self.entries), "ok": 0, "invalid": 0, "duplicate": 0, "with_warnings": 0}
        for e in self.entries:
            c[e.status] += 1
            c["with_warnings"] += bool(e.warnings)
        return c


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def ingest_file(path, cfg, bank_name="UNSPECIFIED", default_account=None, start_id=1) -> IngestResult:
    path = Path(path)
    rows, problems = read_rows(path)
    result = IngestResult(path.name, sha256_file(path), [], problems)
    if not rows:
        return result
    cols = resolve_columns(list(rows[0][1].keys()))
    if "date" not in cols:
        problems.append({"row_ref": "-", "code": "MISSING_DATE_COLUMN", "severity": "error",
                         "message": f"No date column recognised in headers {list(rows[0][1].keys())}"})
        return result
    tz = cfg["ingest"]["timezone"]
    eid = start_id
    seen = {}
    for ref, row in rows:
        def g(f):
            return str(row.get(cols[f], "")).strip() if f in cols else ""
        if not any(str(v).strip() for v in row.values()):
            problems.append({"row_ref": ref, "code": "EMPTY_ROW", "severity": "info", "message": "blank row skipped"})
            continue
        warns, status = [], "ok"
        acct_raw = g("account") or (default_account or "")
        if not acct_raw:
            warns.append("MISSING_ACCOUNT"); status = "invalid"
        ts_raw = f"{g('date')} {g('time')}".strip()
        ts, date_only = parse_ts(ts_raw, tz)
        if ts is None:
            warns.append("INVALID_DATE"); status = "invalid"
        elif date_only:
            warns.append("DATE_ONLY_TIME_UNKNOWN")
        direction = amount = balance = None
        try:
            if "debit" in cols or "credit" in cols:
                deb, cred = parse_amount(g("debit")), parse_amount(g("credit"))
                if deb and cred:
                    warns.append("BOTH_DEBIT_AND_CREDIT"); status = "invalid"
                elif deb:
                    direction, amount = "DR", deb
                elif cred:
                    direction, amount = "CR", cred
            elif "amount" in cols:
                amount = parse_amount(g("amount"))
                t = g("type").upper()
                direction = "DR" if t.startswith(("D", "W")) else "CR" if t.startswith("C") else None
        except ValueError:
            warns.append("BAD_AMOUNT"); status = "invalid"
        if status != "invalid":
            if amount is None or direction is None:
                warns.append("MISSING_AMOUNT"); status = "invalid"
            elif amount <= 0:
                warns.append("NON_POSITIVE_AMOUNT"); status = "invalid"
        try:
            balance = parse_amount(g("balance"))
        except ValueError:
            warns.append("BAD_BALANCE")
        narration = g("narration")
        h_utr, h_cp = narration_hints(narration)
        utr = g("utr") or h_utr
        utr = utr.strip() if utr else None
        cp_raw = g("counterparty") or h_cp
        acct_key = normalize_account(acct_raw)
        if status == "ok" and utr:
            k = (acct_key, utr, direction)
            if k in seen:
                status = "duplicate"
                prev = seen[k]
                warns.append("DUPLICATE_UTR_SAME_SIDE" + ("" if prev == amount else "_DIFFERENT_AMOUNT"))
            else:
                seen[k] = amount
        entry = LedgerEntry(eid, path.name, ref, acct_raw, acct_key, g("bank") or bank_name, ts_raw, ts,
                            direction, amount, balance, cp_raw, normalize_account(cp_raw), utr, narration,
                            status, warns)
        result.entries.append(entry)
        eid += 1
        for w in warns:
            problems.append({"row_ref": ref, "code": w, "severity": "error" if status == "invalid" else "warning",
                             "message": f"{w} (account={acct_raw or '?'}, entry_id={entry.entry_id})"})
    _check_balances(result, cfg)
    return result


def _check_balances(result: IngestResult, cfg):
    """prev_balance +/- amount must equal stated balance (assumes statement rows are in ledger order)."""
    tol = cfg["ingest"]["balance_tolerance_paise"]
    prev = {}
    for e in result.entries:
        if e.status != "ok" or e.balance_paise is None or e.amount_paise is None:
            if e.status == "ok":
                prev.pop(e.account_key, None)       # chain broken: no balance to compare against
            continue
        p = prev.get(e.account_key)
        if p is not None:
            expected = p + e.amount_paise if e.direction == "CR" else p - e.amount_paise
            if abs(expected - e.balance_paise) > tol:
                e.warnings.append("BALANCE_MISMATCH")
                result.problems.append({
                    "row_ref": e.source_row_ref, "code": "BALANCE_MISMATCH", "severity": "warning",
                    "message": f"expected balance {expected / 100:.2f}, statement shows {e.balance_paise / 100:.2f} "
                               f"(account={e.account_raw}, entry_id={e.entry_id})"})
        prev[e.account_key] = e.balance_paise
