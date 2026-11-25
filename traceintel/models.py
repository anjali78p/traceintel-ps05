from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


def inr(paise: Optional[int]) -> Optional[float]:
    return None if paise is None else paise / 100


@dataclass
class LedgerEntry:
    """One row exactly as seen in a statement (Layer 1). Never dropped, only flagged."""
    entry_id: int
    file_name: str
    source_row_ref: str
    account_raw: str
    account_key: str
    bank: str
    ts_raw: str
    ts_utc: Optional[datetime]
    direction: Optional[str]          # DR / CR
    amount_paise: Optional[int]
    balance_paise: Optional[int]
    counterparty_raw: str
    counterparty_key: str
    utr: Optional[str]
    narration: str
    status: str = "ok"                # ok | invalid | duplicate
    warnings: list = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return (self.status == "ok" and self.ts_utc is not None
                and self.direction in ("DR", "CR") and bool(self.amount_paise))


@dataclass
class Transfer:
    """Derived account-to-account edge (Layer 2) with provenance back to ledger rows."""
    transfer_id: int
    from_key: str
    to_key: str
    amount_paise: int
    ts_utc: datetime
    utr: Optional[str]
    method: str                       # utr_both_sides | utr_one_side | counterparty_only
    confidence: str                   # high | medium | low
    debit_entry_id: Optional[int]
    credit_entry_id: Optional[int]
    notes: list = field(default_factory=list)
