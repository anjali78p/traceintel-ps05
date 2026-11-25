# TRACEINTEL — PS05 Financial Crime Infrastructure & Money-Trail Analysis

Investigation-support tool. **Synthetic data only.** Outputs are review-priority indicators and *possible* transaction
paths — never proof of guilt or proven fund movement.

## Status (honest)
| Component | State |
|---|---|
| CSV / XLSX / PDF-table ingestion, validation, balance check, duplicate-UTR detection | Implemented + tested |
| Two-layer model: ledger rows -> derived transfers (observed / one-sided / weak) with provenance | Implemented + tested |
| Rules: fan-in, fan-out, rapid pass-through, velocity, 24h turnover, dormant->active, layering, circular, round-figure | Implemented + tested (configurable in `config.yaml`) |
| Multi-hop trail from UTR/account (time-respecting, commingling flags, graph JSON for React Flow) | Implemented + tested |
| DB (SQLAlchemy), FastAPI, React UI | **Not yet** |
| RDAP/DNS/CT/ASN enrichment, correlation graph, evidence register, PDF/Excel report, info-request drafts | **Not yet** |

## Run
    pip install -r requirements.txt
    python -m traceintel.synthetic                       # regenerate synthetic data
    python -m traceintel.cli data/synthetic/statements_all.csv --utr 699999999001
    python -m unittest discover -s tests -v              # or: pytest

## Key design decisions
- Statements are per-account ledgers, so rows are kept as-is (Layer 1) and account-to-account edges are *derived* (Layer 2).
  `utr_both_sides` = observed in two statements; `utr_one_side`/`counterparty_only` = counterparty text, unverified.
- Money in integer paise. Statement timestamps assumed IST (`ingest.timezone`), stored as UTC.
- Problem rows are never dropped: status `invalid`/`duplicate` + warning codes + source row reference.
- Trail `carried_upper_bound` = min amount along the path; hops where the account received other money recently are marked
  `commingled`. Exact fund attribution is not claimed.

## Known limitations
Rules use configurable heuristics and can false-positive on legitimate activity (each finding states its limitation).
Dormancy only works if history is in the statement. PDF support = ruled tables only (no OCR). Real R4C statement
formats are unseen: add header aliases in `ingest.HEADER_ALIASES` once the sample arrives.
