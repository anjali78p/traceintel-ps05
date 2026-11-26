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
| Passive domain/IP enrichment (RDAP, DNS via DoH, crt.sh CT, Team Cymru ASN, PTR), SQLite cache, offline mode, honest per-source status | Tested on synthetic fixtures. **Live-verified (Codespaces):** RDAP, DNS (A/AAAA/MX/NS/TXT/CNAME/PTR), Team Cymru ASN, cache, offline mode, error handling. **Not verified live:** crt.sh CT (unreachable from Codespaces during testing), Cloudflare DoH fallback |
| Suggested infrastructure relationships (shared IP / NS / ASN / certificate) with strength + caveat, never "strong" | Implemented + tested |
| Case service: SQLite persistence, evidence register (SHA-256), hash-chained audit log, analysis-run history, enrichment storage, demo seeding | Implemented + tested (stdlib `sqlite3`, not SQLAlchemy/Postgres) |
| Report generator: PDF (10 sections + appendix) and Excel (12 sheets), FACT/INDICATOR/SUGGESTED/INVESTIGATOR labels, evidence refs, config + limitations, blank investigator-notes section | Implemented + tested (PDF visually inspected) |
| Draft information requests (bank / registrar / hosting): UTR, timestamps in IST+UTC, legal-process wording, placeholders | Implemented + tested (drafts only; never issued) |
| FastAPI wrapper (`traceintel/api.py`) incl. report/request endpoints | Written; **not yet run/verified** |
| React UI | **Not yet** |
| Financial<->digital correlation, evidence register, PDF/Excel report, info-request drafts | **Not yet** |

## Run
    pip install -r requirements.txt
    python -m traceintel.synthetic                       # regenerate synthetic data
    python -m traceintel.cli data/synthetic/statements_all.csv --utr 699999999001
    python -m unittest discover -s tests -v              # or: pytest
    python -m traceintel.report_cli --out reports       # demo PDF + Excel + draft requests (synthetic)
    uvicorn traceintel.api:app --reload                  # API at http://127.0.0.1:8000/docs ; then POST /demo/seed
    python -m traceintel.infra.cli --demo                # synthetic offline demo of domain/IP intelligence
    python -m traceintel.infra.cli --domain example.com --ip 93.184.216.34   # LIVE passive lookups (needs internet)
    python -m traceintel.infra.cli --domain example.com --offline            # cache only

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

## Infrastructure module notes
- Passive only: queries public data services (rdap.org, dns.google DoH, crt.sh, Team Cymru DNS), never the suspect host.
- Fixtures in `traceintel/infra/fixtures.py` are hand-written in the shape of real responses (reserved `.example` names,
  documentation IP ranges); they are not recordings. Live behaviour must be verified before relying on it.
- Registrant personal data is not retained (only a published/redacted flag). Geolocation = registration country, indicative.
- DNS uses Google DoH, falling back to Cloudflare DoH on failure; the answering resolver is recorded in each observation.
- Team Cymru ASN lookups sometimes return SERVFAIL; this is reported as an error (never as 'no data').
- crt.sh was unreachable from the test environment (`Network is unreachable`); CT is optional and its failure never breaks a case.
