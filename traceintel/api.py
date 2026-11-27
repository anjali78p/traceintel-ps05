"""Thin FastAPI wrapper over CaseService. All logic lives in service.py (unit-tested); this file only maps HTTP <-> service.

Run:  uvicorn traceintel.api:app --reload        (docs at /docs)
Env:  TRACEINTEL_DB (default traceintel.db), TRACEINTEL_UPLOADS (default uploads/)
"""
from __future__ import annotations
import os
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .infra.cache import Cache
from .infra.enrich import Enricher
from .infra.http import UrllibHttp
from .reporting import collect, generate_reports
from .service import CaseNotFound, CaseService, seed_demo

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "synthetic"
UPLOADS = Path(os.environ.get("TRACEINTEL_UPLOADS", "uploads"))

svc = CaseService(os.environ.get("TRACEINTEL_DB", "traceintel.db"))
app = FastAPI(title="TRACEINTEL", version="0.3",
              description="Investigation-support API. Outputs are review-priority indicators and possible transaction paths, "
                          "not proof of wrongdoing. Use synthetic data only.")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                   allow_methods=["*"], allow_headers=["*"])


class CaseIn(BaseModel):
    title: str
    case_number: Optional[str] = None
    is_synthetic: bool = True


class EnrichIn(BaseModel):
    domains: List[str] = []
    ips: List[str] = []
    offline: bool = False


def _guard(fn, *a, **k):
    try:
        return fn(*a, **k)
    except CaseNotFound as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/health")
def health():
    return {"status": "ok", "cases": len(svc.list_cases())}


@app.post("/cases")
def create_case(body: CaseIn):
    cid = svc.create_case(body.title, body.case_number, body.is_synthetic)
    return svc.get_case(cid)


@app.get("/cases")
def list_cases():
    return svc.list_cases()


@app.get("/cases/{cid}")
def get_case(cid: int):
    return _guard(svc.get_case, cid)


@app.post("/demo/seed")
def demo_seed():
    """Creates the labelled SYNTHETIC demo case (statements + analysis + fixture-based infrastructure intel)."""
    cid = seed_demo(svc, DATA_DIR)
    return svc.get_case(cid)


@app.post("/cases/{cid}/files")
async def upload_file(cid: int, file: UploadFile = File(...), bank_name: str = Form("UNSPECIFIED"),
                      default_account: Optional[str] = Form(None)):
    _guard(svc.get_case, cid)
    dest_dir = UPLOADS / f"case_{cid}"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / Path(file.filename or "upload").name          # strip any path components
    dest.write_bytes(await file.read())
    return _guard(svc.add_statement, cid, dest, bank_name, default_account)


@app.get("/cases/{cid}/problems")
def problems(cid: int):
    return _guard(svc.get_problems, cid)


@app.get("/cases/{cid}/entries")
def entries(cid: int, status: Optional[str] = None, account: Optional[str] = None):
    return _guard(svc.get_entries, cid, status, account)


@app.post("/cases/{cid}/analyze")
def analyze(cid: int):
    return _guard(svc.run_analysis, cid)


@app.get("/cases/{cid}/accounts")
def accounts(cid: int):
    return _guard(svc.get_assessments, cid)


@app.get("/cases/{cid}/transfers")
def transfers(cid: int):
    from dataclasses import asdict
    return [asdict(t) for t in _guard(svc.get_transfers, cid)]


@app.get("/cases/{cid}/trail")
def trail(cid: int, utr: Optional[str] = None, account: Optional[str] = None, max_hops: Optional[int] = None):
    if not utr and not account:
        raise HTTPException(400, "provide utr or account")
    return _guard(svc.trail, cid, utr, account, max_hops)


@app.post("/cases/{cid}/enrich")
def enrich(cid: int, body: EnrichIn):
    if not body.domains and not body.ips:
        raise HTTPException(400, "provide domains and/or ips")
    cfg = svc.cfg
    enr = Enricher(UrllibHttp(cfg["infra"]["http_timeout_seconds"], cfg["infra"]["min_interval_seconds"]),
                   Cache(os.environ.get("TRACEINTEL_INFRA_CACHE", "infra_cache.db")), cfg, offline=body.offline)
    return _guard(svc.enrich, cid, enr, body.domains, body.ips)


@app.get("/cases/{cid}/infrastructure")
def infrastructure(cid: int):
    return {"enrichments": _guard(svc.get_enrichments, cid), "suggested_relationships": svc.get_relationships(cid)}


@app.get("/cases/{cid}/evidence")
def evidence(cid: int):
    return _guard(svc.get_evidence, cid)


@app.get("/cases/{cid}/audit")
def audit(cid: int):
    _guard(svc.get_case, cid)
    return svc.get_audit(cid)


@app.get("/audit/verify")
def audit_verify():
    return svc.verify_audit()


REPORTS = Path(os.environ.get("TRACEINTEL_REPORTS", "reports"))


def _report_file(cid: int, kind: str, victim_utr: Optional[str]):
    paths = _guard(generate_reports, svc, cid, REPORTS, victim_utr)
    return paths[kind]


@app.get("/cases/{cid}/report.pdf")
def report_pdf(cid: int, victim_utr: Optional[str] = None):
    p = _report_file(cid, "pdf", victim_utr)
    return FileResponse(p, media_type="application/pdf", filename=Path(p).name)


@app.get("/cases/{cid}/report.xlsx")
def report_xlsx(cid: int, victim_utr: Optional[str] = None):
    p = _report_file(cid, "xlsx", victim_utr)
    return FileResponse(p, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", filename=Path(p).name)


@app.get("/cases/{cid}/requests")
def info_requests(cid: int, victim_utr: Optional[str] = None):
    """Draft information requests (bank/registrar/hosting). Drafts only; issued by an authorised officer via legal process."""
    return _guard(collect, svc, cid, victim_utr)["requests"]


FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
if FRONTEND.exists():
    app.mount("/ui", StaticFiles(directory=str(FRONTEND), html=True), name="ui")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/ui/")
