"""
Email Attack Surface Intelligence — FastAPI router.
Mounted in main.py under /api/v1/tenants/{tenant_id}/email-intel/
"""
from __future__ import annotations
import asyncio
import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from api.main import get_auth, AuthContext, limiter
from db.database import get_db
from db import repo
from easm_email.job_status import JobStatus
from easm_email.models import (
    AnalyzeRequest, AnalyzeResponse, ResultResponse,
    EmailFinding, GraphSummary, DomainListItem,
)
from easm_email.risk_scorer import risk_band as _risk_band


def _parse_jsonb(value, expect_list: bool):
    """Deserialise a JSONB column that asyncpg may return already-parsed or as a JSON string."""
    if value is None:
        return [] if expect_list else None
    if isinstance(value, (list, dict)):
        return value
    return json.loads(value)


router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/email-intel",
    tags=["Email Intelligence"],
)


# ── POST /analyze ──────────────────────────────────────────────────────────────

@router.post("/analyze", response_model=AnalyzeResponse)
@limiter.limit("10/minute")
async def analyze(
    request: Request,    # required by SlowAPI
    tenant_id: str,
    body: AnalyzeRequest,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)

    job_id = str(uuid.uuid4())
    try:
        await repo.email_intel_create_job(db, job_id, tenant_id, body.domain)
    except Exception as exc:
        exc_name = type(exc).__name__
        exc_msg  = str(exc)
        if "email_intel_jobs" in exc_msg or "UndefinedTable" in exc_name or "does not exist" in exc_msg:
            raise HTTPException(
                status_code=503,
                detail="Tabelle email_intel_jobs fehlt — bitte 'alembic upgrade head' ausführen "
                       "oder Container neu bauen (CACHEBUST aktualisieren).",
            )
        raise HTTPException(status_code=503, detail=f"Datenbankfehler: {exc_name}: {exc_msg}")

    try:
        from workers.email_intel_tasks import email_intel_analyze
        email_intel_analyze.delay(job_id, body.domain, tenant_id)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Celery-Worker nicht erreichbar (worker-email-intel läuft?): {exc}",
        )

    return AnalyzeResponse(job_id=job_id, status=JobStatus.PENDING)


# ── GET /result/{job_id} ───────────────────────────────────────────────────────

@router.get("/result/{job_id}", response_model=ResultResponse)
async def get_result(
    tenant_id: str,
    job_id: str,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)

    row = await repo.email_intel_get_job(db, job_id, tenant_id)
    if not row:
        raise HTTPException(status_code=404, detail="Job nicht gefunden.")

    findings = [EmailFinding(**f) for f in (_parse_jsonb(row["findings"], expect_list=True) or [])]
    raw_summary = _parse_jsonb(row["graph_summary"], expect_list=False)
    summary: GraphSummary | None = GraphSummary(**raw_summary) if raw_summary else None
    mx_records: list[dict] = _parse_jsonb(row["mx_records"], expect_list=True) or []

    graph_json: dict | None = None
    if row["status"] == JobStatus.COMPLETE:
        try:
            from easm_email.graph_builder import get_graph_json
            graph_json = await asyncio.to_thread(get_graph_json, row["domain"], tenant_id)
        except Exception:
            pass  # Neo4j unavailable — result still useful

    score = row["risk_score"]
    return ResultResponse(
        job_id=str(row["id"]),
        domain=row["domain"],
        status=row["status"],
        risk_score=score,
        risk_band=_risk_band(score) if score is not None else None,
        findings=findings,
        graph_summary=summary,
        graph_json=graph_json,
        spf_raw=row["spf_raw"],
        dmarc_raw=row["dmarc_raw"],
        mx_records=mx_records,
        created_at=row["created_at"],
        completed_at=row["completed_at"],
        error=row["error"],
    )


# ── GET /graph/{domain} ────────────────────────────────────────────────────────

@router.get("/graph/{domain:path}")
async def get_graph(
    tenant_id: str,
    domain: str,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)

    if not await repo.email_intel_has_complete_job(db, tenant_id, domain):
        raise HTTPException(status_code=404, detail="Keine abgeschlossene Analyse für diese Domain.")

    try:
        from easm_email.graph_builder import get_graph_json
        return await asyncio.to_thread(get_graph_json, domain, tenant_id)
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Graph-Datenbank nicht erreichbar: {e}")


# ── GET /domains ───────────────────────────────────────────────────────────────

@router.get("/domains", response_model=list[DomainListItem])
async def list_domains(
    tenant_id: str,
    limit: int = Query(50, ge=1, le=200),
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)

    rows = await repo.email_intel_list_domains(db, tenant_id, limit)
    return [
        DomainListItem(
            job_id=str(r["id"]),
            domain=r["domain"],
            status=r["status"],
            risk_score=r["risk_score"],
            risk_band=_risk_band(r["risk_score"]) if r["risk_score"] is not None else None,
            created_at=r["created_at"],
            completed_at=r["completed_at"],
        )
        for r in rows
    ]


# ── DELETE /domains/{domain} ───────────────────────────────────────────────────

@router.delete("/domains/{domain:path}", status_code=204)
async def delete_domain(
    tenant_id: str,
    domain: str,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)

    await repo.email_intel_delete_domain(db, tenant_id, domain)

    try:
        from easm_email.graph_builder import delete_domain_graph
        await asyncio.to_thread(delete_domain_graph, domain, tenant_id)
    except Exception:
        pass
