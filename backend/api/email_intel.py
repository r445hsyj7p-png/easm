"""
Email Attack Surface Intelligence — FastAPI router.
Mounted in main.py under /api/v1/tenants/{tenant_id}/email-intel/
"""
from __future__ import annotations
import asyncio
import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.main import get_auth, AuthContext, limiter
from db.database import get_db
from easm_email.models import (
    AnalyzeRequest, AnalyzeResponse, ResultResponse,
    EmailFinding, GraphSummary, DomainListItem,
)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/email-intel",
    tags=["Email Intelligence"],
)


def _risk_band(score: int) -> str:
    if score <= 25: return "Low"
    if score <= 50: return "Medium"
    if score <= 75: return "High"
    return "Critical"


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
    await db.execute(text("""
        INSERT INTO email_intel_jobs (id, tenant_id, domain, status, created_at)
        VALUES (:id, :tid, :domain, 'pending', :now)
    """), {"id": job_id, "tid": tenant_id, "domain": body.domain,
           "now": datetime.now(timezone.utc)})
    await db.commit()

    # Dispatch to dedicated email-intel Celery worker
    from workers.email_intel_tasks import email_intel_analyze
    email_intel_analyze.delay(job_id, body.domain, tenant_id)

    return AnalyzeResponse(job_id=job_id, status="pending")


# ── GET /result/{job_id} ───────────────────────────────────────────────────────

@router.get("/result/{job_id}", response_model=ResultResponse)
async def get_result(
    tenant_id: str,
    job_id: str,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)

    row = (await db.execute(text("""
        SELECT id, tenant_id, domain, status, risk_score,
               spf_raw, dmarc_raw, mx_records, findings, graph_summary,
               error, created_at, completed_at
        FROM email_intel_jobs
        WHERE id = :id AND tenant_id = :tid
    """), {"id": job_id, "tid": tenant_id})).mappings().first()

    if not row:
        raise HTTPException(status_code=404, detail="Job nicht gefunden.")

    findings: list[EmailFinding] = []
    if row["findings"]:
        raw = row["findings"] if isinstance(row["findings"], list) else json.loads(row["findings"])
        findings = [EmailFinding(**f) for f in raw]

    summary: GraphSummary | None = None
    if row["graph_summary"]:
        raw = row["graph_summary"] if isinstance(row["graph_summary"], dict) else json.loads(row["graph_summary"])
        summary = GraphSummary(**raw)

    mx_records: list[dict] = []
    if row["mx_records"]:
        mx_records = row["mx_records"] if isinstance(row["mx_records"], list) else json.loads(row["mx_records"])

    # Fetch Neo4j graph when analysis is complete (non-fatal)
    graph_json: dict | None = None
    if row["status"] == "complete":
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

    # Verify domain belongs to this tenant
    exists = (await db.execute(text("""
        SELECT 1 FROM email_intel_jobs
        WHERE tenant_id = :tid AND domain = :domain AND status = 'complete'
        LIMIT 1
    """), {"tid": tenant_id, "domain": domain})).first()

    if not exists:
        raise HTTPException(status_code=404, detail="Keine abgeschlossene Analyse für diese Domain.")

    try:
        from easm_email.graph_builder import get_graph_json
        graph = await asyncio.to_thread(get_graph_json, domain, tenant_id)
        return graph
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

    # Prefer complete > failed > running/pending for each domain so the list
    # shows the last successful result even while a re-analysis is in progress.
    rows = (await db.execute(text("""
        SELECT DISTINCT ON (domain)
            id, domain, status, risk_score, created_at, completed_at
        FROM email_intel_jobs
        WHERE tenant_id = :tid
        ORDER BY domain,
                 CASE status WHEN 'complete' THEN 0 WHEN 'failed' THEN 1 ELSE 2 END,
                 created_at DESC
        LIMIT :limit
    """), {"tid": tenant_id, "limit": limit})).mappings().all()

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

    await db.execute(text("""
        DELETE FROM email_intel_jobs WHERE tenant_id = :tid AND domain = :domain
    """), {"tid": tenant_id, "domain": domain})
    await db.commit()

    # Best-effort graph cleanup
    try:
        from easm_email.graph_builder import delete_domain_graph
        await asyncio.to_thread(delete_domain_graph, domain, tenant_id)
    except Exception:
        pass
