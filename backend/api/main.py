"""
EASM MSSP Platform — FastAPI Backend (Production)
All endpoints backed by PostgreSQL. No demo data in request path.
"""
from fastapi import FastAPI, Depends, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.responses import Response, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from contextlib import asynccontextmanager
from contextvars import ContextVar
from pydantic import BaseModel, EmailStr, validator
from typing import Optional
from datetime import datetime, timedelta, timezone
import uuid, json, os, secrets as _secrets, logging
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from sqlalchemy.ext.asyncio import AsyncSession

from db.database import get_db
from db import repo

# Shared auth / rate-limiting — imported BEFORE any sub-routers to avoid
# circular imports (email_intel.py and search.py import from api.deps, not
# from api.main).
from api.deps import (
    limiter, AuthContext, get_auth, bearer,
    create_jwt, decode_jwt, hash_pw, verify_pw,
    JWT_EXPIRE_HOURS, SECRET_KEY,
)

# ─── Correlation-ID context ───────────────────────────────────────────────────
request_id_var: ContextVar[str] = ContextVar("request_id", default="")

class _RequestIDFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get("—")  # type: ignore[attr-defined]
        return True

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(request_id)s] %(levelname)s %(name)s: %(message)s",
)
for _h in logging.root.handlers:
    _h.addFilter(_RequestIDFilter())

logger = logging.getLogger(__name__)

# ─── Config ──────────────────────────────────────────────────────────────────
USERS_FILE = os.environ.get("USERS_FILE", "/data/users.json")

# ─── Pydantic models ──────────────────────────────────────────────────────────

class SetupRequest(BaseModel):
    email: EmailStr
    password: str
    name: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    expires_in:   int = JWT_EXPIRE_HOURS * 3600
    tenant_id:    str
    role:         str
    user_name:    str

class FindingUpdateRequest(BaseModel):
    status:     str
    ticket_ref: Optional[str] = None
    note:       Optional[str] = None

class ScanRequest(BaseModel):
    scan_type: str = "full"
    scan_mode: str = "active"  # "passive" | "active"

    @validator("scan_mode")
    def _validate_mode(cls, v: str) -> str:
        if v not in ("passive", "active"):
            raise ValueError("scan_mode must be 'passive' or 'active'")
        return v

class DomainCreateRequest(BaseModel):
    domain: str
    ip_ranges: list[str] = []
    panos_version: str = ""

class DomainUpdateRequest(BaseModel):
    status:        Optional[str]       = None
    ip_ranges:     Optional[list[str]] = None
    panos_version: Optional[str]       = None

# ─── Request-ID Middleware ────────────────────────────────────────────────────

class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/api/v1/health":
            return await call_next(request)
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        token = request_id_var.set(rid)
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = rid
        return response

# ─── App lifecycle ────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield

app = FastAPI(
    title="EASM MSSP Platform API",
    version="1.0.0",
    description="""
## External Attack Surface Management

REST API der EASM MSSP Plattform. Alle Endpunkte erfordern JWT-Authentifizierung
(außer `/auth/status` und `/auth/login`).

**Rollen:** `mssp_admin` · `mssp_analyst` · `customer_admin` · `customer_viewer`
""",
    openapi_tags=[
        {"name": "Auth",         "description": "Login, Setup, Token-Verwaltung"},
        {"name": "System",       "description": "Health-Check und Status"},
        {"name": "Tenants",      "description": "Mandanten-Stammdaten"},
        {"name": "Findings",     "description": "Sicherheitsbefunde verwalten"},
        {"name": "Assets",       "description": "Erkannte Assets und Subdomains"},
        {"name": "Scans",        "description": "Scan-Jobs steuern und überwachen"},
        {"name": "MCP",          "description": "MCP-Server Erkennung"},
        {"name": "Intelligence", "description": "Threat-Intelligence Snapshots"},
        {"name": "MSSP",         "description": "MSSP-Überblick (nur für Admins)"},
    ],
    docs_url=None,
    redoc_url=None,
    contact={"name": "EASM MSSP Operations"},
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

_cors_origins_raw = os.environ.get("CORS_ALLOWED_ORIGINS", "")
_cors_origins = [o.strip() for o in _cors_origins_raw.split(",") if o.strip()] or ["*"]

# Middleware-Reihenfolge: LIFO → RequestID ist äußerste Schicht
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestIDMiddleware)
app.add_exception_handler(Exception, _unhandled_exception_handler)

# ─── Search router ────────────────────────────────────────────────────────────
try:
    from api.search import search_router
    app.include_router(search_router)
except ImportError:
    pass

# ─── Email Intelligence router ────────────────────────────────────────────────
_email_intel_import_error: str | None = None
try:
    from api.email_intel import router as email_intel_router
    app.include_router(email_intel_router)
    logger.info("email_intel router registered OK")
except Exception as _e:
    import traceback as _tb
    _email_intel_import_error = f"{type(_e).__name__}: {_e}"
    logger.error(
        "email_intel router NOT registered — import failed: %s\n%s",
        _email_intel_import_error,
        _tb.format_exc(),
    )
    # Register a catch-all fallback so callers get 503 (with the real error) instead of 404.
    @app.api_route(
        "/api/v1/tenants/{tenant_id}/email-intel/{path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
        include_in_schema=False,
    )
    async def _email_intel_unavailable(tenant_id: str, path: str = ""):
        raise HTTPException(
            status_code=503,
            detail=(
                "Email Intelligence Modul konnte nicht geladen werden. "
                f"Fehler: {_email_intel_import_error}. "
                "Container neu bauen: "
                "docker compose build --no-cache api worker-email-intel && "
                "docker compose up -d api worker-email-intel"
            ),
        )

# ─── Docs (gesichert, nur MSSP-Rollen) ───────────────────────────────────────

@app.get("/docs", include_in_schema=False)
async def swagger_ui(ctx: AuthContext = Depends(get_auth)):
    if ctx.role not in ("mssp_admin", "mssp_analyst"):
        raise HTTPException(status_code=403, detail="Swagger-UI nur für MSSP-Mitarbeiter.")
    return get_swagger_ui_html(openapi_url="/openapi.json", title="EASM API — Swagger UI")

@app.get("/redoc", include_in_schema=False)
async def redoc_ui(ctx: AuthContext = Depends(get_auth)):
    if ctx.role not in ("mssp_admin", "mssp_analyst"):
        raise HTTPException(status_code=403, detail="ReDoc nur für MSSP-Mitarbeiter.")
    return get_redoc_html(openapi_url="/openapi.json", title="EASM API — ReDoc")

@app.get("/openapi.json", include_in_schema=False)
async def openapi_schema(ctx: AuthContext = Depends(get_auth)):
    if ctx.role not in ("mssp_admin", "mssp_analyst"):
        raise HTTPException(status_code=403)
    return JSONResponse(app.openapi())

# ═══════════════════════════════════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/auth/status", tags=["Auth"])
async def auth_status(db: AsyncSession = Depends(get_db)):
    """Returns whether initial setup is required."""
    count = await repo.user_count(db)
    return {"setup_required": count == 0}


@app.post("/api/v1/auth/setup", response_model=LoginResponse, tags=["Auth"])
async def setup(request: Request, req: SetupRequest, db: AsyncSession = Depends(get_db)):
    """Creates the first admin account. Only callable once."""
    count = await repo.user_count(db)
    if count > 0:
        raise HTTPException(status_code=403, detail="Einrichtung bereits abgeschlossen.")
    if len(req.password) < 8:
        raise HTTPException(status_code=422, detail="Passwort muss mindestens 8 Zeichen haben.")

    tenant_id = await repo.ensure_default_tenant(db)
    user_id   = await repo.create_user(
        db, req.email, hash_pw(req.password), req.name, "mssp_admin", tenant_id
    )
    token = create_jwt(user_id, tenant_id, "mssp_admin")
    return LoginResponse(
        access_token=token, tenant_id=tenant_id,
        role="mssp_admin", user_name=req.name,
    )


@app.post("/api/v1/auth/login", response_model=LoginResponse, tags=["Auth"])
@limiter.limit("10/minute;30/hour")
async def login(request: Request, req: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate and receive a JWT."""
    count = await repo.user_count(db)
    if count == 0:
        raise HTTPException(status_code=403,
            detail="Ersteinrichtung erforderlich — bitte Admin-Account anlegen.")

    user = await repo.get_user_by_email(db, req.email)
    if not user or not verify_pw(req.password, user.get("pw_hash", "")):
        raise HTTPException(status_code=401, detail="E-Mail oder Passwort falsch.")
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account deaktiviert.")

    token = create_jwt(user["id"], user["tenant_id"], user["role"])
    return LoginResponse(
        access_token=token,
        tenant_id=user["tenant_id"],
        role=user["role"],
        user_name=user.get("full_name", req.email),
    )

# ═══════════════════════════════════════════════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/health", tags=["System"])
async def health(db: AsyncSession = Depends(get_db)):
    try:
        from sqlalchemy import text
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    email_ok = _email_intel_import_error is None
    status = "ok" if (db_ok and email_ok) else "degraded"
    resp = {"status": status, "db": db_ok, "version": "1.0.0", "email_intel": email_ok}
    if not email_ok:
        resp["email_intel_error"] = _email_intel_import_error
    return resp

# ═══════════════════════════════════════════════════════════════════════════════
# TENANT
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/tenants/{tenant_id}", tags=["Tenants"])
async def get_tenant(
    tenant_id: str,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    tenant = await repo.get_tenant(db, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Mandant nicht gefunden.")
    return tenant

# ═══════════════════════════════════════════════════════════════════════════════
# FINDINGS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/tenants/{tenant_id}/findings", tags=["Findings"])
async def list_findings(
    tenant_id: str,
    severity:  Optional[str] = None,
    status:    Optional[str] = None,
    category:  Optional[str] = None,
    limit:     int = Query(200, ge=1, le=500),
    offset:    int = Query(0, ge=0),
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    return await repo.list_findings(db, tenant_id, severity, status, category, limit, offset)


@app.patch("/api/v1/tenants/{tenant_id}/findings/{finding_id}", tags=["Findings"])
@limiter.limit("100/minute")
async def update_finding(
    request: Request,
    tenant_id:  str,
    finding_id: str,
    req: FindingUpdateRequest,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    ok = await repo.update_finding_status(db, tenant_id, finding_id, req.status, req.ticket_ref)
    if not ok:
        raise HTTPException(status_code=404, detail="Finding nicht gefunden.")
    # Recalculate score in background
    await repo.upsert_tenant_score(db, tenant_id)
    return {"ok": True}

# ═══════════════════════════════════════════════════════════════════════════════
# ASSETS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/tenants/{tenant_id}/assets", tags=["Assets"])
async def list_assets(
    tenant_id: str,
    limit:  int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    return await repo.list_assets(db, tenant_id, limit, offset)

# ═══════════════════════════════════════════════════════════════════════════════
# DOMAINS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/tenants/{tenant_id}/domains", tags=["Tenants"])
async def list_domains(
    tenant_id: str,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    return await repo.list_domains(db, tenant_id)


@app.post("/api/v1/tenants/{tenant_id}/domains", tags=["Tenants"])
async def create_domain(
    tenant_id: str,
    req: DomainCreateRequest,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    if not req.domain.strip():
        raise HTTPException(status_code=422, detail="Domain darf nicht leer sein.")
    try:
        return await repo.create_domain(db, tenant_id, req.domain, req.ip_ranges, req.panos_version)
    except ValueError as e:
        msg = str(e)
        status = 404 if "Mandant nicht gefunden" in msg else 409
        raise HTTPException(status_code=status, detail=msg)
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=409, detail=str(e))


@app.patch("/api/v1/tenants/{tenant_id}/domains/{domain_id}", tags=["Tenants"])
async def update_domain(
    tenant_id: str,
    domain_id: str,
    req: DomainUpdateRequest,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    ok = await repo.update_domain(db, tenant_id, domain_id,
                                   status=req.status, ip_ranges=req.ip_ranges,
                                   panos_version=req.panos_version)
    if not ok:
        raise HTTPException(status_code=404, detail="Domain nicht gefunden.")
    return {"ok": True}


@app.delete("/api/v1/tenants/{tenant_id}/domains/{domain_id}", tags=["Tenants"])
async def delete_domain(
    tenant_id: str,
    domain_id: str,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    ok = await repo.delete_domain(db, tenant_id, domain_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Domain nicht gefunden.")
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════════════
# SETTINGS (Schedule + Notifications)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/tenants/{tenant_id}/settings", tags=["Tenants"])
async def get_settings(
    tenant_id: str,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    return await repo.get_settings(db, tenant_id)


@app.put("/api/v1/tenants/{tenant_id}/settings", tags=["Tenants"])
async def save_settings(
    tenant_id: str,
    request: Request,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    settings = await request.json()
    await repo.save_settings(db, tenant_id, settings)
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════════════
# MCP
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/tenants/{tenant_id}/mcp", tags=["MCP"])
async def list_mcp_servers(
    tenant_id: str,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    return await repo.list_mcp_servers(db, tenant_id)

# ═══════════════════════════════════════════════════════════════════════════════
# INTEL
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/tenants/{tenant_id}/intel", tags=["Intelligence"])
async def get_intel(
    tenant_id: str,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    return await repo.get_intel(db, tenant_id)

# ═══════════════════════════════════════════════════════════════════════════════
# SCANS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/tenants/{tenant_id}/scans", tags=["Scans"])
async def list_scans(
    tenant_id: str,
    limit:  int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    return await repo.list_scans(db, tenant_id, limit, offset)


@app.post("/api/v1/tenants/{tenant_id}/scans", tags=["Scans"])
@limiter.limit("10/hour")
async def trigger_scan(
    request: Request,
    tenant_id: str,
    req: ScanRequest,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)

    # quick scan is always passive — enforce server-side
    effective_mode = "passive" if req.scan_type == "quick" else req.scan_mode

    # Encode mode into stored scan_type so the history table can display it
    # without a schema migration.  Format: "<type>/<mode>"  e.g. "full/active"
    stored_type = f"{req.scan_type}/{effective_mode}"
    scan_id = await repo.create_scan_job(db, tenant_id, stored_type, "manual")

    # Dispatch to Celery
    try:
        from sqlalchemy import text
        from workers.toolchain_tasks import run_full_pipeline

        # Load tenant domain + api_keys (settings) in one query so the worker
        # has everything it needs without a second DB round-trip.
        tenant_row = await db.execute(text("""
            SELECT
                t.settings,
                COALESCE(MIN(d.domain), t.slug, '') AS domain,
                COALESCE(array_agg(DISTINCT r) FILTER (WHERE r IS NOT NULL), '{}') AS ip_ranges,
                COALESCE(MAX(d.panos_version), '') AS panos_version
            FROM tenants t
            LEFT JOIN domains d ON d.tenant_id = t.id AND d.status = 'active'
            LEFT JOIN LATERAL unnest(d.ip_ranges) AS r ON TRUE
            WHERE t.id = :tid
            GROUP BY t.id, t.slug, t.settings
        """), {"tid": tenant_id})
        row = tenant_row.mappings().first() or {}

        import json as _json
        raw_settings = row.get("settings") or {}
        if isinstance(raw_settings, str):
            raw_settings = _json.loads(raw_settings)
        integ = raw_settings.get("integrations", {}) if isinstance(raw_settings, dict) else {}

        api_keys = {
            "hibp":           integ.get("hibp", ""),
            "greynoise":      integ.get("greynoise", ""),
            "abuseipdb":      integ.get("abuseipdb", ""),
            "alienvault_otx": integ.get("alienvault_otx", ""),
            "spyonweb":       integ.get("spyonweb", ""),
            "mcp_url":        integ.get("mcp_url", ""),
            "mcp_token":      integ.get("mcp_token", ""),
        }

        run_full_pipeline.apply_async(
            args=[tenant_id, {
                "scan_id":       scan_id,
                "scan_type":     req.scan_type,
                "scan_mode":     effective_mode,
                "domain":        row.get("domain", ""),
                "ip_ranges":     list(row.get("ip_ranges") or []),
                "panos_version": row.get("panos_version", ""),
                "api_keys":      api_keys,
            }],
            kwargs={"request_id": request_id_var.get()},
            queue="scans",
        )
    except Exception as _dispatch_err:
        logger.warning(f"[trigger_scan] Celery dispatch failed (scan_id={scan_id}): {_dispatch_err}")

    return {
        "scan_id":   scan_id,
        "status":    "pending",
        "id":        scan_id,
        "scan_mode": effective_mode,
    }


@app.get("/api/v1/tenants/{tenant_id}/scans/{scan_id}", tags=["Scans"])
async def get_scan(
    tenant_id: str, scan_id: str,
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    ctx.assert_own_tenant(tenant_id)
    from sqlalchemy import text
    r = await db.execute(text("""
        SELECT id, scan_type, status,
               COALESCE((findings_count->>'CRITICAL')::int, 0) +
               COALESCE((findings_count->>'HIGH')::int,     0) +
               COALESCE((findings_count->>'MEDIUM')::int,   0) +
               COALESCE((findings_count->>'LOW')::int,      0) +
               COALESCE((findings_count->>'INFO')::int,     0) AS findings_count,
               risk_score_after AS risk_score,
               created_at AS started_at, completed_at AS finished_at,
               duration_seconds, error_message,
               COALESCE((raw_results->>'progress_pct')::int, 0) AS progress_pct,
               COALESCE(raw_results->>'current_phase', '') AS current_phase,
               COALESCE(raw_results->'scan_log', '[]'::jsonb) AS scan_log
        FROM scan_jobs
        WHERE id = :sid AND tenant_id = :tid
    """), {"sid": scan_id, "tid": tenant_id})
    row = r.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Scan nicht gefunden.")
    d = dict(row)
    for f in ("started_at", "finished_at"):
        if d.get(f):
            d[f] = d[f].isoformat()
    # scan_log comes back as a string from asyncpg/psycopg — parse if needed
    if isinstance(d.get("scan_log"), str):
        try:
            import json as _json
            d["scan_log"] = _json.loads(d["scan_log"])
        except Exception:
            d["scan_log"] = []
    return d

# ═══════════════════════════════════════════════════════════════════════════════
# MSSP DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/mssp/dashboard", tags=["MSSP"])
async def mssp_dashboard(
    ctx: AuthContext = Depends(get_auth),
    db: AsyncSession  = Depends(get_db),
):
    """Overview of all tenants for MSSP admins."""
    if ctx.role not in ("mssp_admin", "mssp_analyst"):
        raise HTTPException(status_code=403, detail="Nur für MSSP-Mitarbeiter.")
    from sqlalchemy import text
    r = await db.execute(text("""
        SELECT t.id, t.name, t.slug,
               COALESCE(s.score, 0)  AS score,
               COALESCE(s.grade, '?') AS grade,
               COALESCE(s.findings_summary->>'CRITICAL', '0')::int AS critical_count,
               (SELECT MAX(created_at) FROM scan_jobs
                WHERE tenant_id = t.id AND status='completed') AS last_scan
        FROM tenants t
        LEFT JOIN LATERAL (
            SELECT score, grade, findings_summary
            FROM tenant_scores WHERE tenant_id = t.id
            ORDER BY recorded_at DESC LIMIT 1
        ) s ON TRUE
        ORDER BY score ASC
    """))
    tenants = []
    for row in r.mappings().all():
        d = dict(row)
        if d.get("last_scan"):
            d["last_scan"] = d["last_scan"].isoformat()
        tenants.append(d)
    return {"tenants": tenants, "total": len(tenants)}

# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
