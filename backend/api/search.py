"""
api/search.py — Global search router (DB-backed in production)
"""
from fastapi import APIRouter, Depends, Query
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from db.database import get_db
from api.deps import get_auth, AuthContext
from search.search_service import SearchService

search_router = APIRouter(prefix="/api/v1/search", tags=["Search"])
_service = SearchService()


@search_router.get("")
async def global_search(
    q: str = Query(..., description="Query string e.g. 'severity:critical has:kev'"),
    scope:  str = Query("all"),
    limit:  int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    sort:   str = Query("relevance"),
    order:  str = Query("desc"),
    ctx: AuthContext   = Depends(get_auth),
    db: AsyncSession   = Depends(get_db),
):
    return await _service.search_db(
        q=q, db=db, tenant_id=ctx.tenant_id,
        scope=scope, limit=limit, offset=offset, sort=sort, order=order,
    )


@search_router.get("/syntax")
async def search_syntax():
    return {
        "filters": {
            "severity":  {"syntax": "severity:critical,high"},
            "status":    {"syntax": "status:open"},
            "category":  {"syntax": "cat:mcp  oder  tag:mcp-exposure"},
            "tool":      {"syntax": "tool:nuclei"},
            "has":       {"syntax": "has:cve  has:kev  has:ticket  has:no-ticket"},
            "cvss":      {"syntax": "cvss:>=9  oder  cvss:7..10"},
            "epss":      {"syntax": "epss:>=0.9"},
            "age":       {"syntax": "age:<7  (jünger als 7 Tage)"},
            "port":      {"syntax": "port:6274"},
            "subdomain": {"syntax": "subdomain:*.example.de"},
            "ip":        {"syntax": "ip:203.0.113.0/24"},
            "org":       {"syntax": "org:hetzner"},
            "cve":       {"syntax": "cve:CVE-2024-3400"},
        },
        "examples": [
            "severity:critical has:kev",
            "tool:nuclei cvss:>=9 status:open",
            "age:<7 has:no-ticket severity:critical,high",
            "cat:mcp has:cve",
            "port:6274 OR port:6277",
        ],
    }
