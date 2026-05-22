"""
repo.py — Repository layer: all DB queries in one place.
Uses raw SQL via SQLAlchemy text() for clarity and performance.
"""
from datetime import datetime, timezone, timedelta
from typing import Optional
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
import hashlib, json


def _now():
    return datetime.now(timezone.utc)


# ─── Tenant ──────────────────────────────────────────────────────────────────

async def get_tenant(db: AsyncSession, tenant_id: str) -> Optional[dict]:
    r = await db.execute(text("""
        SELECT
            t.id, t.name, t.slug,
            COALESCE(s.score, 0)            AS score,
            COALESCE(s.grade, '?')          AS grade,
            COALESCE(s.findings_summary, '{}')::jsonb AS findings_summary,
            COALESCE(s.asset_counts, '{}')::jsonb     AS assets,
            COALESCE(s.tool_stats, '{}')::jsonb       AS tool_stats,
            t.created_at,
            (SELECT MAX(created_at) FROM scan_jobs
             WHERE tenant_id = t.id AND status = 'completed') AS last_scan
        FROM tenants t
        LEFT JOIN LATERAL (
            SELECT score, grade, findings_summary, asset_counts, tool_stats
            FROM tenant_scores
            WHERE tenant_id = t.id
            ORDER BY recorded_at DESC
            LIMIT 1
        ) s ON TRUE
        WHERE t.id = :tid
    """), {"tid": tenant_id})
    row = r.mappings().first()
    if not row:
        return None
    d = dict(row)
    d["last_scan"] = d["last_scan"].isoformat() if d.get("last_scan") else None
    return d


async def upsert_tenant_score(db: AsyncSession, tenant_id: str):
    """Recalculates and persists the risk score from current findings."""
    # Count findings by severity
    r = await db.execute(text("""
        SELECT sev, COUNT(*) as cnt
        FROM findings_v2
        WHERE tenant_id = :tid AND status NOT IN ('resolved','accepted_risk','false_positive')
        GROUP BY sev
    """), {"tid": tenant_id})
    rows = r.mappings().all()
    summary = {r["sev"]: r["cnt"] for r in rows}

    SEV_W = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 3, "LOW": 1, "INFO": 0}
    loss = sum(SEV_W.get(s, 0) * c for s, c in summary.items())
    score = max(0, min(100, 100 - loss))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"

    # Asset counts
    ar = await db.execute(text("""
        SELECT
            COUNT(DISTINCT fqdn) FILTER (WHERE fqdn IS NOT NULL) AS subdomains,
            COUNT(DISTINCT ip)   FILTER (WHERE ip IS NOT NULL)   AS ips,
            COUNT(DISTINCT unnested_port)                         AS ports
        FROM assets,
             LATERAL unnest(ports) AS unnested_port
        WHERE tenant_id = :tid
    """), {"tid": tenant_id})
    ac = dict(ar.mappings().first() or {})

    await db.execute(text("""
        INSERT INTO tenant_scores (id, tenant_id, score, grade, findings_summary, asset_counts)
        VALUES (gen_random_uuid()::text, :tid, :score, :grade, :fs::jsonb, :ac::jsonb)
        ON CONFLICT (tenant_id) DO UPDATE SET
            score            = EXCLUDED.score,
            grade            = EXCLUDED.grade,
            findings_summary = EXCLUDED.findings_summary,
            asset_counts     = EXCLUDED.asset_counts,
            recorded_at      = NOW()
    """), {
        "tid": tenant_id, "score": score, "grade": grade,
        "fs": json.dumps(summary), "ac": json.dumps(ac),
    })
    await db.commit()
    return score


# ─── Findings ────────────────────────────────────────────────────────────────

async def list_findings(
    db: AsyncSession, tenant_id: str,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
) -> dict:
    filters = ["tenant_id = :tid"]
    params: dict = {"tid": tenant_id, "limit": limit, "offset": offset}

    if severity:
        sevs = [s.strip().upper() for s in severity.split(",")]
        filters.append(f"sev = ANY(:sevs)")
        params["sevs"] = sevs
    if status:
        filters.append("status = :status")
        params["status"] = status
    if category:
        filters.append("LOWER(cat) = LOWER(:cat)")
        params["cat"] = category

    where = " AND ".join(filters)
    r = await db.execute(text(f"""
        SELECT id, sev, cat, tool, title, asset, status, ticket_ref,
               cve, cvss, epss, kev, age, "desc", fix, first_seen, last_seen,
               EXTRACT(DAY FROM NOW() - first_seen)::int AS age_days
        FROM findings_v2
        WHERE {where}
        ORDER BY
            CASE sev
                WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM'   THEN 2 WHEN 'LOW'  THEN 3
                ELSE 4
            END, cvss DESC NULLS LAST, first_seen DESC
        LIMIT :limit OFFSET :offset
    """), params)

    rows = [dict(r) for r in r.mappings().all()]
    for row in rows:
        if row.get("first_seen"):
            row["first_seen"] = row["first_seen"].isoformat()
        row["age"] = row.pop("age_days", row.get("age", 0))

    total_r = await db.execute(
        text(f"SELECT COUNT(*) FROM findings_v2 WHERE {where}"),
        {k: v for k, v in params.items() if k not in ("limit", "offset")}
    )
    total = total_r.scalar()
    return {"findings": rows, "total": total}


async def update_finding_status(
    db: AsyncSession, tenant_id: str, finding_id: str,
    status: str, ticket_ref: Optional[str] = None
) -> bool:
    r = await db.execute(text("""
        UPDATE findings_v2
        SET status = :status,
            ticket_ref = COALESCE(:ticket, ticket_ref),
            last_seen = NOW()
        WHERE id = :fid AND tenant_id = :tid
        RETURNING id
    """), {"status": status, "ticket": ticket_ref, "fid": finding_id, "tid": tenant_id})
    await db.commit()
    row = r.fetchone()
    return row is not None


async def upsert_finding(db: AsyncSession, tenant_id: str, f: dict) -> str:
    """Insert or update a finding by fingerprint."""
    fp = hashlib.sha256(
        f"{tenant_id}:{f.get('cat')}:{f.get('asset')}:{f.get('cve') or f.get('title')}".encode()
    ).hexdigest()

    await db.execute(text("""
        INSERT INTO findings_v2
            (id, tenant_id, sev, cat, tool, title, asset, cve, cvss, epss,
             kev, "desc", fix, fingerprint, first_seen, last_seen)
        VALUES
            (gen_random_uuid()::text, :tid, :sev, :cat, :tool, :title,
             :asset, :cve, :cvss, :epss, :kev, :desc, :fix, :fp, NOW(), NOW())
        ON CONFLICT (fingerprint) DO UPDATE SET
            sev       = EXCLUDED.sev,
            cvss      = EXCLUDED.cvss,
            epss      = EXCLUDED.epss,
            kev       = EXCLUDED.kev,
            last_seen = NOW()
        RETURNING id
    """), {
        "tid": tenant_id, "sev": f.get("sev", "INFO"),
        "cat": f.get("cat", "exposure"), "tool": f.get("tool"),
        "title": f.get("title", ""), "asset": f.get("asset"),
        "cve": f.get("cve"), "cvss": f.get("cvss"),
        "epss": f.get("epss"), "kev": bool(f.get("kev")),
        "desc": f.get("desc"), "fix": f.get("fix"), "fp": fp,
    })
    await db.commit()
    return fp


# ─── Assets ──────────────────────────────────────────────────────────────────

async def list_assets(
    db: AsyncSession, tenant_id: str,
    limit: int = 200, offset: int = 0,
) -> dict:
    r = await db.execute(text("""
        SELECT id, fqdn, ip::text AS ip, org, asn,
               ports, risk, sources, takeover, first_seen
        FROM assets
        WHERE tenant_id = :tid
        ORDER BY
            CASE risk
                WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM'   THEN 2 WHEN 'LOW'  THEN 3 ELSE 4
            END, fqdn
        LIMIT :limit OFFSET :offset
    """), {"tid": tenant_id, "limit": limit, "offset": offset})

    rows = [dict(r) for r in r.mappings().all()]
    for row in rows:
        if row.get("first_seen"):
            row["first_seen"] = row["first_seen"].isoformat()

    total_r = await db.execute(
        text("SELECT COUNT(*) FROM assets WHERE tenant_id = :tid"), {"tid": tenant_id}
    )
    return {"assets": rows, "total": total_r.scalar()}


async def upsert_asset(db: AsyncSession, tenant_id: str, a: dict):
    import json as _json, socket as _sock
    # Validate IP before passing to PostgreSQL ::inet cast
    raw_ip = a.get("ip")
    try:
        _sock.inet_aton(str(raw_ip)) if raw_ip else None
        valid_ip = raw_ip
    except (OSError, TypeError):
        valid_ip = None
    await db.execute(text("""
        INSERT INTO assets
            (id, tenant_id, fqdn, ip, org, asn, ports, risk, sources, takeover,
             technologies, first_seen, last_seen)
        VALUES
            (gen_random_uuid()::text, :tid, :fqdn, :ip::inet, :org, :asn,
             :ports, :risk, :sources, :takeover, :technologies, NOW(), NOW())
        ON CONFLICT DO NOTHING
    """), {
        "tid": tenant_id, "fqdn": a.get("fqdn"),
        "ip": valid_ip, "org": a.get("org"), "asn": a.get("asn"),
        "ports": a.get("ports", []), "risk": a.get("risk", "LOW"),
        "sources": a.get("sources", []), "takeover": bool(a.get("takeover")),
        "technologies": _json.dumps(a.get("technologies", [])),
    })
    await db.commit()


async def list_technologies(db: AsyncSession, tenant_id: str) -> dict:
    """Aggregiert alle erkannten Technologies über alle Assets eines Mandanten."""
    r = await db.execute(text("""
        SELECT
            tech->>'name'     AS name,
            tech->>'category' AS category,
            tech->>'version'  AS version,
            COUNT(*)::int     AS asset_count,
            MAX(risk)         AS max_risk,
            json_agg(DISTINCT fqdn) FILTER (WHERE fqdn IS NOT NULL) AS assets
        FROM assets,
             jsonb_array_elements(technologies) AS tech
        WHERE tenant_id = :tid
          AND jsonb_array_length(technologies) > 0
        GROUP BY
            tech->>'name',
            tech->>'category',
            tech->>'version'
        ORDER BY asset_count DESC, name
    """), {"tid": tenant_id})
    rows = [dict(r) for r in r.mappings().all()]

    # Kategorie-Zusammenfassung
    categories: dict = {}
    for row in rows:
        cat = row.get("category") or "Other"
        categories[cat] = categories.get(cat, 0) + 1

    return {
        "technologies": rows,
        "total": len(rows),
        "categories": categories,
    }


# ─── MCP Servers ─────────────────────────────────────────────────────────────

async def list_mcp_servers(db: AsyncSession, tenant_id: str) -> dict:
    r = await db.execute(text("""
        SELECT id, url, port, auth, tools, server_info AS server,
               cve, risk, injection, inspection_active, first_seen
        FROM mcp_servers
        WHERE tenant_id = :tid
        ORDER BY risk, first_seen DESC
    """), {"tid": tenant_id})
    rows = [dict(r) for r in r.mappings().all()]
    return {"servers": rows, "total": len(rows)}


async def upsert_mcp_server(db: AsyncSession, tenant_id: str, m: dict):
    await db.execute(text("""
        INSERT INTO mcp_servers
            (id, tenant_id, url, port, auth, tools, server_info, cve, risk, injection, inspection_active)
        VALUES
            (gen_random_uuid()::text, :tid, :url, :port, :auth, :tools,
             :server, :cve, :risk, :injection, :inspection)
        ON CONFLICT (tenant_id, url, port) DO UPDATE SET
            auth               = EXCLUDED.auth,
            tools              = EXCLUDED.tools,
            server_info        = EXCLUDED.server_info,
            cve                = EXCLUDED.cve,
            risk               = EXCLUDED.risk,
            injection          = EXCLUDED.injection,
            inspection_active  = EXCLUDED.inspection_active
    """), {
        "tid": tenant_id, "url": m.get("url"), "port": m.get("port"),
        "auth": bool(m.get("auth")), "tools": m.get("tools", []),
        "server": m.get("server"), "cve": m.get("cve"),
        "risk": m.get("risk", "CRITICAL"),
        "injection": bool(m.get("injection")),
        "inspection": bool(m.get("inspection_active")),
    })
    await db.commit()


# ─── Intel ───────────────────────────────────────────────────────────────────

async def get_intel(db: AsyncSession, tenant_id: str) -> dict:
    r = await db.execute(text("""
        SELECT data FROM intel_snapshots
        WHERE tenant_id = :tid
        ORDER BY created_at DESC
        LIMIT 1
    """), {"tid": tenant_id})
    row = r.first()
    return dict(row[0]) if row and row[0] else {}


async def upsert_intel(db: AsyncSession, tenant_id: str, data: dict):
    await db.execute(text("""
        INSERT INTO intel_snapshots (id, tenant_id, data)
        VALUES (gen_random_uuid()::text, :tid, :data::jsonb)
    """), {"tid": tenant_id, "data": json.dumps(data)})
    await db.commit()


# ─── Scans ───────────────────────────────────────────────────────────────────

async def list_scans(
    db: AsyncSession, tenant_id: str, limit: int = 20, offset: int = 0
) -> dict:
    r = await db.execute(text("""
        SELECT id,
               COALESCE(
                 (SELECT domain FROM domains WHERE id = target_domain_id LIMIT 1),
                 (SELECT MIN(domain) FROM domains WHERE tenant_id = scan_jobs.tenant_id AND status = 'active')
               ) AS domain,
               scan_type, status,
               COALESCE((findings_count->>'CRITICAL')::int, 0) +
               COALESCE((findings_count->>'HIGH')::int, 0) +
               COALESCE((findings_count->>'MEDIUM')::int, 0) +
               COALESCE((findings_count->>'LOW')::int, 0) AS findings_count,
               risk_score_after AS risk_score,
               COALESCE(started_at, created_at) AS started_at,
               completed_at AS finished_at,
               duration_seconds,
               raw_results->'phases_completed' AS phases_completed,
               COALESCE((raw_results->>'progress_pct')::int, 0) AS progress_pct
        FROM scan_jobs
        WHERE tenant_id = :tid
        ORDER BY created_at DESC
        LIMIT :limit OFFSET :offset
    """), {"tid": tenant_id, "limit": limit, "offset": offset})

    rows = []
    for row in r.mappings().all():
        d = dict(row)
        for ts_col in ("started_at", "finished_at"):
            if d.get(ts_col):
                d[ts_col] = d[ts_col].isoformat()
        rows.append(d)

    total_r = await db.execute(
        text("SELECT COUNT(*) FROM scan_jobs WHERE tenant_id = :tid"), {"tid": tenant_id}
    )
    return {"scans": rows, "total": total_r.scalar()}


async def create_scan_job(
    db: AsyncSession, tenant_id: str, scan_type: str, triggered_by: str = "manual"
) -> str:
    r = await db.execute(text("""
        INSERT INTO scan_jobs (
            id, tenant_id, target_domain_id, scan_type, status, triggered_by, created_at
        )
        VALUES (
            gen_random_uuid()::text,
            :tid,
            (SELECT id FROM domains WHERE tenant_id = :tid AND status = 'active' ORDER BY created_at LIMIT 1),
            :type,
            'pending',
            :by,
            NOW()
        )
        RETURNING id
    """), {"tid": tenant_id, "type": scan_type, "by": triggered_by})
    row = r.fetchone()  # fetch before commit — cursor closed after commit
    await db.commit()
    if not row:
        raise RuntimeError(f"Scan-Job konnte nicht erstellt werden für Mandant {tenant_id}")
    return str(row[0])


# ─── Users ───────────────────────────────────────────────────────────────────

async def get_user_by_email(db: AsyncSession, email: str) -> Optional[dict]:
    r = await db.execute(text("""
        SELECT u.id, u.email, u.full_name, u.role_v2 AS role,
               u.pw_hash, u.is_active,
               COALESCE(u.tenant_id::text, '') AS tenant_id
        FROM users u
        WHERE u.email = :email
    """), {"email": email})
    row = r.mappings().first()
    return dict(row) if row else None


async def user_count(db: AsyncSession) -> int:
    r = await db.execute(text("SELECT COUNT(*) FROM users WHERE pw_hash IS NOT NULL"))
    return r.scalar() or 0


async def create_user(
    db: AsyncSession, email: str, pw_hash: str,
    full_name: str, role: str, tenant_id: Optional[str]
) -> str:
    r = await db.execute(text("""
        INSERT INTO users (id, email, pw_hash, full_name, role_v2, tenant_id, password_hash, role)
        VALUES (gen_random_uuid()::text, :email, :pw, :name, :role,
                :tid, :pw, :role)
        RETURNING id
    """), {
        "email": email, "pw": pw_hash, "name": full_name,
        "role": role, "tid": tenant_id,
    })
    user_id = r.scalar()  # fetch before commit — cursor closed after commit
    await db.commit()
    return user_id


async def ensure_default_tenant(db: AsyncSession) -> str:
    """Creates a default tenant if none exist."""
    r = await db.execute(text("SELECT id FROM tenants LIMIT 1"))
    row = r.first()
    if row:
        return str(row[0])

    r2 = await db.execute(text("""
        INSERT INTO tenants (id, name, slug, status, created_at)
        VALUES (gen_random_uuid()::text, 'Default', 'default', 'active', NOW())
        RETURNING id
    """))
    tenant_id = r2.scalar()  # fetch before commit — cursor closed after commit
    await db.commit()
    return str(tenant_id)


# ─── Domains ─────────────────────────────────────────────────────────────────

async def list_domains(db: AsyncSession, tenant_id: str) -> dict:
    r = await db.execute(text("""
        SELECT id, domain, fqdn, status,
               COALESCE(ip_ranges, '{}')    AS ip_ranges,
               last_scan, findings_count, risk_score,
               COALESCE(panos_version, '')  AS panos_version,
               created_at
        FROM domains
        WHERE tenant_id = :tid
        ORDER BY created_at
    """), {"tid": tenant_id})
    rows = []
    for row in r.mappings().all():
        d = dict(row)
        if d.get("last_scan"):
            d["last_scan"] = d["last_scan"].isoformat()
        if d.get("created_at"):
            d["added"] = d.pop("created_at").strftime("%Y-%m-%d")
        rows.append(d)
    return {"domains": rows, "total": len(rows)}


async def create_domain(
    db: AsyncSession, tenant_id: str, domain: str,
    ip_ranges: list, panos_version: str,
) -> dict:
    # Verify tenant exists first to give a clear error (avoids FK violation 500)
    t = await db.execute(text("SELECT id FROM tenants WHERE id = :tid"), {"tid": tenant_id})
    if not t.first():
        raise ValueError(f"Mandant nicht gefunden: {tenant_id}")

    r = await db.execute(text("""
        INSERT INTO domains (id, tenant_id, domain, fqdn, status, ip_ranges, panos_version, created_at)
        VALUES (gen_random_uuid()::text, :tid, :domain, :domain, 'active', :ranges, :panos, NOW())
        RETURNING id, domain, fqdn, status, ip_ranges, last_scan,
                  findings_count, risk_score, panos_version, created_at
    """), {
        "tid": tenant_id, "domain": domain.strip().lower(),
        "ranges": ip_ranges, "panos": panos_version or "",
    })
    row = r.mappings().first()  # read BEFORE commit — cursor closed after commit
    await db.commit()
    if not row:
        raise ValueError("Domain bereits vorhanden")
    d = dict(row)
    if d.get("created_at"):
        d["added"] = d.pop("created_at").strftime("%Y-%m-%d")
    return d


async def update_domain(
    db: AsyncSession, tenant_id: str, domain_id: str,
    status: str | None = None,
    ip_ranges: list | None = None,
    panos_version: str | None = None,
) -> bool:
    sets = []
    params: dict = {"tid": tenant_id, "did": domain_id}
    if status is not None:
        sets.append("status = :status"); params["status"] = status
    if ip_ranges is not None:
        sets.append("ip_ranges = :ranges"); params["ranges"] = ip_ranges
    if panos_version is not None:
        sets.append("panos_version = :panos"); params["panos"] = panos_version
    if not sets:
        return True
    r = await db.execute(
        text(f"UPDATE domains SET {', '.join(sets)} WHERE id = :did AND tenant_id = :tid RETURNING id"),
        params,
    )
    await db.commit()
    row = r.fetchone()
    return row is not None


async def delete_domain(db: AsyncSession, tenant_id: str, domain_id: str) -> bool:
    r = await db.execute(
        text("DELETE FROM domains WHERE id = :did AND tenant_id = :tid RETURNING id"),
        {"did": domain_id, "tid": tenant_id},
    )
    await db.commit()
    row = r.fetchone()
    return row is not None


# ─── Tenant Settings (schedule + notifications) ───────────────────────────────

async def get_settings(db: AsyncSession, tenant_id: str) -> dict:
    r = await db.execute(
        text("SELECT COALESCE(settings, '{}')::jsonb FROM tenants WHERE id = :tid"),
        {"tid": tenant_id},
    )
    row = r.first()
    return dict(row[0]) if row and row[0] else {}


async def save_settings(db: AsyncSession, tenant_id: str, settings: dict) -> None:
    await db.execute(
        text("UPDATE tenants SET settings = CAST(:s AS jsonb) WHERE id = :tid"),
        {"s": json.dumps(settings), "tid": tenant_id},
    )
    await db.commit()


# ─── Email Intelligence jobs ──────────────────────────────────────────────────

async def email_intel_create_job(
    db: AsyncSession, job_id: str, tenant_id: str, domain: str,
) -> None:
    await db.execute(text("""
        INSERT INTO email_intel_jobs (id, tenant_id, domain, status, created_at)
        VALUES (:id, :tid, :domain, 'pending', now())
    """), {"id": job_id, "tid": tenant_id, "domain": domain})
    await db.commit()


async def email_intel_get_job(
    db: AsyncSession, job_id: str, tenant_id: str,
) -> dict | None:
    row = (await db.execute(text("""
        SELECT id, tenant_id, domain, status, risk_score,
               spf_raw, dmarc_raw, mx_records, findings, graph_summary,
               error, created_at, completed_at
        FROM email_intel_jobs
        WHERE id = :id AND tenant_id = :tid
    """), {"id": job_id, "tid": tenant_id})).mappings().first()
    return dict(row) if row else None


async def email_intel_has_complete_job(
    db: AsyncSession, tenant_id: str, domain: str,
) -> bool:
    row = (await db.execute(text("""
        SELECT 1 FROM email_intel_jobs
        WHERE tenant_id = :tid AND domain = :domain AND status = 'complete'
        LIMIT 1
    """), {"tid": tenant_id, "domain": domain})).first()
    return row is not None


async def email_intel_list_domains(
    db: AsyncSession, tenant_id: str, limit: int = 50,
) -> list[dict]:
    # Prefer complete > failed > running/pending so the list shows the last
    # successful result even while a re-analysis is in progress.
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
    return [dict(r) for r in rows]


async def email_intel_delete_domain(
    db: AsyncSession, tenant_id: str, domain: str,
) -> None:
    await db.execute(text("""
        DELETE FROM email_intel_jobs WHERE tenant_id = :tid AND domain = :domain
    """), {"tid": tenant_id, "domain": domain})
    await db.commit()


async def email_intel_get_history(
    db: AsyncSession, tenant_id: str, domain: str, limit: int = 20,
) -> list[dict]:
    rows = (await db.execute(text("""
        SELECT id, risk_score, created_at,
               jsonb_array_length(COALESCE(findings, '[]'::jsonb)) AS findings_count
        FROM email_intel_jobs
        WHERE tenant_id = :tid AND domain = :domain AND status = 'complete'
        ORDER BY created_at DESC
        LIMIT :limit
    """), {"tid": tenant_id, "domain": domain, "limit": limit})).mappings().all()
    return [dict(r) for r in rows]


async def email_intel_get_settings(
    db: AsyncSession, tenant_id: str,
) -> dict:
    row = (await db.execute(text("""
        SELECT auto_rescan_enabled, rescan_interval_days
        FROM email_intel_settings
        WHERE tenant_id = :tid
    """), {"tid": tenant_id})).mappings().first()
    if row:
        return dict(row)
    return {"auto_rescan_enabled": False, "rescan_interval_days": 7}


async def email_intel_save_settings(
    db: AsyncSession, tenant_id: str, enabled: bool, interval_days: int,
) -> None:
    await db.execute(text("""
        INSERT INTO email_intel_settings (tenant_id, auto_rescan_enabled, rescan_interval_days, updated_at)
        VALUES (:tid, :enabled, :interval, now())
        ON CONFLICT (tenant_id) DO UPDATE SET
            auto_rescan_enabled  = EXCLUDED.auto_rescan_enabled,
            rescan_interval_days = EXCLUDED.rescan_interval_days,
            updated_at           = EXCLUDED.updated_at
    """), {"tid": tenant_id, "enabled": enabled, "interval": interval_days})
    await db.commit()


async def email_intel_mark_failed(
    db: AsyncSession, job_id: str, error: str,
) -> None:
    await db.execute(text("""
        UPDATE email_intel_jobs SET status = 'failed', error = :error WHERE id = :id
    """), {"id": job_id, "error": error})
    await db.commit()


async def email_intel_get_active_job(
    db: AsyncSession, tenant_id: str, domain: str,
) -> dict | None:
    """Return the most recent pending/running job for a domain, or None."""
    row = (await db.execute(text("""
        SELECT id, status FROM email_intel_jobs
        WHERE tenant_id = :tid AND domain = :domain
          AND status IN ('pending', 'running')
        ORDER BY created_at DESC LIMIT 1
    """), {"tid": tenant_id, "domain": domain})).mappings().first()
    return dict(row) if row else None


async def email_intel_list_due_domains(
    db: AsyncSession, limit: int = 10,
) -> list[dict]:
    """Return domains due for automatic re-scan (one row per tenant+domain)."""
    rows = (await db.execute(text("""
        SELECT DISTINCT ON (j.tenant_id, j.domain)
            j.tenant_id, j.domain
        FROM email_intel_jobs j
        JOIN email_intel_settings s ON s.tenant_id = j.tenant_id
        WHERE s.auto_rescan_enabled = true
          AND j.status = 'complete'
          AND j.completed_at < now() - (s.rescan_interval_days || ' days')::interval
          AND NOT EXISTS (
              SELECT 1 FROM email_intel_jobs j2
              WHERE j2.tenant_id = j.tenant_id
                AND j2.domain    = j.domain
                AND j2.status IN ('pending', 'running')
          )
        ORDER BY j.tenant_id, j.domain, j.completed_at ASC
        LIMIT :limit
    """), {"limit": limit})).mappings().all()
    return [dict(r) for r in rows]
