"""
Email Intelligence Celery worker.
Self-contained Celery app on the same Redis broker — runs as a dedicated
worker-email-intel service so it doesn't need the heavy security-tool
dependencies of the main scan worker.
"""
from __future__ import annotations
import json
import logging
import os
import sys

import psycopg2
from celery import Celery
from celery.signals import worker_ready
from datetime import datetime, timezone

from easm_email.job_status import JobStatus

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

log = logging.getLogger(__name__)

_redis = os.getenv("REDIS_URL", "redis://localhost:6379/0")
_redis_backend = _redis.replace("/0", "/1", 1) if _redis.endswith("/0") else _redis

celery_app = Celery(
    "easm_email_intel",
    broker=_redis,
    backend=_redis_backend,
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    result_expires=86400,
)

_JSONB_COLS = {"mx_records", "findings", "graph_summary"}

# Cypher statements to create Neo4j constraints/indexes on first startup
_NEO4J_INIT_STMTS = [
    "CREATE CONSTRAINT domain_unique IF NOT EXISTS FOR (d:Domain) REQUIRE (d.fqdn, d.tenant_id) IS UNIQUE",
    "CREATE CONSTRAINT provider_unique IF NOT EXISTS FOR (p:Provider) REQUIRE p.name IS UNIQUE",
    "CREATE CONSTRAINT ip_unique IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE",
    "CREATE CONSTRAINT asn_unique IF NOT EXISTS FOR (a:ASN) REQUIRE a.number IS UNIQUE",
    "CREATE CONSTRAINT mxserver_unique IF NOT EXISTS FOR (m:MXServer) REQUIRE m.fqdn IS UNIQUE",
    "CREATE INDEX domain_tenant_idx IF NOT EXISTS FOR (d:Domain) ON (d.tenant_id)",
    "CREATE INDEX ip_address_idx IF NOT EXISTS FOR (i:IP) ON (i.address)",
    "CREATE INDEX asn_number_idx IF NOT EXISTS FOR (a:ASN) ON (a.number)",
]


@worker_ready.connect
def _init_neo4j_schema(**kwargs):
    """Apply Neo4j constraints and indexes once when the worker starts."""
    try:
        from easm_email.graph_builder import get_driver
        driver = get_driver()
        with driver.session() as session:
            for stmt in _NEO4J_INIT_STMTS:
                session.run(stmt)
        log.info("[email_intel] Neo4j schema initialised")
    except Exception as e:
        log.warning("[email_intel] Neo4j schema init skipped (will retry on next startup): %s", e)


def _db_conn():
    return psycopg2.connect(os.getenv("DATABASE_URL", ""))


def _update_job(conn, job_id: str, **fields) -> None:
    parts, vals = [], []
    for k, v in fields.items():
        parts.append(f"{k} = %s::jsonb" if k in _JSONB_COLS else f"{k} = %s")
        vals.append(v)
    vals.append(job_id)
    with conn.cursor() as cur:
        cur.execute(
            f"UPDATE email_intel_jobs SET {', '.join(parts)} WHERE id = %s", vals
        )
    conn.commit()


@celery_app.task(
    bind=True,
    name="workers.email_intel_tasks.email_intel_analyze",
    queue="email_intel",
    max_retries=2,
    soft_time_limit=120,
    time_limit=150,
    acks_late=True,
)
def email_intel_analyze(self, job_id: str, domain: str, tenant_id: str):
    log.info("[email_intel] start domain=%s job=%s", domain, job_id)
    conn = None
    try:
        conn = _db_conn()
        _update_job(conn, job_id, status=JobStatus.RUNNING)

        # ── Step 1: DNS collection ────────────────────────────────────────
        from easm_email.dns_collector import collect
        bundle = collect(domain)
        log.info("[email_intel] dns ok spf=%s dmarc=%s mx=%d",
                 bool(bundle.spf_raw), bool(bundle.dmarc_raw), len(bundle.mx_records))

        # ── Step 2: SPF parse ─────────────────────────────────────────────
        from easm_email.spf_parser import parse as spf_parse
        spf_tree = spf_parse(domain, bundle.spf_raw) if bundle.spf_raw else None

        # ── Step 3: DMARC parse ───────────────────────────────────────────
        from easm_email.dmarc_parser import parse as dmarc_parse
        dmarc = dmarc_parse(bundle.dmarc_raw)

        # ── Step 4: MX analysis ───────────────────────────────────────────
        from easm_email.mx_analyzer import analyze as mx_analyze
        mx_servers = mx_analyze(bundle.mx_records)

        # ── Step 5: Enrichment ────────────────────────────────────────────
        from easm_email.enricher import enrich_ip_list
        ip_tuples = [
            (ip.address, ip.version, ip.ptr)
            for mx in mx_servers
            for ip in mx.ips
        ]
        enriched_ips = enrich_ip_list(ip_tuples)

        # ── Steps 6-8: DKIM + RBL + MTA-STS in parallel (all non-fatal) ──
        from concurrent.futures import ThreadPoolExecutor as _TPE

        _mx_ips = [ip.address for mx in mx_servers for ip in mx.ips]

        def _run_dkim():
            from easm_email.dkim_checker import discover as _disc
            results = _disc(domain)
            log.info("[email_intel] dkim selectors found=%d", len(results))
            return results

        def _run_rbl():
            from easm_email.rbl_checker import check_ips as _chk
            hits = _chk(_mx_ips)
            if hits:
                log.warning("[email_intel] rbl hits=%d for domain=%s", len(hits), domain)
            return hits

        def _run_mta():
            from easm_email.mta_sts_checker import check as _chk
            result = _chk(domain)
            log.info("[email_intel] mta_sts declared=%s mode=%s tls_rpt=%s",
                     result.dns_declared, result.mode, result.tls_rpt_present)
            return result

        dkim_results, rbl_hits, mta_sts = [], [], None
        with _TPE(max_workers=3) as _pool:
            _f_dkim = _pool.submit(_run_dkim)
            _f_rbl  = _pool.submit(_run_rbl)
            _f_mta  = _pool.submit(_run_mta)
            try: dkim_results = _f_dkim.result()
            except Exception as e: log.warning("[email_intel] dkim failed: %s", e)
            try: rbl_hits = _f_rbl.result()
            except Exception as e: log.warning("[email_intel] rbl failed: %s", e)
            try: mta_sts = _f_mta.result()
            except Exception as e: log.warning("[email_intel] mta_sts failed: %s", e)

        # ── Step 9: Graph (Neo4j — non-fatal on failure) ──────────────────
        try:
            from easm_email.graph_builder import upsert_analysis, delete_domain_graph
            delete_domain_graph(domain, tenant_id)
            upsert_analysis(
                domain, tenant_id,
                bundle.spf_raw,
                dmarc.p if dmarc.present else "absent",
                spf_tree, mx_servers, enriched_ips,
            )
        except Exception as neo_err:
            log.warning("[email_intel] neo4j write skipped: %s", neo_err)

        # ── Step 10: Risk scoring ─────────────────────────────────────────
        from easm_email.risk_scorer import score as risk_score
        result = risk_score(spf_tree, dmarc, enriched_ips, mx_servers,
                            dkim_results=dkim_results,
                            rbl_hits=rbl_hits,
                            mta_sts=mta_sts,
                            dnssec_signed=bundle.dnssec_signed)

        findings_json = json.dumps([
            {
                "code": f.code, "severity": f.severity,
                "title": f.title, "detail": f.detail, "remediation": f.remediation,
            }
            for f in result.findings
        ])
        summary_json = json.dumps({
            "provider_count": result.provider_count,
            "spf_depth": result.spf_depth,
            "spf_include_count": result.spf_include_count,
            "spf_lookup_count": result.spf_lookup_count,
            "ip_count": result.ip_count,
            "asn_count": result.asn_count,
            "mx_count": result.mx_count,
            "dkim_selectors_found": len(dkim_results),
            "dkim_weak_keys": sum(1 for r in dkim_results if r.weak),
            "rbl_listed_count": len([h for h in rbl_hits if h.severity != "INFO"]),
            "mta_sts_mode": mta_sts.mode if mta_sts else None,
            "tls_rpt_present": mta_sts.tls_rpt_present if mta_sts else False,
            "dnssec_signed": bundle.dnssec_signed,
        })
        enriched_by_addr = {e.address: e for e in enriched_ips}

        def _ip_dict(ip) -> dict:
            e = enriched_by_addr.get(ip.address)
            return {
                "address": ip.address,
                "version": ip.version,
                "ptr": ip.ptr,
                "provider_name": e.provider_name if e else "Unknown",
                "provider_category": e.provider_category if e else "unknown",
                "asn": ({"number": e.asn.number, "name": e.asn.name, "country": e.asn.country}
                        if e and e.asn else None),
            }

        mx_json = json.dumps([
            {"fqdn": mx.fqdn, "priority": mx.priority, "ips": [_ip_dict(ip) for ip in mx.ips]}
            for mx in mx_servers
        ])

        _update_job(conn, job_id,
            status=JobStatus.COMPLETE,
            risk_score=result.score,
            spf_raw=bundle.spf_raw,
            dmarc_raw=bundle.dmarc_raw,
            mx_records=mx_json,
            findings=findings_json,
            graph_summary=summary_json,
            completed_at=datetime.now(timezone.utc),
        )
        log.info("[email_intel] done domain=%s score=%d band=%s", domain, result.score, result.band)

    except Exception as exc:
        log.exception("[email_intel] failed domain=%s: %s", domain, exc)
        if conn:
            try:
                _update_job(conn, job_id, status=JobStatus.FAILED, error=str(exc)[:500])
            except Exception:
                pass
        raise self.retry(exc=exc, countdown=30)
    finally:
        if conn:
            conn.close()
