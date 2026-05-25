"""
EASM as a Service — Celery Worker / Task Queue
Multi-Tenant Scan-Orchestrierung

Architektur:
- 1 Celery Beat Scheduler → plant tägliche/wöchentliche Scans
- N Worker-Prozesse → führen Scans parallel aus
- Redis als Broker (bereits im Stack für Palo-Health-Check)
- Tenant-Isolation: jeder Mandant hat eigene Queue-Priorität
- Rate-Limiting: pro Mandant max. X parallele Scans
"""

from celery import Celery
from celery.schedules import crontab
from datetime import datetime, timezone
import json
import os
import time

_redis = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Celery-App konfigurieren
celery_app = Celery(
    "easm_service",
    broker=_redis,
    backend=_redis.replace("/0", "/1", 1),
)

celery_app.conf.update(
    # Task-Serialisierung
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,

    # Task-Routing: Tenant-spezifische Queues für Priorisierung
    task_routes={
        "workers.scan_tasks.run_easm_scan": {
            "queue": "scans"  # default queue, routing per task
        },
        "workers.scan_tasks.run_hibp_check": {
            "queue": "hibp"   # separate queue für HIBP (rate-limited)
        },
        "workers.scan_tasks.generate_report": {
            "queue": "reports"
        },
        "workers.scan_tasks.send_alerts": {
            "queue": "alerts"   # höchste Priorität
        },
    },

    # Queues mit Prioritäten
    task_queue_max_priority=10,
    task_default_priority=5,

    # Timeouts
    task_soft_time_limit=600,   # 10 Min soft limit
    task_time_limit=900,        # 15 Min hard limit

    # Retry-Konfiguration
    task_acks_late=True,        # Task erst nach Erfolg bestätigen
    task_reject_on_worker_lost=True,

    # Ergebnisse 24h behalten
    result_expires=86400,

    # Beat Schedule: wann welche Mandanten gescannt werden
    beat_schedule={
        # Alle Mandanten: täglich
        "scan-all-daily": {
            "task": "workers.scan_tasks.schedule_tenant_scans",
            "schedule": crontab(minute=0),  # jede volle Stunde
            "args": ["all"],
            "options": {"queue": "scheduler"}
        },
        # Alle Mandanten: zusätzlicher täglicher Scan
        "scan-all-daily-2": {
            "task": "workers.scan_tasks.schedule_tenant_scans",
            "schedule": crontab(hour=2, minute=0),
            "args": ["all"],
            "options": {"queue": "scheduler"}
        },
        # Wöchentlicher Deep-Scan (alle Mandanten)
        "scan-all-weekly": {
            "task": "workers.scan_tasks.schedule_tenant_scans",
            "schedule": crontab(hour=3, minute=0, day_of_week="sunday"),
            "args": ["all"],
            "options": {"queue": "scheduler"}
        },
        # HIBP Check: täglich neue Breaches prüfen
        "check-new-breaches-daily": {
            "task": "workers.scan_tasks.check_new_hibp_breaches",
            "schedule": crontab(hour=6, minute=0),
            "options": {"queue": "hibp"}
        },
        # Lizenz-Ablauf-Monitoring: täglich
        "check-panos-license-expiry": {
            "task": "workers.scan_tasks.check_panos_license_expirations",
            "schedule": crontab(hour=7, minute=0),
            "options": {"queue": "alerts"}
        },
        # Risk-Acceptance Ablauf: täglich
        "check-risk-acceptances-expiry": {
            "task": "workers.scan_tasks.check_risk_acceptances",
            "schedule": crontab(hour=7, minute=30),
            "options": {"queue": "alerts"}
        },
        # Monatliche Reports: 1. des Monats, 08:00
        "generate-monthly-reports": {
            "task": "workers.scan_tasks.generate_all_monthly_reports",
            "schedule": crontab(hour=8, minute=0, day_of_month=1),
            "options": {"queue": "reports"}
        },
    }
)


# ─── Core Scan Tasks ─────────────────────────────────────────────────

@celery_app.task(
    bind=True,
    name="workers.scan_tasks.run_easm_scan",
    max_retries=3,
    default_retry_delay=60,
    queue="scans"
)
def run_easm_scan(self, tenant_id: str, scan_config: dict):
    """
    Haupt-Scan-Task für einen Mandanten.

    Orchestriert:
    1. Domain-Layer Scan (DNS, Subdomains, HIBP)
    2. Asset-Layer Scan (Port-Scan, Service-Fingerprinting)
    3. Ergebnisse in DB speichern
    4. Findings deduplizieren und delta berechnen
    5. Alerts bei neuen Critical-Findings senden

    Args:
        tenant_id: Mandanten-ID
        scan_config: {
            "domains": ["example.de"],
            "ip_ranges": ["203.0.113.0/24"],
            "panos_version": "10.2.7",
            "scan_types": ["domain", "asset", "hibp"],
            "priority": "normal"
        }
    """
    job_id = self.request.id
    print(f"[Worker] Scan gestartet: tenant={tenant_id}, job={job_id}")

    try:
        _scan_start = time.time()
        # Status: Running
        update_scan_status(job_id, "running", tenant_id)

        results = {
            "tenant_id": tenant_id,
            "job_id": job_id,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "findings": []
        }

        # ── 1. Domain-Layer ──────────────────────────────────────
        if "domain" in scan_config.get("scan_types", ["full"]):
            for domain in scan_config.get("domains", []):
                print(f"  [Domain] Scanne {domain}...")
                # Import der Engine
                # from easm_engine import EASMScanner
                # scanner = EASMScanner(tenant_id)
                # domain_report = scanner.scan(domain, scan_config["ip_ranges"])
                # results["domain_findings"] = domain_report

        # ── 2. Asset-Layer ───────────────────────────────────────
        if "asset" in scan_config.get("scan_types", ["full"]):
            for ip_range in scan_config.get("ip_ranges", []):
                print(f"  [Asset] Scanne {ip_range}...")
                # from easm_asset_scanner import AssetScanner
                # scanner = AssetScanner(tenant_id)
                # asset_report = scanner.scan([ip_range])
                # results["asset_findings"] = asset_report

        # ── 3. HIBP-Check ────────────────────────────────────────
        if "hibp" in scan_config.get("scan_types", ["full"]):
            for domain in scan_config.get("domains", []):
                print(f"  [HIBP] Prüfe {domain}...")
                hibp_result = run_hibp_check.delay(tenant_id, domain)

        # ── 4. Findings deduplizieren ────────────────────────────
        new_findings = deduplicate_findings(
            tenant_id=tenant_id,
            current_findings=results.get("findings", []),
            job_id=job_id
        )

        # ── 5. Risk Score berechnen ──────────────────────────────
        risk_score = calculate_risk_score(new_findings)

        # ── 6. DB speichern ──────────────────────────────────────
        save_findings_to_db(tenant_id, job_id, new_findings, risk_score)

        # ── 7. Alerts für neue Critical-Findings ────────────────
        critical_new = [f for f in new_findings
                       if f.get("severity") == "CRITICAL" and f.get("is_new")]
        if critical_new:
            send_alerts.delay(tenant_id, critical_new)

        # Status: Completed
        update_scan_status(job_id, "completed", tenant_id, {
            "risk_score": risk_score,
            "findings_count": len(new_findings),
            "new_critical": len(critical_new),
            "duration_seconds": int(time.time() - _scan_start)
        })

        print(f"[Worker] Scan abgeschlossen: {len(new_findings)} Findings")
        return {"status": "completed", "findings": len(new_findings)}

    except Exception as exc:
        print(f"[Worker] Scan fehlgeschlagen: {exc}")
        update_scan_status(job_id, "failed", tenant_id, {"error": str(exc)})
        # Retry mit exponential backoff
        raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1))


@celery_app.task(
    name="workers.scan_tasks.run_hibp_check",
    queue="hibp",
    rate_limit="10/m"  # HIBP Rate-Limit respektieren
)
def run_hibp_check(tenant_id: str, domain: str, api_key: str = ""):
    """
    HIBP-spezifischer Task mit Rate-Limiting.
    Prüft alle HIBP-Endpunkte für eine Domain.
    Rate-limited: max. 10/Minute (HIBP Core Plan Limit).
    """
    import urllib.request
    import json

    print(f"[HIBP] Prüfe Domain: {domain}")
    headers = {
        "User-Agent": "MSSP-EASM/1.0",
        "hibp-api-key": api_key
    }

    results = {}

    # 1. Alle Breaches für Domain
    try:
        url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            results["domain_breaches"] = json.loads(r.read())
    except Exception as e:
        results["domain_breaches_error"] = str(e)

    # 2. Stealer Logs für Website-Domain (Pro)
    if api_key:
        try:
            url = f"https://haveibeenpwned.com/api/v3/stealerlogwebsitedomain/{domain}"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as r:
                results["stealer_on_website"] = json.loads(r.read())
        except Exception as e:
            results["stealer_website_error"] = str(e)

    return {"tenant_id": tenant_id, "domain": domain, "results": results}


# ─── Scheduler Tasks ─────────────────────────────────────────────────

@celery_app.task(name="workers.scan_tasks.schedule_tenant_scans", queue="scheduler")
def schedule_tenant_scans(plan: str = "all"):
    """
    Wird vom Beat-Scheduler aufgerufen.
    Startet Scans für alle aktiven Mandanten des Plans.
    """
    print(f"[Scheduler] Starte Scans für alle Mandanten")

    # In Produktion: DB-Abfrage aller aktiven Mandanten des Plans
    demo_tenants = {
        "all": [
            {"id": "t3", "domains": ["stadtwerke.de"], "ip_ranges": ["192.0.2.0/24"],
             "panos_version": "10.1.11"}
        ],
        "all": []
    }

    tenants = demo_tenants.get("all", [])
    scheduled = 0

    for tenant in tenants:
        # Prüfe ob Mandant aktiv und kein laufender Scan
        # if has_running_scan(tenant["id"]): continue

        # Scan in Queue einreihen
        run_easm_scan.apply_async(
            args=[tenant["id"], {
                "domains": tenant["domains"],
                "ip_ranges": tenant["ip_ranges"],
                "panos_version": tenant.get("panos_version", ""),
                "scan_types": ["domain", "asset", "hibp"],
                "priority": "normal"
            }],
            # Enterprise: höhere Task-Priorität
            priority=5
        )
        scheduled += 1

    print(f"[Scheduler] {scheduled} Scans für '{plan}' eingeplant")
    return {"scheduled": scheduled}


@celery_app.task(name="workers.scan_tasks.check_new_hibp_breaches", queue="hibp")
def check_new_hibp_breaches():
    """
    Täglich: Prüft ob neue Breaches zu HIBP hinzugefügt wurden.
    Wenn ja: betroffene Mandanten sofort benachrichtigen.
    """
    import urllib.request
    import json

    try:
        url = "https://haveibeenpwned.com/api/v3/latestbreach"
        req = urllib.request.Request(url, headers={"User-Agent": "MSSP-EASM/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            latest = json.loads(r.read())

        breach_name = latest.get("Name", "")
        breach_domain = latest.get("Domain", "")
        added_date = latest.get("AddedDate", "")

        print(f"[HIBP] Neuester Breach: {breach_name} ({breach_domain}) @ {added_date}")

        # In Produktion: prüfen ob dieser Breach schon bekannt ist
        # Wenn neu: für alle betroffenen Mandanten HIBP-Check triggern
        # Betroffene Mandanten finden via Domain-Übereinstimmung

        return {"latest_breach": breach_name, "domain": breach_domain}
    except Exception as e:
        print(f"[HIBP] Fehler beim Breach-Check: {e}")
        return {"error": str(e)}


@celery_app.task(name="workers.scan_tasks.check_license_expirations", queue="alerts")
def check_license_expirations():
    """
    Täglich: Prüft Palo-Alto-Lizenz-Ablauf für alle Mandanten.
    Alert wenn < 60 Tage bis Ablauf.
    """
    # In Produktion: für jeden Mandant PAN-OS API aufrufen
    # 'show license' → Ablaufdatum parsen
    expiring = [
        {"tenant": "TechNova AG", "license": "Threat Prevention",
         "expires_in_days": 45, "severity": "HIGH"},
        {"tenant": "Müller GmbH", "license": "URL Filtering",
         "expires_in_days": 28, "severity": "CRITICAL"}
    ]

    for item in expiring:
        if item["expires_in_days"] <= 30:
            send_alerts.delay(
                tenant_id=item["tenant"],
                findings=[{
                    "severity": "CRITICAL",
                    "title": f"Lizenz läuft in {item['expires_in_days']} Tagen ab: {item['license']}",
                    "category": "license_expiry"
                }]
            )

    return {"checked": len(expiring), "alerts_sent": sum(1 for i in expiring if i["expires_in_days"] <= 30)}


@celery_app.task(name="workers.scan_tasks.check_risk_acceptances", queue="alerts")
def check_risk_acceptances():
    """
    Täglich: Prüft ablaufende Risk-Acceptances.
    Alert 14 Tage vor Ablauf.
    """
    # In Produktion: DB-Abfrage aller Acceptances die in < 14 Tagen ablaufen
    print("[RiskAcceptance] Prüfe ablaufende Ausnahmen...")
    return {"checked": 0, "expiring_soon": 0}


@celery_app.task(name="workers.scan_tasks.generate_all_monthly_reports", queue="reports")
def generate_all_monthly_reports():
    """Am 1. des Monats: Reports für alle Mandanten generieren"""
    # In Produktion: für jeden Mandant Report-Generation starten
    print("[Reports] Generiere monatliche Reports für alle Mandanten...")
    return {"reports_queued": 0}


# ─── Alert Tasks ─────────────────────────────────────────────────────

def _load_tenant_alert_config(tenant_id: str) -> dict:
    """Load Slack webhook and alert settings from the tenant's settings JSONB."""
    db_url = os.getenv("DATABASE_URL", "")
    if not db_url:
        return {}
    try:
        import psycopg2, psycopg2.extras
        conn = psycopg2.connect(db_url)
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT settings FROM tenants WHERE id = %s",
                (tenant_id,)
            )
            row = cur.fetchone()
        conn.close()
        if not row:
            return {}
        settings = row.get("settings") or {}
        if isinstance(settings, str):
            settings = json.loads(settings)
        integ = settings.get("integrations", {}) if isinstance(settings, dict) else {}
        return {
            "slack_webhook": integ.get("slack_webhook", ""),
            "slack_channel": integ.get("slack_channel", ""),
        }
    except Exception as e:
        print(f"[Alerts] Fehler beim Laden der Tenant-Config: {e}")
        return {}


@celery_app.task(name="workers.scan_tasks.send_alerts", queue="alerts", priority=10)
def send_alerts(tenant_id: str, findings: list):
    """
    Sendet Alerts für neue/kritische Findings.

    Kanäle:
    - Slack-Webhook (wenn in Einstellungen konfiguriert)
    - Jira/ServiceNow Ticket (wenn konfiguriert, nur CRITICAL)
    """
    print(f"[Alerts] {len(findings)} neue Findings für Tenant {tenant_id}")

    tenant_config = _load_tenant_alert_config(tenant_id)
    slack_url = tenant_config.get("slack_webhook", "")

    for finding in findings:
        severity = finding.get("severity", "LOW")

        # Slack-Webhook (nur wenn konfiguriert)
        if slack_url and severity in ("CRITICAL", "HIGH"):
            send_webhook(slack_url, {
                "tenant": tenant_id,
                "severity": severity,
                "title": finding.get("title"),
                "asset": finding.get("asset") or finding.get("affected_asset"),
                "remediation": finding.get("remediation"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        # Ticket für CRITICAL (4h SLA)
        if severity == "CRITICAL" and tenant_config.get("ticket_system"):
            create_ticket(tenant_id, finding, tenant_config["ticket_system"])


# ─── Hilfsfunktionen ─────────────────────────────────────────────────

def update_scan_status(job_id: str, status: str, tenant_id: str, data: dict = None):
    """Scan-Status in DB aktualisieren"""
    print(f"[DB] Scan {job_id}: {status}")
    # In Produktion: DB-Update

def deduplicate_findings(tenant_id: str, current_findings: list, job_id: str) -> list:
    """
    Findings gegen bestehende DB-Einträge deduplizieren.
    Fingerprint = SHA256(category + asset + details)
    Gibt 'is_new' Flag zurück.
    """
    import hashlib
    for f in current_findings:
        fingerprint_str = f"{f.get('category')}:{f.get('affected_asset')}:{f.get('title')}"
        f["fingerprint"] = hashlib.sha256(fingerprint_str.encode()).hexdigest()
        f["is_new"] = True  # In Produktion: DB-Check ob Fingerprint schon existiert
    return current_findings

def calculate_risk_score(findings: list) -> int:
    """Gesamt-Risk-Score aus allen Findings berechnen"""
    score = 100
    weights = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 1}
    for f in findings:
        score -= weights.get(f.get("severity", "LOW"), 0)
    return max(0, min(100, score))

def save_findings_to_db(tenant_id: str, job_id: str, findings: list, score: int):
    """Findings in DB persistieren"""
    print(f"[DB] Speichere {len(findings)} Findings für Tenant {tenant_id}, Score: {score}")

def send_email_alert(tenant_id: str, finding: dict, email: str):
    """E-Mail-Alert senden"""
    print(f"[Email] Alert an {email}: {finding.get('title')}")

def send_webhook(url: str, payload: dict):
    """Webhook-Alert senden"""
    import urllib.request
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data,
                                    headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
        print(f"[Webhook] Gesendet an {url}")
    except Exception as e:
        print(f"[Webhook] Fehler: {e}")

def create_ticket(tenant_id: str, finding: dict, system: str):
    """Ticket in Jira/ServiceNow erstellen"""
    print(f"[Ticket] Erstelle {system}-Ticket für: {finding.get('title')}")
