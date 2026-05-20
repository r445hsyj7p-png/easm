"""
EASM Toolchain — Vollständige Scan-Pipeline
============================================
Orchestriert alle Tools in der richtigen Reihenfolge:

  Phase 1: Discovery     Subfinder + theHarvester → Subdomain-Pool
  Phase 2: Port-Scan     Naabu → Offene Ports + MCP-Port-Detection
  Phase 3: HTTP-Probing  HTTPX → Tech-Stack, Screenshots, Security-Header
  Phase 4: Vuln-Scan     Nuclei → API-Exposition, CVEs, MCP-Checks
  Phase 5: MCP-Scan      Ramparts → MCP-Server-Tiefenanalyse
  Phase 6: Aggregation   Deduplizierung + Risk-Scoring + DB-Persistierung

Verwendung:
    pipeline = EASMPipeline(tenant_id="kunde-001", config=config)
    report = await pipeline.run(domain="example.de", ip_ranges=["203.0.113.0/24"])
"""

import json
import hashlib
import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from easm.tool_adapters import (
    SubfinderAdapter, NaabuAdapter, TheHarvesterAdapter,
    HTTPXAdapter, NucleiAdapter, RampartsAdapter, ToolFinding
)


# ─── Pipeline-Konfiguration ────────────────────────────────────────────────────

@dataclass
class PipelineConfig:
    """Konfiguration der EASM-Pipeline pro Mandant"""

    # API-Keys für externe Dienste
    api_keys: dict = field(default_factory=dict)
    # {
    #   "virustotal": "...", "shodan": "...", "hibp": "...",
    #   "censys_id": "...", "censys_secret": "...",
    #   "securitytrails": "..."
    # }

    # Alle Features aktiviert — kein Plan-Limit
    run_subfinder: bool = True
    run_naabu: bool = True
    run_theharvester: bool = True
    run_sslyze: bool = True
    run_httpx: bool = True
    run_nuclei: bool = True
    run_ramparts: bool = True
    run_mcp_scan: bool = True

    # Subfinder
    subfinder_recursive: bool = False

    # Naabu
    naabu_ports: str = "top-1000"  # top-100 | top-1000 | full | "80,443,..."
    naabu_rate: int = 1000
    naabu_nmap: bool = False

    # theHarvester
    theharvester_limit: int = 500
    theharvester_full_sources: bool = False  # LinkedIn (langsamer)

    # HTTPX
    httpx_screenshots: bool = True
    httpx_threads: int = 50

    # Nuclei — tags must match NucleiAdapter.run() fallback; "default-logins" (plural)
    # is the actual nuclei template folder/tag name (not "default-login")
    nuclei_tags: str = "api,exposure,misconfig,default-logins,mcp,cve,tech"
    nuclei_severity: str = "low,medium,high,critical"
    nuclei_rate: int = 100

    # Ramparts
    ramparts_llm: bool = False  # LLM-gestützte Analyse

    # MCP — additional URLs configured by the user in Settings (bypasses port-scan discovery)
    extra_mcp_urls: list = field(default_factory=list)

    # Pipeline
    max_workers: int = 4
    timeout_phase: int = 600     # Sekunden pro Phase


# ─── Pipeline-Report ──────────────────────────────────────────────────────────

@dataclass
class PipelineReport:
    """Vollständiger EASM-Scan-Report eines Mandanten"""
    tenant_id: str
    domain: str
    ip_ranges: list
    scan_start: str
    scan_end: str = ""
    duration_seconds: int = 0

    # Findings pro Tool
    findings_subfinder: list = field(default_factory=list)
    findings_naabu: list = field(default_factory=list)
    findings_theharvester: list = field(default_factory=list)
    findings_sslyze: list = field(default_factory=list)
    findings_httpx: list = field(default_factory=list)
    findings_nuclei: list = field(default_factory=list)
    findings_ramparts: list = field(default_factory=list)

    # Aggregiert + dedupliziert
    all_findings: list = field(default_factory=list)
    subdomains_discovered: list = field(default_factory=list)
    open_ports: dict = field(default_factory=dict)   # {ip: [ports]}
    mcp_servers_found: list = field(default_factory=list)
    emails_harvested: list = field(default_factory=list)

    # Statistiken
    stats: dict = field(default_factory=dict)
    risk_score: int = 100


# ─── Pipeline-Orchestrator ────────────────────────────────────────────────────

class EASMPipeline:
    """
    Orchestriert alle EASM-Tool-Adapter in der optimalen Reihenfolge.
    Jede Phase baut auf den Ergebnissen der vorherigen auf.
    """

    def __init__(self, tenant_id: str, config: PipelineConfig = None, log_fn=None):
        self.tenant_id = tenant_id
        self.config = config or PipelineConfig()
        self._log = log_fn or (lambda tool, msg, level="info": None)

        # Tool-Adapter initialisieren
        self.subfinder = SubfinderAdapter(api_keys=self.config.api_keys)
        self.naabu = NaabuAdapter()
        self.harvester = TheHarvesterAdapter()
        self.httpx = HTTPXAdapter()
        self.nuclei = NucleiAdapter()
        self.ramparts = RampartsAdapter()

    def run(self, domain: str, ip_ranges: list[str] = None,
            panos_version: str = "", progress_fn=None) -> PipelineReport:
        """
        Führt vollständigen EASM-Scan aus.

        Args:
            domain: Haupt-Domain des Mandanten
            ip_ranges: IP-Ranges für Port-Scan (CIDR)
            panos_version: PAN-OS-Version für CVE-Matching
            progress_fn: Optional callback(phase: str, pct: int, report) called after each phase
        """
        ip_ranges = ip_ranges or []

        def _notify(phase: str, pct: int):
            if progress_fn:
                try:
                    progress_fn(phase, pct, report)
                except Exception:
                    pass

        report = PipelineReport(
            tenant_id=self.tenant_id,
            domain=domain,
            ip_ranges=ip_ranges,
            scan_start=datetime.datetime.utcnow().isoformat()
        )

        start_ts = datetime.datetime.utcnow()

        self._log("pipeline", f"Start: {domain} [{self.tenant_id}] | IP-Ranges: {ip_ranges}", "info")
        _notify("starting", 0)

        # ── Phase 1: Discovery (Subfinder + theHarvester parallel) ────────────
        self._log("pipeline", "Phase 1/6: Subdomain Discovery", "info")
        subdomains = self._phase_discovery(report, domain)
        self._log("pipeline", f"Phase 1 done: {len(subdomains)} Subdomains", "info")
        _notify("discovery", 5)

        # ── Phase 2: Port-Scan (Naabu) ────────────────────────────────────────
        self._log("pipeline", "Phase 2/6: Port-Scanning", "info")
        all_hosts = list(set(ip_ranges + [s.affected_asset for s in subdomains
                                          if "." in s.affected_asset]))
        open_ports = self._phase_portscan(report, all_hosts)
        mcp_hosts = self._identify_mcp_hosts(report)
        self._log("pipeline",
                  f"Phase 2 done: {sum(len(p) for p in open_ports.values())} offene Ports | "
                  f"{len(mcp_hosts)} MCP-Kandidaten", "info")
        _notify("portscan", 20)

        # ── Phase 3: TLS-Scan (SSLyze) ────────────────────────────────────────
        self._log("pipeline", "Phase 3/6: TLS-Scanning", "info")
        tls_targets = self._build_tls_targets(open_ports, subdomains)
        self._phase_tls(report, tls_targets)
        self._log("pipeline", f"Phase 3 done: {len(report.findings_sslyze)} TLS-Findings", "info")
        _notify("tls", 35)

        # ── Phase 4: HTTP-Probing (HTTPX) ─────────────────────────────────────
        self._log("pipeline", "Phase 4/6: HTTP-Probing & Fingerprinting", "info")
        http_targets = self._build_http_targets(open_ports, subdomains, domain)
        self._phase_http(report, http_targets)
        self._log("pipeline", f"Phase 4 done: {len(report.findings_httpx)} HTTP-Findings", "info")
        _notify("http", 50)

        # ── Phase 5: Vulnerability-Scan (Nuclei) ──────────────────────────────
        self._log("pipeline", "Phase 5/6: Vulnerability-Scanning (Nuclei)", "info")
        vuln_targets = list(set(http_targets + mcp_hosts))
        self._phase_vulnscan(report, vuln_targets, mcp_hosts)
        self._log("pipeline", f"Phase 5 done: {len(report.findings_nuclei)} Nuclei-Findings", "info")
        _notify("vuln", 70)

        # ── Phase 6: MCP-Tiefenanalyse (Ramparts) ────────────────────────────
        if mcp_hosts and self.config.run_ramparts:
            self._log("pipeline", "Phase 6/6: MCP-Tiefenanalyse (Ramparts)", "info")
            self._phase_mcp(report, mcp_hosts)
            self._log("pipeline", f"Phase 6 done: {len(report.findings_ramparts)} MCP-Findings", "info")
        else:
            self._log("pipeline", "Phase 6/6: MCP-Analyse übersprungen (keine MCP-Hosts)", "info")
        _notify("mcp", 88)

        # ── Aggregation + Deduplication ───────────────────────────────────────
        self._log("pipeline", "Aggregation: Deduplizierung & Risk-Scoring", "info")
        self._aggregate(report)
        _notify("aggregating", 95)

        # ── Abschluss ─────────────────────────────────────────────────────────
        end_ts = datetime.datetime.utcnow()
        report.scan_end = end_ts.isoformat()
        report.duration_seconds = int((end_ts - start_ts).total_seconds())

        self._print_summary(report)
        return report

    def _phase_discovery(self, report: PipelineReport, domain: str) -> list[ToolFinding]:
        """Phase 1: Parallele Subdomain-Discovery"""
        all_subs = []

        with ThreadPoolExecutor(max_workers=2) as ex:
            futures = {}

            if self.config.run_subfinder:
                futures[ex.submit(
                    self.subfinder.run,
                    self.tenant_id, domain,
                    self.config.subfinder_recursive,
                    self._log
                )] = "subfinder"

            if self.config.run_theharvester:
                futures[ex.submit(
                    self.harvester.run,
                    self.tenant_id, domain,
                    self.config.theharvester_limit,
                    self.config.theharvester_full_sources,
                    self._log
                )] = "theharvester"

            for future in as_completed(futures):
                tool = futures[future]
                try:
                    findings = future.result(timeout=self.config.timeout_phase)
                    if tool == "subfinder":
                        report.findings_subfinder = findings
                        report.subdomains_discovered = [
                            f.affected_asset for f in findings
                            if f.category == "subdomain"
                        ]
                        all_subs.extend([f for f in findings if f.category == "subdomain"])
                    elif tool == "theharvester":
                        report.findings_theharvester = findings
                        for f in findings:
                            if f.category == "email":
                                report.emails_harvested.extend(f.raw_data.get("emails", []))
                except Exception as e:
                    self._log(tool, f"Phase-Fehler: {e}", "error")

        # Ensure the root domain itself is always in the discovered list so
        # HTTP probing and nuclei always target it, even if subfinder omits it.
        if domain and domain not in report.subdomains_discovered:
            report.subdomains_discovered.append(domain)
            root_finding = ToolFinding(
                tenant_id=self.tenant_id, tool="subfinder", category="subdomain",
                severity="INFO", title=f"Root-Domain: {domain}",
                description=f"Root-Domain {domain} als Asset aufgenommen.",
                affected_asset=domain,
            )
            report.findings_subfinder.append(root_finding)
            all_subs.append(root_finding)

        return all_subs

    def _phase_portscan(self, report: PipelineReport,
                         targets: list[str]) -> dict:
        """Phase 2: Port-Scan mit Naabu"""
        if not self.config.run_naabu:
            return {}

        try:
            findings = self.naabu.run(
                tenant_id=self.tenant_id,
                targets=targets,
                ports=self.config.naabu_ports,
                rate=self.config.naabu_rate,
                nmap_integration=self.config.naabu_nmap,
                log_fn=self._log
            )
            report.findings_naabu = findings

            # Port-Map aufbauen: {host: [ports]}
            port_map = {}
            for f in findings:
                if ":" in f.affected_asset:
                    host, port_str = f.affected_asset.rsplit(":", 1)
                    try:
                        port_int = int(port_str)
                    except (ValueError, TypeError):
                        continue
                    if host not in port_map:
                        port_map[host] = []
                    port_map[host].append(port_int)
            report.open_ports = port_map
            return port_map

        except Exception as e:
            self._log("naabu", f"Phase-Fehler: {e}", "error")
            return {}

    def _identify_mcp_hosts(self, report: PipelineReport) -> list[str]:
        """Identifiziert Hosts mit MCP-typischen Ports"""
        MCP_PORTS = {6274, 6277, 3000, 8080, 8000, 9000, 4000, 5000}
        mcp_hosts = []

        for host, ports in report.open_ports.items():
            if any(p in MCP_PORTS for p in ports):
                for port in ports:
                    if port in MCP_PORTS:
                        mcp_hosts.append(f"http://{host}:{port}")
                        mcp_hosts.append(f"https://{host}:{port}")

        # Auch MCP-Findings aus Naabu
        for f in report.findings_naabu:
            if f.category == "mcp_exposure" and ":" in f.affected_asset:
                parts = f.affected_asset.rsplit(":", 1)
                if len(parts) == 2:
                    host, port = parts
                    mcp_hosts.extend([
                        f"http://{host}:{port}",
                        f"https://{host}:{port}"
                    ])

        report.mcp_servers_found = list(set(mcp_hosts))
        return report.mcp_servers_found

    def _build_tls_targets(self, open_ports: dict,
                            subdomains: list[ToolFinding]) -> list[dict]:
        """Baut TLS-Target-Liste für bekannte HTTPS-Ports.

        Für Hosts die der Portscan abgedeckt hat, werden nur tatsächlich
        offene HTTPS-Ports genutzt. Für Hosts außerhalb des Portscan-Scope
        (z.B. wenn naabu nicht verfügbar war) wird Port 443 als Fallback
        angenommen.
        """
        HTTPS_PORTS = {443, 8443, 9443, 4443, 5986, 6443, 8200}
        targets = []
        seen = set()

        # Hosts mit Portscan-Ergebnissen: nur bestätigte HTTPS-Ports
        scanned_hosts = set(open_ports.keys())
        for host, ports in open_ports.items():
            for port in ports:
                if port in HTTPS_PORTS:
                    key = (host, port)
                    if key not in seen:
                        seen.add(key)
                        targets.append({"host": host, "port": port})

        # Subdomains außerhalb des Portscan-Scope: Port 443 als Fallback
        for sub in subdomains:
            host = sub.affected_asset
            if host in scanned_hosts:
                continue  # Portscan hat entschieden ob 443 offen ist
            key = (host, 443)
            if key not in seen:
                seen.add(key)
                targets.append({"host": host, "port": 443})

        return targets

    def _phase_tls(self, report: PipelineReport, targets: list[dict]):
        """Phase 3: TLS-Scan via SSLyze — alle Targets parallel"""
        if not self.config.run_sslyze or not targets:
            return
        try:
            from workers.sslyze_task import _scan_target
            findings_raw = []
            with ThreadPoolExecutor(max_workers=min(20, len(targets))) as ex:
                futures = {ex.submit(_scan_target, t["host"], t["port"]): t
                           for t in targets}
                for fut in as_completed(futures):
                    try:
                        findings_raw.extend(fut.result())
                    except Exception as e:
                        t = futures[fut]
                        self._log("sslyze", f"{t['host']}:{t['port']}: {e}", "warn")
            tls_findings = []
            for raw in findings_raw:
                tls_findings.append(ToolFinding(
                    tenant_id=self.tenant_id,
                    tool="sslyze",
                    category=raw.get("category", "tls"),
                    severity=raw.get("severity", "INFO"),
                    title=raw.get("title", "TLS Issue"),
                    description=raw.get("description", ""),
                    affected_asset=raw.get("affected_asset", ""),
                    raw_data=raw,
                ))
            report.findings_sslyze = tls_findings
        except Exception as e:
            self._log("sslyze", f"Phase-Fehler: {e}", "error")

    def _build_http_targets(self, open_ports: dict,
                             subdomains: list[ToolFinding],
                             domain: str = "") -> list[str]:
        """Baut HTTP-Target-Liste aus Port-Scan-Ergebnissen"""
        targets = []
        HTTP_PORTS = {80, 8080, 8000, 8008, 8081, 8090, 3000, 9000, 10000}
        HTTPS_PORTS = {443, 8443, 9443, 4443, 5986, 6443, 8200}

        for host, ports in open_ports.items():
            for port in ports:
                if port in HTTP_PORTS:
                    targets.append(f"http://{host}:{port}")
                elif port in HTTPS_PORTS:
                    targets.append(f"https://{host}:{port}")

        # Subdomains direkt (HTTPX prüft http + https)
        for sub in subdomains:
            targets.append(sub.affected_asset)

        # Always probe the root domain on both schemes
        if domain:
            for scheme in ("https", "http"):
                targets.append(f"{scheme}://{domain}")

        return list(set(targets))

    def _phase_http(self, report: PipelineReport, targets: list[str]):
        """Phase 3: HTTP-Probing mit HTTPX"""
        if not self.config.run_httpx or not targets:
            return

        try:
            findings = self.httpx.run(
                tenant_id=self.tenant_id,
                urls=targets,
                take_screenshots=self.config.httpx_screenshots,
                threads=self.config.httpx_threads,
                log_fn=self._log
            )
            report.findings_httpx = findings
        except Exception as e:
            self._log("httpx", f"Phase-Fehler: {e}", "error")

    def _merge_mcp_hosts(self, discovered: list[str]) -> list[str]:
        """Merge port-scan-discovered MCP hosts with user-configured extra URLs."""
        extra = [u for u in self.config.extra_mcp_urls if u]
        if not extra:
            return discovered
        combined = list(dict.fromkeys(discovered + extra))  # deduplicate, preserve order
        if extra:
            self._log("pipeline", f"MCP: {len(extra)} konfigurierte URL(s) hinzugefügt "
                      f"({', '.join(extra[:3])}{'…' if len(extra) > 3 else ''})", "info")
        return combined

    def _phase_vulnscan(self, report: PipelineReport,
                          targets: list[str], mcp_hosts: list[str]):
        """Phase 4: Nuclei Vulnerability-Scan"""
        if not self.config.run_nuclei or not targets:
            return

        try:
            findings = self.nuclei.run(
                tenant_id=self.tenant_id,
                targets=targets,
                tags=self.config.nuclei_tags,
                severity_filter=self.config.nuclei_severity,
                rate_limit=self.config.nuclei_rate,
                log_fn=self._log
            )

            # Separater MCP-Scan: entdeckte + konfigurierte Hosts
            all_mcp = self._merge_mcp_hosts(mcp_hosts)
            if all_mcp and self.config.run_mcp_scan:
                mcp_findings = self.nuclei.run_mcp_scan(
                    tenant_id=self.tenant_id,
                    targets=all_mcp,
                    log_fn=self._log
                )
                findings.extend(mcp_findings)

            report.findings_nuclei = findings
        except Exception as e:
            self._log("nuclei", f"Phase-Fehler: {e}", "error")

    def _phase_mcp(self, report: PipelineReport, mcp_hosts: list[str]):
        """Phase 5: Ramparts MCP-Tiefenanalyse"""
        all_mcp = self._merge_mcp_hosts(mcp_hosts)
        if not all_mcp:
            return

        try:
            findings = self.ramparts.run(
                tenant_id=self.tenant_id,
                mcp_urls=all_mcp,
                use_llm=self.config.ramparts_llm,
                log_fn=self._log
            )
            report.findings_ramparts = findings
        except Exception as e:
            self._log("ramparts", f"Phase-Fehler: {e}", "error")

    def _aggregate(self, report: PipelineReport):
        """Alle Findings deduplizieren, priorisieren, Risk-Score berechnen"""
        all_findings = (
            report.findings_subfinder +
            report.findings_naabu +
            report.findings_theharvester +
            report.findings_sslyze +
            report.findings_httpx +
            report.findings_nuclei +
            report.findings_ramparts
        )

        # Deduplizierung via Fingerprint
        seen = {}
        unique = []
        for f in all_findings:
            if f.fingerprint not in seen:
                seen[f.fingerprint] = f
                unique.append(f)
            else:
                # Höheres Severity gewinnt
                existing = seen[f.fingerprint]
                sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
                if sev_order.get(f.severity, 0) > sev_order.get(existing.severity, 0):
                    seen[f.fingerprint] = f
                    idx = unique.index(existing)
                    unique[idx] = f

        # Nach Severity sortieren
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        unique.sort(key=lambda x: sev_order.get(x.severity, 5))
        report.all_findings = unique

        # Risk-Score
        score = 100
        deductions = {
            "CRITICAL": 20, "HIGH": 10, "MEDIUM": 4, "LOW": 1
        }
        mcp_crit = sum(1 for f in unique
                       if f.category == "mcp_exposure" and f.severity == "CRITICAL")
        for f in unique:
            score -= deductions.get(f.severity, 0)
        if mcp_crit > 0:
            score -= mcp_crit * 5  # Extra-Abzug für MCP-Findings
        report.risk_score = max(0, min(100, score))

        # Statistiken
        report.stats = {
            "total_findings": len(unique),
            "by_severity": {
                sev: sum(1 for f in unique if f.severity == sev)
                for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            },
            "by_tool": {
                tool: sum(1 for f in unique if f.tool == tool)
                for tool in ["subfinder", "naabu", "theharvester",
                             "sslyze", "httpx", "nuclei", "ramparts"]
            },
            "by_category": {
                cat: sum(1 for f in unique if f.category == cat)
                for cat in ["subdomain", "port", "email", "http",
                            "vulnerability", "mcp_exposure", "cve", "osint"]
            },
            "subdomains_found": len(report.subdomains_discovered),
            "emails_found": len(report.emails_harvested),
            "mcp_servers_found": len(report.mcp_servers_found),
            "risk_score": report.risk_score,
        }

    def _print_summary(self, report: PipelineReport):
        s = report.stats
        sev_parts = " | ".join(
            f"{sev}: {s.get('by_severity', {}).get(sev, 0)}"
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        )
        tool_parts = " | ".join(
            f"{tool}: {cnt}"
            for tool, cnt in s.get("by_tool", {}).items() if cnt
        )
        self._log("pipeline",
                  f"DONE {report.domain} | {report.duration_seconds}s | "
                  f"score={report.risk_score} | total={s.get('total_findings', 0)} | "
                  f"{sev_parts}", "info")
        if tool_parts:
            self._log("pipeline", f"By tool: {tool_parts}", "info")
        self._log("pipeline",
                  f"subdomains={s.get('subdomains_found', 0)} "
                  f"emails={s.get('emails_found', 0)} "
                  f"mcp={s.get('mcp_servers_found', 0)}", "info")


# ─── Celery-Task-Integration ──────────────────────────────────────────────────

def create_celery_tasks(celery_app, db_session_factory):
    """
    Registriert Pipeline-Tasks in Celery.
    Aufruf in workers/scan_tasks.py:

        from pipeline.orchestrator import create_celery_tasks
        create_celery_tasks(celery_app, get_db)
    """

    @celery_app.task(
        name="pipeline.run_full_easm",
        bind=True,
        max_retries=2,
        queue="scans"
    )
    def run_full_easm(self, tenant_id: str, scan_config: dict):
        """Vollständiger EASM-Pipeline-Task"""
        config = PipelineConfig(
            api_keys=scan_config.get("api_keys", {}),
            naabu_ports=scan_config.get("ports", "top-1000"),
            httpx_screenshots=scan_config.get("screenshots", True),
            run_mcp_scan=scan_config.get("mcp_scan", True),
            ramparts_llm=scan_config.get("ramparts_llm", False),
        )

        pipeline = EASMPipeline(tenant_id=tenant_id, config=config)
        report = pipeline.run(
            domain=scan_config.get("domain", ""),
            ip_ranges=scan_config.get("ip_ranges", []),
            panos_version=scan_config.get("panos_version", "")
        )

        # Report in DB speichern (Placeholder)
        # with db_session_factory() as db:
        #     save_pipeline_report(db, report)

        return {
            "tenant_id": tenant_id,
            "risk_score": report.risk_score,
            "total_findings": report.stats.get("total_findings", 0),
            "mcp_servers": len(report.mcp_servers_found),
            "duration_seconds": report.duration_seconds,
        }

    @celery_app.task(
        name="pipeline.run_mcp_only",
        queue="scans"
    )
    def run_mcp_only(tenant_id: str, targets: list[str]):
        """Nur MCP-Scan für bekannte Hosts"""
        nuclei = NucleiAdapter()
        ramparts = RampartsAdapter()

        findings = []
        findings += nuclei.run_mcp_scan(tenant_id, targets)
        findings += ramparts.run(tenant_id, targets)

        return {
            "tenant_id": tenant_id,
            "mcp_findings": len(findings),
            "critical": sum(1 for f in findings if f.severity == "CRITICAL"),
        }

    return run_full_easm, run_mcp_only


# ─── CLI / Demo ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    domain = sys.argv[1] if len(sys.argv) > 1 else "example.de"
    ip_range = sys.argv[2] if len(sys.argv) > 2 else "192.0.2.0/24"

    config = PipelineConfig(
        # Schneller Demo-Scan
        naabu_ports="top-100",
        naabu_rate=500,
        theharvester_limit=100,
        httpx_threads=20,
        nuclei_tags="api,exposure,mcp",
        nuclei_severity="medium,high,critical",
        httpx_screenshots=False,
        ramparts_llm=False,
    )

    pipeline = EASMPipeline(tenant_id="demo-001", config=config)
    report = pipeline.run(domain=domain, ip_ranges=[ip_range])

    print("\nTop-10 Findings:")
    for f in report.all_findings[:10]:
        print(f"  [{f.severity:8s}] [{f.tool:12s}] {f.title[:70]}")

    print(f"\nFull JSON report saved to /tmp/easm_report_{domain}.json")
    with open(f"/tmp/easm_report_{domain}.json", "w") as out:
        json.dump({
            "stats": report.stats,
            "findings": [asdict(f) for f in report.all_findings],
        }, out, indent=2, default=str)
