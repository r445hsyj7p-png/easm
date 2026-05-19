"""
EASM Toolchain — Tool Adapters
==============================
Einheitliche Wrapper für alle externen Security-Tools.
Jeder Adapter:
  - ruft das Tool via subprocess auf
  - parsed JSON-Output
  - konvertiert Ergebnisse in Finding-Objekte
  - ist als Celery-Task aufrufbar

Tools: Subfinder · Naabu · theHarvester · HTTPX · Nuclei · Ramparts
"""

import subprocess
import json
import logging
import os
import re
import shutil
import hashlib
import tempfile
import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path


# ─── Basis-Finding ────────────────────────────────────────────────────────────

@dataclass
class ToolFinding:
    """Einheitliches Finding-Format für alle Tools"""
    tenant_id: str
    tool: str                    # subfinder | naabu | theharvester | httpx | nuclei | ramparts
    category: str                # subdomain | port | email | http | vulnerability | mcp
    severity: str                # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    description: str
    affected_asset: str          # host, IP:Port, E-Mail, URL
    remediation: str = ""
    raw_data: dict = field(default_factory=dict)
    cve_id: str = ""
    cvss_score: float = 0.0
    cisa_kev: bool = False
    fingerprint: str = ""        # SHA256 für Deduplizierung
    discovered_at: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())

    def __post_init__(self):
        if not self.fingerprint:
            fp_str = f"{self.tool}:{self.category}:{self.affected_asset}:{self.title}"
            self.fingerprint = hashlib.sha256(fp_str.encode()).hexdigest()[:16]


def _run(cmd: list, timeout: int = 300, env: dict = None) -> tuple[int, str, str]:
    """Führt externes Tool aus, gibt (returncode, stdout, stderr) zurück"""
    try:
        proc_env = os.environ.copy()
        if env:
            proc_env.update(env)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=proc_env
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Timeout nach {timeout}s"
    except FileNotFoundError:
        return -2, "", f"Tool nicht gefunden: {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)


def tool_available(name: str) -> bool:
    """Prüft ob ein Tool im PATH verfügbar ist"""
    return shutil.which(name) is not None


def tool_path(name: str) -> str | None:
    """Gibt den absoluten Pfad eines Tools zurück oder None.

    Prefer over tool_available() when building subprocess commands — using the
    full path avoids FileNotFoundError in Celery workers that inherit a PATH
    different from the one Python's shutil.which() scanned at import time.
    """
    return shutil.which(name)


def _verify_executable(path: str) -> tuple[bool, str]:
    """Try to exec the binary with a harmless flag to confirm it actually runs.

    shutil.which() only checks file existence and X_OK permission.  The OS may
    still return ENOENT if the ELF PT_INTERP (dynamic linker) is missing, the
    file is a broken symlink, or a required shared library is absent.

    Returns (ok, diagnostic_message).
    """
    try:
        subprocess.run([path, "-version"], capture_output=True, timeout=5)
        return True, ""
    except FileNotFoundError:
        real = os.path.realpath(path)
        exists = os.path.exists(real)
        return False, (
            f"{path} → {real} (exists={exists}) nicht ausführbar "
            f"(defekter Symlink / fehlender ELF-Interpreter / falsche Architektur)"
        )
    except Exception:
        return True, ""  # timeout or version flag not supported — binary is probably fine


# ═══════════════════════════════════════════════════════════════════════════════
# ADAPTER 1: SUBFINDER
# Subdomain-Discovery via 50+ passive Quellen + Bruteforce
# ═══════════════════════════════════════════════════════════════════════════════

class SubfinderAdapter:
    """
    Subfinder — Subdomain-Discovery
    Docker: projectdiscovery/subfinder
    Binary: https://github.com/projectdiscovery/subfinder

    Findet 5–20x mehr Subdomains als reine DNS-Bruteforce.
    Quellen: VirusTotal, Shodan, Censys, SecurityTrails, DNSdumpster,
             AlienVault, Wayback, Certificate Transparency, ...
    """

    # Subdomains die auf exponierte Management-Interfaces hinweisen
    HIGH_RISK_PATTERNS = {
        "vpn", "remote", "rdp", "ssh", "admin", "portal", "owa",
        "exchange", "webmail", "citrix", "globalprotect", "pulse",
        "phpmyadmin", "cpanel", "whm", "plesk", "jenkins", "gitlab",
        "jira", "confluence", "grafana", "kibana", "elastic", "mongo",
        "redis", "postgres", "mysql", "dev", "staging", "test", "uat",
        "scada", "plc", "hmi", "ics", "mcp", "api-internal", "internal"
    }

    def __init__(self, api_keys: dict = None):
        """
        api_keys: {
            "virustotal": "...",
            "shodan": "...",
            "censys_id": "...",
            "censys_secret": "...",
            "securitytrails": "..."
        }
        """
        self.api_keys = api_keys or {}
        self.binary = "subfinder"

    def run(self, tenant_id: str, domain: str, recursive: bool = False, log_fn=None) -> list[ToolFinding]:
        """
        Startet Subfinder-Scan für eine Domain.

        Args:
            tenant_id: Mandanten-ID
            domain: Ziel-Domain (z.B. "example.de")
            recursive: Auch Subdomains von Subdomains scannen
            log_fn: Optionale Log-Funktion (tool, msg, level)

        Returns:
            Liste von ToolFinding-Objekten
        """
        _binary_path = tool_path(self.binary)
        _avail = _binary_path is not None
        if _avail:
            _ok, _diag = _verify_executable(_binary_path)
            if not _ok:
                _binary_path = None
                _avail = False
        if log_fn:
            log_fn("subfinder", f"binary {'verfügbar' if _avail else 'NICHT gefunden — Docker-Fallback'}"
                   + (f" ({_binary_path})" if _avail else ""), "info" if _avail else "warn")
        if not _avail:
            return self._fallback_docker(tenant_id, domain, log_fn)

        cmd = [
            _binary_path,
            "-d", domain,
            "-json",
            "-silent",
            "-all",                    # Alle Quellen nutzen
        ]
        if recursive:
            cmd += ["-recursive"]

        # Provider config only when API keys are present (empty config causes warnings)
        cfg_path = None
        cfg_content = self._build_config()
        if cfg_content.strip():
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml',
                                             delete=False) as cfg:
                cfg.write(cfg_content)
                cfg_path = cfg.name
            cmd += ["-provider-config", cfg_path]

        try:
            rc, stdout, stderr = _run(cmd, timeout=300)
            if log_fn:
                n_lines = len([l for l in stdout.splitlines() if l.strip()])
                if rc != 0:
                    log_fn("subfinder", f"rc={rc} | stderr: {(stderr or '').strip()[:200]}", "error")
                else:
                    log_fn("subfinder", f"rc=0, {n_lines} JSON-Zeilen ausgegeben", "info")
            return self._parse(tenant_id, domain, stdout, stderr, rc)

        finally:
            if cfg_path and os.path.exists(cfg_path):
                os.unlink(cfg_path)

    def run_docker(self, tenant_id: str, domain: str) -> list[ToolFinding]:
        """Fallback: Subfinder via Docker"""
        cmd = [
            "docker", "run", "--rm",
            "projectdiscovery/subfinder:latest",
            "-d", domain, "-json", "-silent", "-all"
        ]
        rc, stdout, stderr = _run(cmd, timeout=300)
        return self._parse(tenant_id, domain, stdout, stderr, rc)

    def _fallback_docker(self, tenant_id: str, domain: str, log_fn=None) -> list[ToolFinding]:
        """Versucht Docker, dann crt.sh Certificate Transparency als Fallback"""
        if shutil.which("docker"):
            return self.run_docker(tenant_id, domain)
        return self._crtsh_fallback(tenant_id, domain, log_fn)

    def _crtsh_fallback(self, tenant_id: str, domain: str, log_fn=None) -> list[ToolFinding]:
        """Pure-Python Subdomain-Discovery via crt.sh Certificate Transparency Logs"""
        import urllib.request as _ur
        findings = []
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            req = _ur.Request(url, headers={"User-Agent": "EASM-Scanner/1.0"})
            with _ur.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
            seen: set = set()
            for entry in data:
                for raw in (entry.get("common_name", ""), entry.get("name_value", "")):
                    for sub in raw.splitlines():
                        sub = sub.strip().lstrip("*.")
                        if not sub:
                            continue
                        if sub == domain or sub.endswith(f".{domain}"):
                            if sub not in seen:
                                seen.add(sub)
                                label = sub.split(".")[0]
                                sev = "HIGH" if label in self.HIGH_RISK_PATTERNS else "INFO"
                                findings.append(ToolFinding(
                                    tenant_id=tenant_id, tool="subfinder",
                                    category="subdomain", severity=sev,
                                    title=f"Subdomain entdeckt: {sub}",
                                    description=f"Subdomain via Certificate Transparency (crt.sh): {sub}",
                                    affected_asset=sub,
                                    raw_data={"source": "crt.sh"},
                                ))
            if log_fn:
                log_fn("subfinder", f"crt.sh CT-Fallback: {len(findings)} Subdomains für {domain}", "info")
        except Exception as e:
            if log_fn:
                log_fn("subfinder", f"crt.sh Fallback fehlgeschlagen: {e}", "warn")
        return findings

    def _build_config(self) -> str:
        """Erzeugt Subfinder YAML-Config mit API-Keys"""
        lines = []
        if self.api_keys.get("virustotal"):
            lines.append(f"virustotal:\n  - {self.api_keys['virustotal']}")
        if self.api_keys.get("shodan"):
            lines.append(f"shodan:\n  - {self.api_keys['shodan']}")
        if self.api_keys.get("censys_id") and self.api_keys.get("censys_secret"):
            lines.append(f"censys:\n  - {self.api_keys['censys_id']}:{self.api_keys['censys_secret']}")
        if self.api_keys.get("securitytrails"):
            lines.append(f"securitytrails:\n  - {self.api_keys['securitytrails']}")
        return "\n".join(lines) if lines else ""

    def _parse(self, tenant_id: str, domain: str,
               stdout: str, stderr: str, rc: int) -> list[ToolFinding]:
        """Parsed Subfinder JSON-Output in Findings"""
        findings = []

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                # Subfinder gibt pro Zeile: {"host": "sub.domain.de", "source": "virustotal", ...}
                entry = json.loads(line)
                subdomain = entry.get("host", "").lower().strip()
                if not subdomain or not subdomain.endswith(f".{domain}"):
                    continue

                # Risiko-Einstufung anhand des Subdomain-Namens
                label = subdomain.split(".")[0]
                severity = "HIGH" if label in self.HIGH_RISK_PATTERNS else "MEDIUM"
                source = entry.get("source", "unknown")

                # CRITICAL wenn mehrere Quellen bestätigen (echter Treffer)
                ip = entry.get("ip", "")
                cname = entry.get("cname", "")

                # Subdomain-Takeover wenn CNAME auf externe Plattform
                takeover_targets = ["github", "heroku", "amazonaws", "cloudfront",
                                    "shopify", "zendesk", "ghost", "surge", "netlify"]
                if cname and any(t in cname.lower() for t in takeover_targets):
                    severity = "CRITICAL"
                    title = f"Subdomain Takeover möglich: {subdomain}"
                    desc = (f"Die Subdomain {subdomain} hat einen CNAME auf {cname}, "
                           f"der auf eine externe Plattform zeigt die möglicherweise "
                           f"nicht mehr aktiv ist. Subdomain-Takeover möglich.")
                    remediation = f"CNAME {cname} entfernen oder Ressource auf Plattform neu erstellen"
                else:
                    title = f"{'Management-Interface' if severity == 'HIGH' else 'Subdomain'} exponiert: {subdomain}"
                    desc = (f"Subdomain via {source} entdeckt. "
                           f"IP: {ip or 'unbekannt'}. "
                           f"{'Zeigt auf Management-Interface.' if severity == 'HIGH' else ''}")
                    remediation = (f"Management-Interface '{label}' hinter VPN schützen"
                                  if severity == "HIGH" else "Subdomain auf Notwendigkeit prüfen")

                findings.append(ToolFinding(
                    tenant_id=tenant_id,
                    tool="subfinder",
                    category="subdomain",
                    severity=severity,
                    title=title,
                    description=desc,
                    affected_asset=subdomain,
                    remediation=remediation,
                    raw_data=entry,
                ))

            except (json.JSONDecodeError, KeyError):
                # Subfinder gibt manchmal nur den Hostnamen (kein JSON)
                if line and "." in line:
                    label = line.split(".")[0]
                    severity = "HIGH" if label in self.HIGH_RISK_PATTERNS else "MEDIUM"
                    findings.append(ToolFinding(
                        tenant_id=tenant_id, tool="subfinder",
                        category="subdomain", severity=severity,
                        title=f"Subdomain entdeckt: {line}",
                        description=f"Subdomain {line} gefunden.",
                        affected_asset=line,
                    ))

        return findings


# ═══════════════════════════════════════════════════════════════════════════════
# ADAPTER 2: NAABU
# Port-Scanner — SYN-Scan, UDP, deutlich schneller als TCP-Connect
# ═══════════════════════════════════════════════════════════════════════════════

class NaabuAdapter:
    """
    Naabu — Port Scanner
    Docker: projectdiscovery/naabu
    Binary: https://github.com/projectdiscovery/naabu

    SYN-Scan (braucht root/NET_RAW): 10x schneller als TCP-Connect.
    /24 in unter 30 Sekunden.
    """

    # Ports mit sofortigem Risiko wenn offen
    CRITICAL_PORTS = {23, 445, 2375, 502, 102, 44818, 20000, 9600, 11001, 2379, 10250}
    HIGH_PORTS = {22, 3306, 5432, 1433, 3389, 5900, 5985, 5986, 6379, 9200, 27017,
                  8888, 3000, 9090, 5601, 8161, 10000, 4848, 7001, 6443, 8983}
    MCP_PORTS = {6274, 6277, 3000, 8080, 8000, 9000, 4000, 5000}  # typische MCP-Ports

    SERVICE_MAP = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM",
        6379: "Redis", 6274: "MCP-Inspector-UI", 6277: "MCP-Inspector-Proxy",
        8080: "HTTP-Alt (evtl. MCP)", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
        10250: "K8s-Kubelet", 27017: "MongoDB", 2375: "Docker-API",
        2379: "etcd", 6443: "K8s-API", 502: "Modbus", 102: "S7/Siemens",
    }

    def __init__(self):
        self.binary = "naabu"

    def run(self, tenant_id: str, targets: list[str],
            ports: str = "top-1000", rate: int = 1000,
            nmap_integration: bool = False,
            log_fn=None) -> list[ToolFinding]:
        """
        Args:
            targets: Liste von IPs, Ranges oder Hostnamen
            ports: "top-100", "top-1000", "full" oder "80,443,8080,..."
            rate: Pakete/Sekunde (Standard: 1000, max ~10000)
            nmap_integration: Nmap für Service-Detection nach Port-Scan
            log_fn: Optionale Log-Funktion (tool, msg, level)
        """
        _binary_path = tool_path(self.binary)
        _avail = _binary_path is not None
        if _avail:
            _ok, _diag = _verify_executable(_binary_path)
            if not _ok:
                _binary_path = None
                _avail = False
        if log_fn:
            log_fn("naabu", f"binary {'verfügbar' if _avail else 'NICHT gefunden — Docker-Fallback'}"
                   + (f" ({_binary_path})" if _avail else ""), "info" if _avail else "warn")

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt',
                                          delete=False) as tf:
            tf.write("\n".join(targets))
            target_file = tf.name

        try:
            cmd = [
                _binary_path if _avail else "naabu",
                "-list", target_file,
                "-json",
                "-silent",
                "-rate", str(rate),
                "-retries", "2",
                "-timeout", "5000",  # ms
            ]

            if ports == "top-100":
                cmd += ["-top-ports", "100"]
            elif ports == "top-1000":
                cmd += ["-top-ports", "1000"]
            elif ports == "full":
                cmd += ["-p", "-"]  # alle 65535 Ports
            else:
                cmd += ["-p", ports]

            if nmap_integration:
                cmd += ["-nmap-cli", "nmap -sV -sC"]

            # Docker-Fallback, then Python fallback
            if not _avail:
                if shutil.which("docker"):
                    return self._run_docker(tenant_id, targets, ports, rate)
                return self._python_portscan_fallback(tenant_id, targets, log_fn)

            rc, stdout, stderr = _run(cmd, timeout=600)
            if log_fn:
                if rc != 0 and not stdout.strip():
                    log_fn("naabu", f"rc={rc} | stderr: {(stderr or '').strip()[:200]}", "error" if rc > 0 else "warn")
                else:
                    log_fn("naabu", f"rc={rc}, {len(stdout.splitlines())} Zeilen stdout", "info")
            return self._parse(tenant_id, stdout, stderr, rc)

        finally:
            os.unlink(target_file)

    def _run_docker(self, tenant_id, targets, ports, rate) -> list[ToolFinding]:
        target_str = ",".join(targets)
        port_arg = ["-top-ports", "1000"] if ports == "top-1000" else ["-p", ports]
        cmd = ["docker", "run", "--rm", "--cap-add=NET_RAW",
               "projectdiscovery/naabu:latest",
               "-host", target_str, "-json", "-silent"] + port_arg
        rc, stdout, stderr = _run(cmd, timeout=600)
        return self._parse(tenant_id, stdout, stderr, rc)

    def _python_portscan_fallback(self, tenant_id: str, targets: list[str], log_fn=None) -> list[ToolFinding]:
        """Pure-Python TCP port scan on common ports when naabu and Docker unavailable."""
        import socket as _s
        from concurrent.futures import ThreadPoolExecutor as _TPE
        COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                        1433, 1521, 2375, 3000, 3306, 3389, 4000, 5000, 5432, 5900,
                        5985, 6274, 6277, 6379, 8000, 8080, 8443, 8888, 9000, 9200,
                        10250, 27017]
        findings = []
        hosts = list({t.replace("http://","").replace("https://","").split("/")[0].split(":")[0]
                      for t in targets if t})[:15]

        def _check(host, port):
            try:
                with _s.create_connection((host, port), timeout=2):
                    return True
            except Exception:
                return False

        pairs = [(h, p) for h in hosts for p in COMMON_PORTS]
        n_workers = max(1, min(50, len(pairs)))
        with _TPE(max_workers=n_workers) as ex:
            futs = {ex.submit(_check, h, p): (h, p) for h, p in pairs}
            for fut, (host, port) in futs.items():
                try:
                    if fut.result(timeout=3):
                        service = self.SERVICE_MAP.get(port, f"Port {port}")
                        is_mcp = port in self.MCP_PORTS
                        sev = ("CRITICAL" if port in self.CRITICAL_PORTS
                               else "HIGH" if port in self.HIGH_PORTS or is_mcp
                               else "MEDIUM")
                        findings.append(ToolFinding(
                            tenant_id=tenant_id, tool="naabu",
                            category="mcp_exposure" if is_mcp else "port",
                            severity=sev,
                            title=f"{service} exponiert: {host}:{port}",
                            description=f"Port {port} ({service}) auf {host} ist offen.",
                            affected_asset=f"{host}:{port}",
                            raw_data={"ip": host, "port": port},
                        ))
                except Exception:
                    pass
        if log_fn:
            log_fn("naabu", f"Python TCP-Fallback: {len(findings)} offene Ports auf {len(hosts)} Hosts", "info")
        return findings

    def _parse(self, tenant_id: str, stdout: str,
               stderr: str, rc: int) -> list[ToolFinding]:
        findings = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                # Naabu: {"ip": "1.2.3.4", "port": 443, "host": "example.de"}
                entry = json.loads(line)
                ip = entry.get("ip", "")
                port = entry.get("port", 0)
                host = entry.get("host", ip)
                asset = f"{host}:{port}"

                service = self.SERVICE_MAP.get(port, f"Port {port}")
                is_mcp = port in self.MCP_PORTS

                if port in self.CRITICAL_PORTS:
                    severity = "CRITICAL"
                elif port in self.HIGH_PORTS:
                    severity = "HIGH"
                elif is_mcp:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"

                if is_mcp:
                    title = f"Möglicher MCP-Server-Port offen: {asset}"
                    desc = (f"Port {port} auf {host} ist offen. "
                           f"Dieser Port wird häufig für MCP-Server genutzt. "
                           f"Ohne Authentifizierung können KI-Agenten-Tools aufgerufen werden.")
                    remediation = "MCP-Authentifizierung erzwingen oder Port hinter Firewall"
                else:
                    title = f"{service} exponiert: {asset}"
                    desc = f"Port {port} ({service}) auf {host} ist offen."
                    remediation = f"Port {port} hinter Firewall / VPN schützen"

                findings.append(ToolFinding(
                    tenant_id=tenant_id, tool="naabu",
                    category="mcp_exposure" if is_mcp else "port",
                    severity=severity,
                    title=title, description=desc,
                    affected_asset=asset, remediation=remediation,
                    raw_data=entry,
                ))
            except (json.JSONDecodeError, KeyError):
                pass
        return findings


# ═══════════════════════════════════════════════════════════════════════════════
# ADAPTER 3: THEHARVESTER  (native Python — kein externes Binary)
# OSINT — E-Mails, DNS-Records, Subdomains aus öffentlichen Quellen
# ═══════════════════════════════════════════════════════════════════════════════

class TheHarvesterAdapter:
    """
    Native Python OSINT — kein externes Binary, keine schweren Dependencies.

    Quellen:
      - DNS: MX / NS / TXT / SPF / DMARC → E-Mail-Infrastruktur, Dienste
      - crt.sh: Certificate Transparency → Subdomains
      - Wayback CDX API: historische Crawl-URLs → zusätzliche Subdomains
      - HTTP-Scraping: Website, robots.txt, sitemap.xml, /contact, /about
        → E-Mail-Adressen per Regex

    Abhängigkeiten: dnspython, requests — beide bereits in requirements.txt.
    """

    _EMAIL_RE = re.compile(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
    )
    # Pages likely to contain email addresses
    _SCRAPE_PATHS = [
        "/", "/contact", "/kontakt", "/about", "/ueber-uns",
        "/team", "/imprint", "/impressum", "/legal",
        "/robots.txt", "/sitemap.xml",
    ]
    # DNS record types queried on the apex domain
    _DNS_TYPES = ["MX", "NS", "TXT", "SOA"]

    def run(self, tenant_id: str, domain: str,
            limit: int = 500,        # unused — kept for API compatibility
            use_full_sources: bool = False,  # unused — kept for API compatibility
            log_fn=None) -> list[ToolFinding]:
        if log_fn:
            log_fn("theharvester", f"native Python OSINT für {domain}", "info")

        emails     = self._harvest_emails(domain, log_fn)
        dns_info   = self._harvest_dns(domain, log_fn)
        crtsh_subs = self._harvest_crtsh(domain, log_fn)
        wb_subs    = self._harvest_wayback(domain, log_fn)
        subdomains = sorted(set(crtsh_subs) | set(wb_subs))

        findings = []
        self._emit_email_findings(tenant_id, domain, emails, findings)
        self._emit_dns_findings(tenant_id, domain, dns_info, findings)
        self._emit_subdomain_findings(tenant_id, domain, subdomains,
                                      crtsh_count=len(crtsh_subs),
                                      wb_count=len(wb_subs),
                                      findings=findings)

        if log_fn:
            log_fn("theharvester",
                   f"{len(emails)} E-Mails | {len(subdomains)} Subdomains "
                   f"(crt.sh={len(crtsh_subs)}, wayback={len(wb_subs)}) "
                   f"| {sum(len(v) for v in dns_info.values())} DNS-Records", "info")
        return findings

    # ── Email harvesting ───────────────────────────────────────────────────────

    def _harvest_emails(self, domain: str, log_fn) -> set:
        import requests as _req
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        emails = set()
        session = _req.Session()
        session.headers["User-Agent"] = "Mozilla/5.0 EASM-Scanner/1.0"

        for path in self._SCRAPE_PATHS:
            for scheme in ("https", "http"):
                url = f"{scheme}://{domain}{path}"
                try:
                    resp = session.get(url, timeout=8, allow_redirects=True,
                                       verify=False)
                    found = self._EMAIL_RE.findall(resp.text)
                    emails.update(e.lower() for e in found)
                    break  # scheme succeeded (even 404) — don't retry with http
                except Exception:
                    continue  # connection refused / timeout — try next scheme

        # Filter out false positives: image names, file extensions, etc.
        emails = {
            e for e in emails
            if "." in e.split("@")[1]
            and not e.endswith((".png", ".jpg", ".gif", ".svg", ".css", ".js"))
            and len(e) < 120
        }
        return emails

    # ── DNS records ───────────────────────────────────────────────────────────

    def _harvest_dns(self, domain: str, log_fn) -> dict:
        try:
            import dns.resolver as _res
            import dns.exception as _exc
        except ImportError:
            if log_fn:
                log_fn("theharvester", "dnspython nicht verfügbar — DNS-Phase übersprungen", "warn")
            return {}

        records: dict[str, list[str]] = {}

        # Standard records on apex domain
        for rtype in self._DNS_TYPES:
            try:
                answers = _res.resolve(domain, rtype, lifetime=10)
                records[rtype] = [str(r) for r in answers]
                if log_fn:
                    log_fn("theharvester", f"DNS {rtype}: {len(records[rtype])} Records", "debug")
            except _exc.NXDOMAIN:
                if log_fn:
                    log_fn("theharvester", f"DNS {rtype}: NXDOMAIN für {domain}", "debug")
            except _exc.NoAnswer:
                pass  # record type simply not set — not an error
            except Exception as exc:
                if log_fn:
                    log_fn("theharvester", f"DNS {rtype} Fehler: {exc}", "debug")

        # DMARC is always on _dmarc.<domain>, never on the apex domain
        dmarc_host = f"_dmarc.{domain}"
        try:
            dmarc_answers = _res.resolve(dmarc_host, "TXT", lifetime=10)
            records["DMARC"] = [str(r) for r in dmarc_answers]
            if log_fn:
                log_fn("theharvester", f"DMARC-Record auf {dmarc_host} gefunden", "debug")
        except _exc.NXDOMAIN:
            records["DMARC"] = []  # subdomain does not exist → no DMARC
        except _exc.NoAnswer:
            records["DMARC"] = []  # subdomain exists but no TXT → no DMARC
        except Exception as exc:
            records["DMARC"] = []
            if log_fn:
                log_fn("theharvester", f"DMARC-Abfrage Fehler ({dmarc_host}): {exc}", "debug")

        return records

    # ── Certificate Transparency (crt.sh) ────────────────────────────────────

    def _harvest_crtsh(self, domain: str, log_fn) -> list[str]:
        import requests as _req
        import time as _time
        _RETRYABLE = {502, 503, 504}
        for attempt in range(3):
            try:
                resp = _req.get(
                    "https://crt.sh/",
                    params={"q": f"%.{domain}", "output": "json"},
                    timeout=15,
                    headers={"User-Agent": "EASM-Scanner/1.0"},
                )
                if resp.status_code == 200:
                    subdomains = set()
                    for entry in resp.json():
                        name = entry.get("name_value", "")
                        for n in name.splitlines():
                            n = n.strip().lstrip("*.")
                            if n.endswith(f".{domain}") or n == domain:
                                subdomains.add(n.lower())
                    return sorted(subdomains)
                if resp.status_code in _RETRYABLE and attempt < 2:
                    wait = 5 * (2 ** attempt)  # 5s, 10s
                    if log_fn:
                        log_fn("theharvester",
                               f"crt.sh HTTP {resp.status_code} — Retry {attempt + 1}/3 in {wait}s",
                               "warn")
                    _time.sleep(wait)
                    continue
                if log_fn:
                    log_fn("theharvester", f"crt.sh HTTP {resp.status_code}", "warn")
                return []
            except Exception as exc:
                if attempt < 2:
                    wait = 5 * (2 ** attempt)
                    if log_fn:
                        log_fn("theharvester",
                               f"crt.sh Fehler: {exc} — Retry {attempt + 1}/3 in {wait}s",
                               "warn")
                    _time.sleep(wait)
                else:
                    if log_fn:
                        log_fn("theharvester", f"crt.sh Fehler nach 3 Versuchen: {exc}", "warn")
        return []

    # ── Wayback CDX API ───────────────────────────────────────────────────────

    def _harvest_wayback(self, domain: str, log_fn) -> list[str]:
        """Query the Wayback Machine CDX API for historical URLs → extract subdomains."""
        import requests as _req
        import time as _time
        _RETRYABLE = {502, 503, 504, 429}
        for attempt in range(3):
            try:
                resp = _req.get(
                    "http://web.archive.org/cdx/search/cdx",
                    params={
                        "url": f"*.{domain}",
                        "output": "json",
                        "fl": "original",
                        "collapse": "urlkey",
                        "limit": "2000",
                    },
                    timeout=20,
                    headers={"User-Agent": "EASM-Scanner/1.0"},
                )
                if resp.status_code == 200:
                    rows = resp.json()
                    # First row is the header ["original"], skip it
                    subdomains = set()
                    for row in rows[1:]:
                        if not row:
                            continue
                        url = row[0]
                        # Extract host: strip scheme, port, path
                        host = url.split("//")[-1].split("/")[0].split(":")[0].lower()
                        if host.endswith(f".{domain}") or host == domain:
                            subdomains.add(host)
                    return sorted(subdomains)
                if resp.status_code in _RETRYABLE and attempt < 2:
                    wait = 5 * (2 ** attempt)  # 5s, 10s
                    if log_fn:
                        log_fn("theharvester",
                               f"Wayback CDX HTTP {resp.status_code} — Retry {attempt + 1}/3 in {wait}s",
                               "warn")
                    _time.sleep(wait)
                    continue
                if log_fn:
                    log_fn("theharvester", f"Wayback CDX HTTP {resp.status_code}", "warn")
                return []
            except Exception as exc:
                if attempt < 2:
                    wait = 5 * (2 ** attempt)
                    if log_fn:
                        log_fn("theharvester",
                               f"Wayback CDX Fehler: {exc} — Retry {attempt + 1}/3 in {wait}s",
                               "warn")
                    _time.sleep(wait)
                else:
                    if log_fn:
                        log_fn("theharvester", f"Wayback CDX Fehler nach 3 Versuchen: {exc}", "warn")
        return []

    # ── Finding emitters ──────────────────────────────────────────────────────

    def _emit_email_findings(self, tenant_id, domain, emails, findings):
        if not emails:
            return
        domain_emails = sorted(e for e in emails if e.endswith(f"@{domain}"))
        other_emails  = sorted(e for e in emails if not e.endswith(f"@{domain}"))

        if domain_emails:
            findings.append(ToolFinding(
                tenant_id=tenant_id, tool="theharvester",
                category="email", severity="MEDIUM",
                title=f"{len(domain_emails)} @{domain} E-Mails öffentlich gefunden",
                description=(
                    f"{len(domain_emails)} @{domain} E-Mail-Adressen auf öffentlichen Seiten "
                    f"des Unternehmens gefunden. Sollten gegen HIBP/Stealer-Logs geprüft werden.\n"
                    f"Beispiele: {', '.join(domain_emails[:5])}"
                    + ("..." if len(domain_emails) > 5 else "")
                ),
                affected_asset=domain,
                remediation="E-Mails gegen HIBP prüfen, Passwort-Reset-Kampagne, Security-Awareness-Training",
                raw_data={"emails": domain_emails, "other_emails": other_emails[:20]},
            ))

        if other_emails:
            findings.append(ToolFinding(
                tenant_id=tenant_id, tool="theharvester",
                category="email", severity="INFO",
                title=f"{len(other_emails)} externe E-Mails auf {domain} gefunden",
                description=f"Drittanbieter-E-Mails: {', '.join(other_emails[:10])}",
                affected_asset=domain,
                raw_data={"emails": other_emails},
            ))

    def _emit_dns_findings(self, tenant_id, domain, dns_info, findings):
        if not dns_info:
            return

        mx    = dns_info.get("MX", [])
        txt   = dns_info.get("TXT", [])
        dmarc = dns_info.get("DMARC", [])  # queried from _dmarc.<domain> in _harvest_dns
        spf   = [r for r in txt if "v=spf1" in r.lower()]

        if not spf:
            findings.append(ToolFinding(
                tenant_id=tenant_id, tool="theharvester",
                category="dns", severity="MEDIUM",
                title=f"Kein SPF-Record für {domain}",
                description="Ohne SPF-Record können Angreifer E-Mails im Namen der Domain versenden (Email Spoofing).",
                affected_asset=domain,
                remediation='SPF-TXT-Record setzen: "v=spf1 include:... -all"',
            ))

        if not dmarc:
            findings.append(ToolFinding(
                tenant_id=tenant_id, tool="theharvester",
                category="dns", severity="MEDIUM",
                title=f"Kein DMARC-Record für {domain}",
                description="Ohne DMARC können gefälschte E-Mails der Domain nicht abgewiesen werden.",
                affected_asset=domain,
                remediation=f'DMARC-TXT-Record für _dmarc.{domain} setzen: "v=DMARC1; p=reject; ..."',
            ))

        if mx:
            findings.append(ToolFinding(
                tenant_id=tenant_id, tool="theharvester",
                category="dns", severity="INFO",
                title=f"MX-Records: {domain}",
                description=f"E-Mail-Server: {', '.join(mx[:5])}",
                affected_asset=domain,
                raw_data={"mx": mx, "spf": spf, "dmarc": dmarc,
                          "ns": dns_info.get("NS", [])},
            ))

    def _emit_subdomain_findings(self, tenant_id, domain, subdomains,
                                  crtsh_count: int, wb_count: int, findings):
        if not subdomains:
            return
        sources = []
        if crtsh_count:
            sources.append(f"crt.sh={crtsh_count}")
        if wb_count:
            sources.append(f"wayback={wb_count}")
        source_note = f" ({', '.join(sources)})" if sources else ""
        findings.append(ToolFinding(
            tenant_id=tenant_id, tool="theharvester",
            category="subdomain", severity="LOW",
            title=f"{len(subdomains)} Subdomains via OSINT{source_note}",
            description=(
                f"{len(subdomains)} Subdomains für {domain} in öffentlichen Quellen gefunden.\n"
                f"Hosts: {', '.join(subdomains[:15])}"
                + ("..." if len(subdomains) > 15 else "")
            ),
            affected_asset=domain,
            remediation="Subdomains auf Notwendigkeit und Sicherheit prüfen",
            raw_data={"subdomains": subdomains, "sources": sources},
        ))


# ═══════════════════════════════════════════════════════════════════════════════
# ADAPTER 4: HTTPX
# HTTP-Probing mit Screenshots, Favicon-Hash, Technologie-Fingerprinting
# ═══════════════════════════════════════════════════════════════════════════════

class HTTPXAdapter:
    """
    HTTPX — HTTP Probing & Fingerprinting
    Docker: projectdiscovery/httpx
    Binary: https://github.com/projectdiscovery/httpx

    Ermöglicht:
    - Screenshot via headless Chrome
    - Favicon-Hash (Shodan-kompatibel)
    - Wappalyzer-Technologie-Erkennung
    - CDN-Erkennung
    - Content-Hash für Änderungs-Detection
    """

    # Bekannte problematische Technologien in Responses
    RISKY_TECH = {
        "WordPress": ("MEDIUM", "WordPress-Version prüfen, Updates sicherstellen"),
        "PHP": ("MEDIUM", "PHP-Version prüfen, keine Debug-Info in Produktion"),
        "ASP.NET": ("LOW", "ASP.NET-Version und Fehlerseiten prüfen"),
        "Apache": ("LOW", "Apache-Version in Server-Header verbergen"),
        "nginx": ("LOW", "nginx-Version in Server-Header verbergen"),
        "IIS": ("MEDIUM", "IIS-Version prüfen, HTTP-Error-Seiten konfigurieren"),
        "Laravel": ("MEDIUM", "APP_DEBUG=false in Produktion sicherstellen"),
        "Django": ("LOW", "DEBUG=False in Produktion sicherstellen"),
        "Spring Boot": ("HIGH", "Actuator-Endpoints deaktivieren oder absichern"),
        "Tomcat": ("MEDIUM", "Tomcat-Manager-Interface abschalten oder schützen"),
    }

    # Security-Header die fehlen sollten als Finding gemeldet werden
    REQUIRED_HEADERS = {
        "Strict-Transport-Security": ("MEDIUM", "HSTS aktivieren"),
        "Content-Security-Policy": ("MEDIUM", "CSP-Header setzen"),
        "X-Frame-Options": ("LOW", "Clickjacking-Schutz aktivieren"),
        "X-Content-Type-Options": ("LOW", "MIME-Sniffing deaktivieren"),
    }

    def __init__(self, screenshot_dir: str = "/tmp/easm_screenshots"):
        self.binary = "httpx"
        self.screenshot_dir = screenshot_dir
        os.makedirs(screenshot_dir, exist_ok=True)

    def run(self, tenant_id: str, urls: list[str],
            take_screenshots: bool = True,
            threads: int = 50,
            log_fn=None) -> list[ToolFinding]:
        """
        Args:
            urls: Liste von URLs oder hosts (httpx fügt http/https hinzu)
            take_screenshots: headless Chrome Screenshots (braucht Chrome)
            threads: Parallelität
            log_fn: Optionale Log-Funktion (tool, msg, level)
        """
        _binary_path = tool_path(self.binary)
        _avail = _binary_path is not None
        if _avail:
            _ok, _diag = _verify_executable(_binary_path)
            if not _ok:
                _binary_path = None
                _avail = False
        if log_fn:
            log_fn("httpx", f"binary {'verfügbar' if _avail else 'NICHT gefunden — Docker-Fallback'}"
                   + (f" ({_binary_path})" if _avail else ""), "info" if _avail else "warn")

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt',
                                          delete=False) as tf:
            tf.write("\n".join(urls))
            input_file = tf.name

        try:
            cmd = [
                _binary_path if _avail else "httpx",
                "-l", input_file,
                "-json",
                "-silent",
                "-threads", str(threads),
                "-follow-redirects",
                "-max-redirects", "5",
                "-tech-detect",          # Wappalyzer-Fingerprinting
                "-title",                # Page-Title
                "-status-code",
                "-content-length",
                "-content-type",
                "-web-server",           # Server-Header
                "-cdn",                  # CDN-Erkennung
                "-tls-probe",            # TLS-Info
                "-hash", "sha256",       # Content-Hash
                "-favicon",              # Favicon-Hash
                "-timeout", "10",        # Verbindungs-Timeout pro Host
            ]

            if take_screenshots and (shutil.which("chromium") or shutil.which("google-chrome")):
                cmd += ["-screenshot", "-screenshot-type", "jpeg",
                        "-screenshot-timeout", "10"]

            if not _avail:
                return self._run_docker(tenant_id, urls, take_screenshots)

            rc, stdout, stderr = _run(cmd, timeout=600)
            if log_fn:
                if rc != 0 and not stdout.strip():
                    log_fn("httpx", f"rc={rc} | stderr: {(stderr or '').strip()[:200]}", "error" if rc > 0 else "warn")
                else:
                    log_fn("httpx", f"rc={rc}, {len(stdout.splitlines())} Zeilen stdout", "info")
            return self._parse(tenant_id, stdout, stderr, rc)

        finally:
            os.unlink(input_file)

    def _run_docker(self, tenant_id, urls, screenshots) -> list[ToolFinding]:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tf:
            tf.write("\n".join(urls))
            input_file = tf.name
        try:
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{input_file}:/targets.txt:ro",
                "projectdiscovery/httpx:latest",
                "-l", "/targets.txt",
                "-json", "-silent",
                "-follow-redirects", "-max-redirects", "5",
                "-tech-detect", "-title", "-status-code",
                "-content-length", "-content-type",
                "-web-server", "-cdn", "-tls-probe",
                "-hash", "sha256",
                "-favicon",
                "-timeout", "10",
            ]
            rc, stdout, stderr = _run(cmd, timeout=600)
            return self._parse(tenant_id, stdout, stderr, rc)
        finally:
            os.unlink(input_file)

    def _parse(self, tenant_id: str, stdout: str,
               stderr: str, rc: int) -> list[ToolFinding]:
        findings = []
        for line in stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                url = entry.get("url", "")
                host = entry.get("host", url)
                status = entry.get("status-code", 0)
                tech = entry.get("tech", []) or []
                server = entry.get("webserver", "")
                title = entry.get("title", "")
                cdn = entry.get("cdn", False)
                content_hash = entry.get("hash", {}).get("body-sha256", "")
                favicon_hash = entry.get("favicon-mmh3", "")

                headers = entry.get("headers", {})

                # 1. Fehlende Security-Header
                missing_headers = []
                for header, (sev, remediation) in self.REQUIRED_HEADERS.items():
                    if header.lower() not in {k.lower() for k in headers}:
                        missing_headers.append(header)

                if missing_headers:
                    findings.append(ToolFinding(
                        tenant_id=tenant_id, tool="httpx",
                        category="http",
                        severity="MEDIUM" if "Strict-Transport-Security" in missing_headers else "LOW",
                        title=f"Fehlende Security-Header: {url}",
                        description=f"Folgende Security-Header fehlen: {', '.join(missing_headers)}",
                        affected_asset=url,
                        remediation="Security-Header in Web-Server-Konfiguration setzen",
                        raw_data={"missing_headers": missing_headers, "all_headers": headers},
                    ))

                # 2. Technologie-Fingerprinting
                for t in tech:
                    if not t or not isinstance(t, str):
                        continue
                    t_name = t.split(":")[0] if ":" in t else t
                    if t_name in self.RISKY_TECH:
                        sev, rem = self.RISKY_TECH[t_name]
                        findings.append(ToolFinding(
                            tenant_id=tenant_id, tool="httpx",
                            category="http",
                            severity=sev,
                            title=f"{t_name} erkannt: {url}",
                            description=f"Technologie-Stack: {', '.join(tech)}. Version: {t}",
                            affected_asset=url,
                            remediation=rem,
                            raw_data={"tech": tech, "server": server, "title": title},
                        ))

                # 3. Interessante Status-Codes
                if status in (200, 301, 302):
                    # Screenshot-Info
                    screenshot_path = entry.get("screenshot", {}).get("path", "")

                    findings.append(ToolFinding(
                        tenant_id=tenant_id, tool="httpx",
                        category="http",
                        severity="INFO",
                        title=f"HTTP-Service aktiv: {url} [{status}]",
                        description=(
                            f"Title: {title or 'N/A'} | Server: {server or 'N/A'} | "
                            f"Tech: {', '.join(tech[:3]) or 'unbekannt'} | "
                            f"CDN: {'Ja' if cdn else 'Nein'} | "
                            f"Content-Hash: {content_hash[:16] if content_hash else 'N/A'}"
                        ),
                        affected_asset=url,
                        raw_data={
                            "status": status, "tech": tech, "server": server,
                            "title": title, "cdn": cdn, "favicon_hash": favicon_hash,
                            "content_hash": content_hash,
                            "screenshot": screenshot_path
                        },
                    ))

                # 4. Kritische Endpunkte in Title erkannt
                critical_titles = [
                    "jenkins", "grafana", "kibana", "prometheus", "sonarqube",
                    "gitlab", "jupyter", "phpmyadmin", "adminer", "webmin",
                    "mcp inspector", "claude", "openai"
                ]
                if title and any(ct in title.lower() for ct in critical_titles):
                    matched = next(ct for ct in critical_titles if ct in title.lower())
                    findings.append(ToolFinding(
                        tenant_id=tenant_id, tool="httpx",
                        category="exposed_service",
                        severity="HIGH",
                        title=f"Admin-Interface exponiert: {matched.title()} auf {url}",
                        description=f"Page-Title '{title}' weist auf exponiertes Admin-Interface hin.",
                        affected_asset=url,
                        remediation=f"{matched.title()} hinter VPN/Bastion-Host schützen",
                        raw_data=entry,
                    ))

            except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                pass

        return findings


# ═══════════════════════════════════════════════════════════════════════════════
# ADAPTER 5: NUCLEI
# Vulnerability Scanner — 7000+ Templates inkl. API, MCP, CVEs
# ═══════════════════════════════════════════════════════════════════════════════

class NucleiAdapter:
    """
    Nuclei — Template-basierter Vulnerability Scanner
    Docker: projectdiscovery/nuclei
    Binary: https://github.com/projectdiscovery/nuclei

    Templates:
    - api/          → Swagger, GraphQL, Actuator, .env, CORS, .git
    - mcp/          → MCP-Server ohne Auth, MCP Inspector, mcp.json
    - cves/         → Bekannte CVEs mit öffentlichem Exploit
    - default-logins/ → Default-Credentials
    - exposures/    → Sensitive Dateien exponiert
    - misconfigs/   → Fehlkonfigurationen
    """

    _logger = logging.getLogger("easm.nuclei")

    def __init__(self):
        self.binary = "nuclei"

    # Template-Kategorien mit Schweregrad-Mapping
    TEMPLATE_SEVERITY = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "info": "INFO",
        "unknown": "MEDIUM",
    }

    # Nuclei-Tags für MCP-spezifische Checks
    MCP_TAGS = "mcp,mcp-server,mcp-inspector,model-context-protocol"

    def run(self, tenant_id: str, targets: list[str],
            template_dirs: list[str] = None,
            tags: str = None,
            severity_filter: str = "info,low,medium,high,critical",
            rate_limit: int = 100,
            bulk_size: int = 25,
            log_fn=None) -> list[ToolFinding]:
        """
        Args:
            targets: URLs oder IPs
            template_dirs: Spezifische Template-Verzeichnisse
            tags: Komma-separierte Tags (z.B. "api,mcp,cve")
            severity_filter: Nur diese Schweregrade
            rate_limit: Requests/Sekunde
            bulk_size: Parallele Targets
            log_fn: Optionale Log-Funktion (tool, msg, level)
        """
        # Use full absolute path from shutil.which so subprocess can locate the binary
        # even when Celery workers inherit a different PATH than the Python process.
        _binary_path = shutil.which(self.binary)
        _avail = _binary_path is not None

        if _avail:
            _ok, _diag = _verify_executable(_binary_path)
            if not _ok:
                if log_fn:
                    log_fn("nuclei", f"{_diag} — Docker/Python-Fallback aktiv", "warn")
                _binary_path = None
                _avail = False
        _home = os.path.expanduser("~")
        _tmpl_dir = os.path.join(_home, "nuclei-templates")
        _tmpl_exists = os.path.isdir(_tmpl_dir)
        # Avoid rglob("*.yaml") over 9000+ templates — use a cheap non-recursive check
        try:
            _tmpl_has_files = _tmpl_exists and any(Path(_tmpl_dir).iterdir())
        except Exception:
            _tmpl_has_files = False
        if log_fn:
            log_fn("nuclei",
                   f"binary {'verfügbar' if _avail else 'NICHT gefunden'}"
                   + (f" ({_binary_path})" if _avail else "")
                   + f" | templates: {'vorhanden' if _tmpl_has_files else 'FEHLEN'} in {_tmpl_dir}",
                   "info" if _avail else "error")

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tf:
            tf.write("\n".join(targets))
            target_file = tf.name

        if log_fn:
            log_fn("nuclei", f"{len(targets)} Targets | erste: {targets[:8]}", "info")

        try:
            # Standard-Templates wenn keine angegeben
            if not template_dirs and not tags:
                # Keep in sync with PipelineConfig.nuclei_tags
                tags = "api,exposure,misconfig,default-logins,mcp,cve,tech"

            cmd = [
                _binary_path if _avail else self.binary,
                "-l", target_file,
                "-jsonl",   # nuclei v3 renamed -json → -jsonl
                "-severity", severity_filter,
                "-rate-limit", str(rate_limit),
                "-bulk-size", str(bulk_size),
                "-timeout", "10",
                "-retries", "1",
                "-no-color",
                "-stats",        # writes template/target counts to stderr — critical for diagnosis
            ]

            if template_dirs:
                for td in template_dirs:
                    cmd += ["-t", td]
            if tags:
                cmd += ["-tags", tags]

            if _tmpl_has_files:
                cmd += ["-duc"]

            if log_fn:
                log_fn("nuclei", f"cmd: {' '.join(str(c) for c in cmd)}", "info")

            if not _avail:
                if shutil.which("docker"):
                    return self._run_docker(tenant_id, targets, tags, severity_filter, log_fn)
                return self._python_http_checks(tenant_id, targets, log_fn)

            rc, stdout, stderr = _run(cmd, timeout=900)
            findings = self._parse(tenant_id, stdout, stderr, rc)

            # Always log stderr — nuclei writes template/target counts there via -stats
            _stderr_full = (stderr or "").strip()
            _stdout_lines = sum(1 for l in stdout.splitlines() if l.strip())
            if log_fn:
                if _stderr_full:
                    # Log stderr in 400-char chunks; cap at 3200 to capture full -stats output
                    for _i in range(0, min(len(_stderr_full), 3200), 400):
                        log_fn("nuclei", f"stderr: {_stderr_full[_i:_i+400]}", "info")
                if rc != 0 and not stdout.strip():
                    log_fn("nuclei", f"rc={rc} FEHLER — kein stdout", "error")
                elif rc != 0:
                    log_fn("nuclei", f"rc={rc} | {_stdout_lines} JSON-Zeilen → {len(findings)} Findings", "warn")
                else:
                    log_fn("nuclei", f"rc=0 | {_stdout_lines} JSON-Zeilen → {len(findings)} Findings", "info")
                if _stdout_lines > 0 and len(findings) == 0:
                    first_line = next((l for l in stdout.splitlines() if l.strip()), "")
                    log_fn("nuclei", f"Parse-Fehler? Erste stdout-Zeile: {first_line[:400]}", "warn")
            return findings

        finally:
            os.unlink(target_file)

    def run_mcp_scan(self, tenant_id: str, targets: list[str], log_fn=None) -> list[ToolFinding]:
        """Spezialisierter MCP-Scan mit MCP-spezifischen Templates"""
        mcp_targets = []
        for t in targets:
            # Skip if already a full URL (has scheme) — avoid double-wrapping
            if t.startswith("http://") or t.startswith("https://"):
                mcp_targets.append(t)
                continue
            for port in [3000, 6274, 6277, 8000, 8080, 9000]:
                mcp_targets.append(f"http://{t}:{port}")
                mcp_targets.append(f"https://{t}:{port}")

        # mcp_targets already contains all derived URLs — do not append raw
        # host strings again, that would scan each hostname a second time
        findings = self.run(
            tenant_id=tenant_id,
            targets=mcp_targets,
            tags=self.MCP_TAGS + ",api,exposure",
            severity_filter="low,medium,high,critical",
            log_fn=log_fn,
        )

        # Zusätzlich: manuelle MCP-Handshake-Checks
        findings += self._check_mcp_handshake(tenant_id, targets)
        return findings

    def _python_http_checks(self, tenant_id: str, targets: list[str], log_fn=None) -> list[ToolFinding]:
        """Pure-Python HTTP security checks when nuclei binary is unavailable."""
        import urllib.request as _ur
        import urllib.error as _ue
        from concurrent.futures import ThreadPoolExecutor as _TPE

        SECURITY_HEADERS = [
            ("Strict-Transport-Security", "MEDIUM", "HSTS-Header fehlt",
             "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload setzen"),
            ("Content-Security-Policy", "MEDIUM", "Content-Security-Policy fehlt",
             "CSP-Header setzen um XSS und Injection-Angriffe zu verhindern"),
            ("X-Frame-Options", "LOW", "X-Frame-Options fehlt (Clickjacking)",
             "X-Frame-Options: DENY oder SAMEORIGIN setzen"),
            ("X-Content-Type-Options", "LOW", "X-Content-Type-Options fehlt",
             "X-Content-Type-Options: nosniff setzen"),
            ("Referrer-Policy", "LOW", "Referrer-Policy fehlt",
             "Referrer-Policy: strict-origin-when-cross-origin setzen"),
        ]
        # Each entry: (path, severity, title, description, content_marker)
        # content_marker: substring that must appear in the response body to
        # avoid false positives from redirected 200 login pages.
        EXPOSED_PATHS = [
            ("/.env",            "CRITICAL", "Exposed .env Datei",
             "Umgebungsvariablen und Credentials öffentlich zugänglich", "DB_"),
            ("/.git/config",     "HIGH",     "Exposed .git/config",
             "Git-Repository-Konfiguration öffentlich zugänglich", "[core]"),
            ("/phpinfo.php",     "MEDIUM",   "phpinfo() exponiert",
             "PHP-Konfigurationsdetails öffentlich zugänglich", "PHP Version"),
            ("/.htaccess",       "MEDIUM",   "Exposed .htaccess",
             "Apache-Konfigurationsdatei öffentlich zugänglich", "Rewrite"),
            ("/wp-config.php.bak","CRITICAL","WordPress Config Backup exponiert",
             "WordPress-Datenbank-Credentials potenziell zugänglich", "DB_NAME"),
            ("/config.php",      "HIGH",     "Exposed config.php",
             "Konfigurationsdatei öffentlich zugänglich", "<?php"),
            ("/backup.sql",      "CRITICAL", "SQL-Backup exponiert",
             "Datenbank-Backup öffentlich zugänglich", "INSERT INTO"),
            ("/server-status",   "MEDIUM",   "Apache server-status exponiert",
             "Server-Metriken und Anfrageliste öffentlich zugänglich", "Server Version"),
            ("/actuator/env",    "CRITICAL", "Spring Boot Actuator /env exponiert",
             "Umgebungsvariablen und Secrets öffentlich zugänglich", "activeProfiles"),
            ("/actuator/health", "LOW",      "Spring Boot Actuator /health exponiert",
             "Anwendungs-Health-Informationen öffentlich zugänglich", '"status"'),
        ]

        findings = []
        urls = [t for t in targets if t.startswith(("http://", "https://"))][:20]

        def _check_url(url):
            local_findings = []
            try:
                req = _ur.Request(url, headers={"User-Agent": "Mozilla/5.0 EASM-Scanner/1.0"})
                resp = _ur.urlopen(req, timeout=10)
                headers_lc = {k.lower(): v for k, v in resp.headers.items()}

                for hdr, sev, title, fix in SECURITY_HEADERS:
                    if hdr.lower() not in headers_lc:
                        # HSTS only makes sense on HTTPS — skip for plain HTTP
                        if hdr == "Strict-Transport-Security" and not url.startswith("https://"):
                            continue
                        local_findings.append(ToolFinding(
                            tenant_id=tenant_id, tool="nuclei",
                            category="vulnerability", severity=sev,
                            title=f"{title}: {url}",
                            description=f"Security-Header '{hdr}' fehlt auf {url}.",
                            affected_asset=url,
                            remediation=fix,
                        ))

                server = headers_lc.get("server", "")
                if server:
                    local_findings.append(ToolFinding(
                        tenant_id=tenant_id, tool="nuclei",
                        category="http", severity="INFO",
                        title=f"Server-Header: {server}",
                        description=f"Server-Banner auf {url}: {server}",
                        affected_asset=url,
                    ))
            except Exception:
                pass

            for path, sev, title, desc, marker in EXPOSED_PATHS:
                try:
                    check_url = url.rstrip("/") + path
                    req = _ur.Request(check_url, headers={"User-Agent": "Mozilla/5.0 EASM-Scanner/1.0"})
                    resp = _ur.urlopen(req, timeout=5)
                    if resp.status == 200:
                        content = resp.read(1024).decode("utf-8", errors="ignore")
                        # Require content_marker to avoid login-page redirect false positives
                        if marker in content:
                            local_findings.append(ToolFinding(
                                tenant_id=tenant_id, tool="nuclei",
                                category="vulnerability", severity=sev,
                                title=f"{title}: {url}",
                                description=f"{desc}. URL: {check_url}",
                                affected_asset=check_url,
                            ))
                except Exception:
                    pass

            return local_findings

        with _TPE(max_workers=8) as ex:
            for result in ex.map(_check_url, urls):
                findings.extend(result)

        if log_fn:
            log_fn("nuclei", f"Python HTTP-Fallback: {len(findings)} Findings auf {len(urls)} URLs", "info")
        return findings

    def _check_mcp_handshake(self, tenant_id: str, targets: list[str]) -> list[ToolFinding]:
        """
        Prüft ob MCP-Server ohne Authentifizierung erreichbar sind.
        Sendet einen MCP JSON-RPC initialize-Request — parallel über alle Hosts/Ports.
        """
        import urllib.request
        import ssl
        from concurrent.futures import ThreadPoolExecutor as _TPE, as_completed as _ac

        mcp_initialize = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "easm-scanner", "version": "1.0"}
            }
        }).encode()

        # Build SSL context once — reused across all workers
        _ssl_ctx = ssl.create_default_context()
        _ssl_ctx.check_hostname = False
        _ssl_ctx.verify_mode = ssl.CERT_NONE

        mcp_endpoints = [
            ("/mcp", 8080), ("/mcp", 3000), ("/mcp", 8000),
            ("/sse", 6277), ("/", 6274),   # MCP Inspector
            ("/mcp", 9000), ("/api/mcp", 8080),
        ]

        # Strip scheme, path, and port — the port comes from mcp_endpoints below.
        # When targets are full URLs (pipeline path: http://host:3000) the naive
        # split("/")[0] leaves "host:3000", which then produces "http://host:3000:8080"
        # → invalid URL.  The extra .split(":")[0] strips the port.
        hosts = list({
            t.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
            for t in targets if t
        })

        def _probe(host: str, path: str, port: int, scheme: str):
            url = f"{scheme}://{host}:{port}{path}"
            try:
                req = urllib.request.Request(
                    url,
                    data=mcp_initialize,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "EASM-Scanner/1.0",
                    },
                    method="POST",
                )
                ctx = _ssl_ctx if scheme == "https" else None
                with urllib.request.urlopen(req, timeout=2, context=ctx) as resp:
                    body = resp.read().decode(errors="ignore")
                if '"jsonrpc"' in body and '"result"' in body:
                    resp_data = json.loads(body)
                    server_info = resp_data.get("result", {}).get("serverInfo", {})
                    capabilities = resp_data.get("result", {}).get("capabilities", {})
                    return ToolFinding(
                        tenant_id=tenant_id,
                        tool="nuclei",
                        category="mcp_exposure",
                        severity="CRITICAL",
                        title=f"MCP-Server ohne Authentifizierung: {url}",
                        description=(
                            f"MCP-Server auf {url} antwortet auf initialize-Requests "
                            f"OHNE Authentifizierung. "
                            f"Server: {server_info.get('name', 'unbekannt')} "
                            f"v{server_info.get('version', '?')}. "
                            f"Capabilities: {list(capabilities.keys())}. "
                            f"Ein Angreifer kann alle verfügbaren Tools (tools/list) "
                            f"auflisten und aufrufen — inkl. Filesystem, Shell, DB-Zugriff."
                        ),
                        affected_asset=url,
                        remediation=(
                            "Bearer-Token-Authentifizierung aktivieren. "
                            "Produktions-MCP-Server nie auf 0.0.0.0 binden. "
                            "MCP Inspector nie in Produktion betreiben."
                        ),
                        raw_data={"response": resp_data, "url": url},
                    )
            except Exception:
                pass  # Port nicht offen oder Auth vorhanden
            return None

        findings = []
        probes = [
            (host, path, port, scheme)
            for host in hosts
            for path, port in mcp_endpoints
            for scheme in ("http", "https")
        ]
        n_workers = min(30, len(probes)) if probes else 1
        with _TPE(max_workers=n_workers) as ex:
            futs = {ex.submit(_probe, *p): p for p in probes}
            for fut in _ac(futs, timeout=30):
                try:
                    result = fut.result()
                    if result:
                        findings.append(result)
                except Exception:
                    pass
        return findings

    def _run_docker(self, tenant_id, targets, tags, severity, log_fn=None) -> list[ToolFinding]:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tf:
            tf.write("\n".join(targets))
            target_file = tf.name
        try:
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{target_file}:/targets.txt:ro",
                "projectdiscovery/nuclei:latest",
                "-l", "/targets.txt", "-jsonl", "-silent",
                "-severity", severity,
                "-duc",  # disable update check inside ephemeral container
            ]
            if tags:
                cmd += ["-tags", tags]
            if log_fn:
                log_fn("nuclei", f"docker fallback | {len(targets)} targets | tags={tags}", "info")
            rc, stdout, stderr = _run(cmd, timeout=900)
            if log_fn:
                _lines = sum(1 for l in stdout.splitlines() if l.strip())
                log_fn("nuclei", f"docker rc={rc} | {_lines} JSON-Zeilen", "info" if rc == 0 else "warn")
            return self._parse(tenant_id, stdout, stderr, rc)
        finally:
            os.unlink(target_file)

    def _parse(self, tenant_id: str, stdout: str,  # NucleiAdapter
               stderr: str, rc: int) -> list[ToolFinding]:
        if rc < 0 or (rc != 0 and not stdout.strip()):
            self._logger.warning("nuclei rc=%d no-stdout stderr=%s", rc, stderr[:300])
        findings = []
        for line in stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                template_id = entry.get("template-id", "unknown")
                name = entry.get("info", {}).get("name", template_id)
                severity_raw = entry.get("info", {}).get("severity", "medium")
                severity = self.TEMPLATE_SEVERITY.get(severity_raw.lower(), "MEDIUM")
                matched_at = entry.get("matched-at", entry.get("host", ""))
                description = entry.get("info", {}).get("description", "")
                remediation = entry.get("info", {}).get("remediation", "")
                # nuclei may return cve-id as a string or a list depending on build/version
                _cve_raw = entry.get("info", {}).get("classification", {}).get("cve-id", [])
                cve_list = [_cve_raw] if isinstance(_cve_raw, str) and _cve_raw else (_cve_raw or [])
                cve_id = cve_list[0] if cve_list else ""
                cvss = entry.get("info", {}).get("classification", {}).get("cvss-score", 0.0)
                # nuclei v3: info.tags can be a comma-string OR a list depending on build
                _tags_raw = entry.get("info", {}).get("tags", [])
                if isinstance(_tags_raw, str):
                    tags_list = [t.strip() for t in _tags_raw.split(",") if t.strip()]
                else:
                    tags_list = list(_tags_raw) if _tags_raw else []

                is_mcp = any(t in {"mcp", "mcp-server", "model-context-protocol", "mcp-inspector"}
                            for t in tags_list)
                category = "mcp_exposure" if is_mcp else (
                    "cve" if cve_id else "vulnerability"
                )

                findings.append(ToolFinding(
                    tenant_id=tenant_id, tool="nuclei",
                    category=category,
                    severity=severity,
                    title=f"[{template_id}] {name}",
                    description=description or f"Nuclei-Template {template_id} angeschlagen.",
                    affected_asset=matched_at,
                    remediation=remediation,
                    cve_id=cve_id,
                    cvss_score=float(cvss) if cvss else 0.0,
                    raw_data=entry,
                ))
            except (json.JSONDecodeError, KeyError, ValueError, TypeError) as _e:
                self._logger.debug("nuclei _parse: skip line (%s): %.200s", _e, line)
        return findings


# ═══════════════════════════════════════════════════════════════════════════════
# ADAPTER 6: RAMPARTS
# MCP-Security-Scanner — spezialisiert auf MCP-Server-Schwachstellen
# ═══════════════════════════════════════════════════════════════════════════════

class RampartsAdapter:
    """
    Ramparts — MCP Security Scanner
    Repo: https://github.com/getjavelin/ramparts
    Install: pip install ramparts

    Scannt MCP-Server auf:
    - Tool-Poisoning (Prompt-Injection in Tool-Descriptions)
    - Gefährliche Tool-Typen (shell, exec, filesystem)
    - Command Injection via YARA-Regeln
    - Cross-Domain-Tool-Spans (Context-Hijacking)
    - LLM-gestützte Analyse der Tool-Sicherheit
    """

    # Gefährliche Tool-Name-Pattern (Regex)
    DANGEROUS_TOOL_PATTERNS = [
        r"(execute|exec|run|shell|cmd|command|bash|sh|powershell)",
        r"(delete|remove|rm|unlink|truncate).*file",
        r"(write|overwrite|create).*file",
        r"(eval|dynamic.*code|inject)",
        r"(sudo|privilege|root|admin)",
    ]

    # Prompt-Injection-Patterns in Tool-Descriptions
    INJECTION_PATTERNS = [
        r"ignore\s+(previous|all|above)\s+instructions",
        r"do\s+not\s+follow\s+(safety|security|policy)",
        r"you\s+are\s+now\s+in\s+(dev|test|admin|sudo)\s+mode",
        r"reveal\s+(secret|password|credential|token|key)",
        r"exfiltrate|send.*to.*http|post.*to.*server",
        r"<\!--.*instruction.*-->",
        r"\[system\]|\[admin\]|\[override\]",
    ]

    def run(self, tenant_id: str, mcp_urls: list[str],
            use_llm: bool = False, log_fn=None) -> list[ToolFinding]:
        """
        Args:
            mcp_urls: Liste von MCP-Server-URLs
            use_llm: LLM-gestützte Analyse (braucht API-Key)
            log_fn: Optionale Log-Funktion (tool, msg, level)
        """
        _binary_path = tool_path("ramparts")
        _avail = _binary_path is not None
        if log_fn:
            log_fn("ramparts", f"binary {'verfügbar' if _avail else 'NICHT gefunden — eigene MCP-Analyse'} | {len(mcp_urls)} URLs", "info" if _avail else "warn")

        all_findings = []

        for url in mcp_urls:
            # Primär: ramparts CLI wenn installiert
            if _avail:
                all_findings += self._run_ramparts_cli(tenant_id, url, use_llm, _binary_path)
            else:
                # Fallback: Eigene MCP-Security-Analyse
                all_findings += self._run_own_analysis(tenant_id, url)

        if log_fn:
            log_fn("ramparts", f"{len(all_findings)} MCP-Findings aus {len(mcp_urls)} URLs", "info" if not all_findings else "warn")

        return all_findings

    def _run_ramparts_cli(self, tenant_id: str, url: str,
                           use_llm: bool, binary_path: str = "ramparts") -> list[ToolFinding]:
        """Ramparts CLI ausführen"""
        cmd = [binary_path, "scan", url, "--json"]
        if use_llm:
            cmd += ["--llm-analysis"]

        rc, stdout, stderr = _run(cmd, timeout=120)
        return self._parse_ramparts(tenant_id, url, stdout, stderr, rc)

    def _parse_ramparts(self, tenant_id: str, url: str,
                         stdout: str, stderr: str, rc: int) -> list[ToolFinding]:
        """Parsed Ramparts-JSON-Output"""
        findings = []
        try:
            data = json.loads(stdout)
            for issue in data.get("findings", []):
                sev = issue.get("severity", "medium").upper()
                findings.append(ToolFinding(
                    tenant_id=tenant_id, tool="ramparts",
                    category="mcp_exposure",
                    severity=sev,
                    title=issue.get("title", "MCP Security Issue"),
                    description=issue.get("description", ""),
                    affected_asset=url,
                    remediation=issue.get("remediation", ""),
                    raw_data=issue,
                ))
        except (json.JSONDecodeError, KeyError):
            pass
        return findings

    def _run_own_analysis(self, tenant_id: str, url: str) -> list[ToolFinding]:
        """
        Eigene MCP-Sicherheitsanalyse wenn ramparts nicht installiert.
        Prüft: Tool-Liste, gefährliche Tools, Prompt-Injection, Authentifizierung
        """
        import urllib.request
        import ssl

        findings = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        def mcp_request(method: str, params: dict = None) -> dict:
            payload = json.dumps({
                "jsonrpc": "2.0", "id": 1,
                "method": method,
                "params": params or {}
            }).encode()
            req = urllib.request.Request(
                url, data=payload,
                headers={"Content-Type": "application/json",
                         "User-Agent": "EASM-Ramparts/1.0"},
                method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                    return json.loads(resp.read().decode(errors="ignore"))
            except Exception:
                return {}

        # 1. Initialize-Check (Auth?)
        init_resp = mcp_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "scanner", "version": "1.0"}
        })

        if not init_resp.get("result"):
            return findings  # Server antwortet nicht oder hat Auth

        server_info = init_resp.get("result", {}).get("serverInfo", {})

        # 2. Tools auflisten
        tools_resp = mcp_request("tools/list")
        tools = tools_resp.get("result", {}).get("tools", []) or []

        if not tools:
            return findings

        # 3. Jedes Tool analysieren
        dangerous_tools = []
        injection_tools = []

        for tool in tools:
            tool_name = tool.get("name", "")
            tool_desc = tool.get("description", "")
            tool_schema = json.dumps(tool.get("inputSchema", {}))

            # Gefährliche Tool-Namen
            for pattern in self.DANGEROUS_TOOL_PATTERNS:
                if re.search(pattern, tool_name + " " + tool_desc, re.IGNORECASE):
                    dangerous_tools.append({
                        "name": tool_name,
                        "description": tool_desc[:200],
                        "pattern": pattern
                    })
                    break

            # Prompt-Injection in Beschreibungen
            for pattern in self.INJECTION_PATTERNS:
                if re.search(pattern, tool_desc, re.IGNORECASE):
                    injection_tools.append({
                        "name": tool_name,
                        "suspicious_text": tool_desc[:200],
                        "pattern": pattern
                    })
                    break

            # Datenbank-Connection-Strings in Schema
            conn_pattern = r"(postgresql|mysql|mongodb|redis|mssql)://[^\s\"]+"
            if re.search(conn_pattern, tool_schema, re.IGNORECASE):
                findings.append(ToolFinding(
                    tenant_id=tenant_id, tool="ramparts",
                    category="mcp_exposure",
                    severity="CRITICAL",
                    title=f"DB-Connection-String in MCP-Tool exponiert: {tool_name}",
                    description=f"Tool '{tool_name}' enthält Datenbank-Connection-Strings im Schema.",
                    affected_asset=url,
                    remediation="Connection-Strings aus Tool-Schema entfernen, Vault nutzen",
                    raw_data={"tool": tool},
                ))

        # 4. Gefährliche Tools Finding
        if dangerous_tools:
            findings.append(ToolFinding(
                tenant_id=tenant_id, tool="ramparts",
                category="mcp_exposure",
                severity="CRITICAL",
                title=f"{len(dangerous_tools)} gefährliche Tool-Typen in MCP-Server: {url}",
                description=(
                    f"Der MCP-Server exponiert Tools die shell/filesystem/code-execution ermöglichen:\n"
                    + "\n".join(f"- {t['name']}: {t['description'][:80]}"
                               for t in dangerous_tools[:5])
                ),
                affected_asset=url,
                remediation=(
                    "Nur notwendige Tools exponieren. Shell/Exec-Tools nicht über Netzwerk zugänglich machen. "
                    "Least-Privilege: MCP-Server nur mit minimalen Rechten betreiben."
                ),
                raw_data={"dangerous_tools": dangerous_tools},
            ))

        # 5. Prompt-Injection Finding
        if injection_tools:
            findings.append(ToolFinding(
                tenant_id=tenant_id, tool="ramparts",
                category="mcp_exposure",
                severity="HIGH",
                title=f"Prompt-Injection in MCP-Tool-Descriptions: {url}",
                description=(
                    f"Tool-Descriptions enthalten potenzielle Prompt-Injection-Anweisungen:\n"
                    + "\n".join(f"- {t['name']}: {t['suspicious_text'][:80]}"
                               for t in injection_tools[:3])
                ),
                affected_asset=url,
                remediation="Tool-Descriptions auf Injection-Anweisungen prüfen. Tool-Poisoning Supply-Chain-Check.",
                raw_data={"injection_tools": injection_tools},
            ))

        # 6. Vollständiges Tool-Inventar als INFO-Finding
        if tools:
            findings.append(ToolFinding(
                tenant_id=tenant_id, tool="ramparts",
                category="mcp_exposure",
                severity="HIGH",
                title=f"MCP-Server exponiert {len(tools)} Tools ohne Auth: {url}",
                description=(
                    f"Server: {server_info.get('name', '?')} v{server_info.get('version', '?')}\n"
                    f"Tools: {', '.join(t.get('name','?') for t in tools[:10])}"
                    f"{'...' if len(tools) > 10 else ''}"
                ),
                affected_asset=url,
                remediation="Bearer-Token-Authentifizierung aktivieren, MCP-Server nicht auf 0.0.0.0 binden",
                raw_data={"tools": tools[:20], "server_info": server_info},
            ))

        return findings


# ═══════════════════════════════════════════════════════════════════════════════
# ADAPTER 7: SPYONWEB
# Reverse-OSINT: Analytics-IDs / AdSense / IP → verbundene Domains
# Einzigartiger Mehrwert: findet Shadow-Domains über gemeinsame Tracking-IDs
# API: https://api.spyonweb.com/v1/
# Kosten: ab $29/Monat für produktive API-Nutzung
# ═══════════════════════════════════════════════════════════════════════════════

class SpyOnWebAdapter:
    """
    SpyOnWeb — Reverse-OSINT via Analytics-IDs, AdSense-Codes und IP-Sharing.

    Findet Domains die:
    - dieselbe Google Analytics ID teilen  (UA-XXXXX-X / G-XXXXXXXXXX)
    - denselben Google AdSense Code teilen (pub-XXXXXXXXXX)
    - auf derselben IP-Adresse gehostet sind

    MSSP-Mehrwert:
    - Kunden wissen oft nicht, dass Schwester-Unternehmen dieselbe
      Analytics-ID nutzen → Shadow-Domains ohne Asset-Inventar
    - Shared-Hosting: Risiko durch Nachbarn auf derselben IP
    - Typosquatting: Angreifer-Domains die dieselbe ID wie Kunden nutzen
    """

    BASE = "https://api.spyonweb.com/v1"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def run(self, tenant_id: str, domain: str,
            ips: list[str] = None) -> list[ToolFinding]:
        """
        Vollständige SpyOnWeb-Analyse für eine Domain.
        1. Domain-Summary → extrahiert Analytics-IDs + AdSense-Codes + IP
        2. Reverse-Lookup jeder ID → verbundene Domains
        3. IP-Sharing-Check → andere Domains auf derselben IP
        """
        findings = []

        # 1. Domain-Summary abrufen
        summary = self._get("/summary/{domain}".format(domain=domain))
        if not summary:
            return findings

        result = summary.get("result", {}).get(domain, {})

        # Analytics-IDs extrahieren
        ua_ids = list(result.get("analytics", {}).keys())
        adsense_ids = list(result.get("adsense", {}).keys())
        domain_ips = list(result.get("ip", {}).keys())

        # 2. Für jede Analytics-ID alle verbundenen Domains finden
        for ua_id in ua_ids[:5]:  # max 5 IDs pro Domain
            linked = self._reverse_lookup("analytics", ua_id, domain)
            if linked:
                findings.extend(self._make_findings(
                    tenant_id, domain, ua_id, linked,
                    "google_analytics", "Analytics-ID"
                ))

        # 3. AdSense-IDs
        for pub_id in adsense_ids[:3]:
            linked = self._reverse_lookup("adsense", pub_id, domain)
            if linked:
                findings.extend(self._make_findings(
                    tenant_id, domain, pub_id, linked,
                    "adsense", "AdSense-Publisher-ID"
                ))

        # 4. IP-Sharing (eigene IPs + aus Port-Scan übergebene)
        all_ips = list(set(domain_ips + (ips or [])))
        for ip in all_ips[:5]:
            linked = self._reverse_lookup("ip", ip, domain)
            if linked:
                findings.append(ToolFinding(
                    tenant_id=tenant_id,
                    tool="spyonweb",
                    category="shared_hosting",
                    severity="LOW",
                    title=f"Shared-Hosting: {len(linked)} Domains auf {ip}",
                    description=(
                        f"Auf der IP {ip} von {domain} hosten {len(linked)} weitere Domains. "
                        f"Kompromittierte Nachbar-Domain kann Angriffe auf geteilte Infrastruktur ermöglichen.\n"
                        f"Domains: {', '.join(linked[:8])}"
                        f"{'...' if len(linked) > 8 else ''}"
                    ),
                    affected_asset=ip,
                    remediation=(
                        "Wenn möglich: dedizierte IP statt Shared-Hosting für kritische Services. "
                        "Nachbar-Domains auf Ruf und Sicherheitsstatus prüfen."
                    ),
                    raw_data={"ip": ip, "shared_domains": linked[:30]},
                ))

        return findings

    def _get(self, path: str) -> dict:
        """Führt einen SpyOnWeb-API-Request aus."""
        import urllib.request, urllib.error
        url = f"{self.BASE}{path}?access_token={self.api_key}"
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "EASM-MSSP/1.0"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 402:
                return {"error": "api_quota_exceeded"}
            if e.code == 404:
                return {}
            return {}
        except Exception:
            return {}

    def _reverse_lookup(self, kind: str, id_: str,
                         origin_domain: str) -> list[str]:
        """
        Reverse-Lookup für Analytics-ID / AdSense-ID / IP.
        Returns: Liste verbundener Domains (ohne origin_domain selbst)
        """
        data = self._get(f"/{kind}/{id_}")
        if not data:
            return []
        result = data.get("result", {}).get(id_, {})
        items = result.get("items", {})
        if isinstance(items, dict):
            domains = [d for d in items if d != origin_domain]
        elif isinstance(items, list):
            domains = [d for d in items if d != origin_domain]
        else:
            domains = []
        return domains

    def _make_findings(self, tenant_id: str, origin: str,
                        tracking_id: str, linked_domains: list[str],
                        id_type: str, id_label: str) -> list[ToolFinding]:
        """Erzeugt Findings für verbundene Domains via Tracking-ID."""
        findings = []
        if not linked_domains:
            return findings

        # Klassifikation der verbundenen Domains
        suspicious = [
            d for d in linked_domains
            if any(kw in d.lower() for kw in
                   ["phish", "fake", "scam", "malware", "clone", "login-"])
        ]
        external = [
            d for d in linked_domains
            if not d.endswith(f".{origin}") and d != origin
        ]

        severity = "HIGH" if suspicious else ("MEDIUM" if external else "LOW")

        findings.append(ToolFinding(
            tenant_id=tenant_id,
            tool="spyonweb",
            category="linked_domains",
            severity=severity,
            title=(
                f"SpyOnWeb: {len(linked_domains)} Domains teilen {id_label} "
                f"'{tracking_id}' mit {origin}"
            ),
            description=(
                f"Die {id_label} '{tracking_id}' wird auch von "
                f"{len(linked_domains)} anderen Domains genutzt.\n"
                f"Verbundene Domains: {', '.join(linked_domains[:10])}"
                f"{'...' if len(linked_domains) > 10 else ''}\n"
                + (f"\n⚠ Verdächtige Domains: {', '.join(suspicious)}"
                   if suspicious else "")
            ),
            affected_asset=origin,
            remediation=(
                "Verbundene Domains prüfen ob sie zur eigenen Organisation gehören "
                "oder ob Tracking-IDs in fremden (ggf. bösartigen) Domains missbraucht werden. "
                "Nicht mehr benötigte Tracking-IDs aus dem Code entfernen."
            ),
            raw_data={
                "tracking_id": tracking_id,
                "id_type": id_type,
                "linked_domains": linked_domains[:50],
                "suspicious_count": len(suspicious),
            },
        ))

        # Separates CRITICAL-Finding für verdächtige Domains
        if suspicious:
            findings.append(ToolFinding(
                tenant_id=tenant_id,
                tool="spyonweb",
                category="typosquatting",
                severity="CRITICAL",
                title=f"Analytics-ID von verdächtigen Domains missbraucht: {origin}",
                description=(
                    f"Die Analytics-ID '{tracking_id}' von {origin} wird in "
                    f"verdächtig benannten Domains gefunden:\n"
                    f"{chr(10).join(suspicious[:5])}\n"
                    f"Dies könnte auf Phishing oder Brand-Abuse hinweisen."
                ),
                affected_asset=origin,
                remediation=(
                    "Sofortmaßnahme: Tracking-ID rotieren. "
                    "Abuse-Report an Google. "
                    "Verdächtige Domains bei Registrar melden."
                ),
                raw_data={"suspicious_domains": suspicious},
            ))

        return findings


# ═══════════════════════════════════════════════════════════════════════════════
# ADAPTER 8: IP-REPUTATION (GreyNoise + AbuseIPDB)
# Ersatz/Ergänzung zu HoneyDB — MSSP-lizenziert, günstiger, breiter
#
# GreyNoise:  Unterscheidet "Mass-Internet-Scanner" von gezielten Angriffen
# AbuseIPDB:  Community-gemeldete Bad-IPs mit Kategorie + Confidence-Score
#
# WARUM NICHT HONEYDB:
#   HoneyDB Community-Tier = nicht-kommerziell only
#   Für MSSP-SaaS: OEM-Lizenz erforderlich (Preis auf Anfrage)
#   GreyNoise + AbuseIPDB haben explizite MSSP/kommerzielle Pläne
# ═══════════════════════════════════════════════════════════════════════════════

class IPReputationAdapter:
    """
    IP-Reputation-Check via GreyNoise + AbuseIPDB.

    GreyNoise API: https://api.greynoise.io/v3/community/{ip}
    - Community-Plan: 10k Requests/Monat kostenlos
    - Liefert: classification (malicious/benign/unknown), name, tags

    AbuseIPDB API: https://api.abuseipdb.com/api/v2/check
    - Free: 1000 req/Tag · Webmaster: $20/Monat · Premium: $50/Monat
    - Liefert: abuseConfidenceScore, totalReports, categories, lastReportedAt
    """

    # AbuseIPDB Kategorie-Mapping
    ABUSE_CATEGORIES = {
        1: "DNS-Kompromittierung", 2: "DNS-Amplification",
        3: "DoS-Angriff", 4: "DDoS-Angriff",
        5: "FTP-Brute-Force", 6: "Ping of Death",
        7: "Phishing", 8: "Fraud VoIP",
        9: "Open Proxy", 10: "Web-Spam",
        11: "E-Mail-Spam", 12: "Blog-Spam",
        13: "VPN-IP", 14: "Port-Scan",
        15: "Hacking", 16: "SQL-Injection",
        17: "Spoofing", 18: "Brute-Force",
        19: "Bad Web Bot", 20: "Exploited Host",
        21: "Web App Angriff", 22: "SSH-Brute-Force",
        23: "IoT-Targeted",
    }

    def __init__(self, greynoise_key: str = "", abuseipdb_key: str = ""):
        self.greynoise_key = greynoise_key
        self.abuseipdb_key = abuseipdb_key

    def check_ips(self, tenant_id: str,
                  ips: list[str]) -> list[ToolFinding]:
        """Prüft eine Liste von IPs gegen GreyNoise und AbuseIPDB."""
        findings = []
        for ip in ips:
            if self.greynoise_key:
                findings.extend(self._greynoise_check(tenant_id, ip))
            if self.abuseipdb_key:
                findings.extend(self._abuseipdb_check(tenant_id, ip))
        return findings

    def _greynoise_check(self, tenant_id: str, ip: str) -> list[ToolFinding]:
        """GreyNoise Community API — klassifiziert IP als malicious/benign/unknown."""
        import urllib.request, urllib.error
        url = f"https://api.greynoise.io/v3/community/{ip}"
        try:
            req = urllib.request.Request(
                url,
                headers={"key": self.greynoise_key,
                         "User-Agent": "EASM-MSSP/1.0"}
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return []  # IP unbekannt bei GreyNoise
            return []
        except Exception:
            return []

        classification = data.get("classification", "unknown")
        noise = data.get("noise", False)
        riot = data.get("riot", False)
        name = data.get("name", "")
        tags = data.get("tags", [])
        message = data.get("message", "")

        # RIOT = bekannte legitime Services (Google, Cloudflare etc.) — kein Finding
        if riot:
            return []

        # Nur bei malicious oder bekannten Scanner-IPs Finding erzeugen
        if classification == "malicious":
            return [ToolFinding(
                tenant_id=tenant_id,
                tool="greynoise",
                category="ip_reputation",
                severity="HIGH",
                title=f"GreyNoise: Schadhafte IP aktiv: {ip}",
                description=(
                    f"IP {ip} ist laut GreyNoise als 'malicious' klassifiziert.\n"
                    f"Name: {name or 'unbekannt'}\n"
                    f"Tags: {', '.join(tags) if tags else 'keine'}\n"
                    f"Wenn diese IP Verbindungen zu Kunden-Assets aufbaut, "
                    f"ist von einem gezielten Angriff auszugehen."
                ),
                affected_asset=ip,
                remediation=(
                    "IP sofort in Firewall blockieren. "
                    "Logs auf Verbindungen von/zu dieser IP prüfen. "
                    "Incident-Response einleiten falls Verbindungen gefunden."
                ),
                raw_data=data,
            )]
        elif noise and not riot:
            # Mass-Internet-Scanner — weniger kritisch aber relevant
            return [ToolFinding(
                tenant_id=tenant_id,
                tool="greynoise",
                category="ip_reputation",
                severity="LOW",
                title=f"GreyNoise: Internet-Mass-Scanner: {ip}",
                description=(
                    f"IP {ip} ist ein bekannter Internet-Mass-Scanner.\n"
                    f"Name: {name or 'unbekannt'} | Tags: {', '.join(tags[:3]) if tags else '—'}\n"
                    f"Massenweit aktive Scanner-IPs scannen automatisch alle IPs — "
                    f"kein gezielter Angriff, aber erhöhte Exponierung."
                ),
                affected_asset=ip,
                remediation="Rate-Limiting und Firewall-Regeln prüfen.",
                raw_data=data,
            )]
        return []

    def _abuseipdb_check(self, tenant_id: str, ip: str) -> list[ToolFinding]:
        """AbuseIPDB API — Community-gemeldete Missbrauchsmeldungen."""
        import urllib.request, urllib.error, urllib.parse
        url = (f"https://api.abuseipdb.com/api/v2/check"
               f"?ipAddress={ip}&maxAgeInDays=90&verbose")
        try:
            req = urllib.request.Request(
                url,
                headers={"Key": self.abuseipdb_key,
                         "Accept": "application/json",
                         "User-Agent": "EASM-MSSP/1.0"}
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())
        except Exception:
            return []

        d = data.get("data", {})
        score = d.get("abuseConfidenceScore", 0)
        reports = d.get("totalReports", 0)
        categories = d.get("categories", [])
        last_reported = d.get("lastReportedAt", "")
        isp = d.get("isp", "")
        country = d.get("countryCode", "")
        is_tor = d.get("isTor", False)
        is_public = d.get("isPublic", True)

        if score < 10 and not is_tor:
            return []  # Unauffällig

        # Severity aus Confidence-Score
        if score >= 80:
            severity = "CRITICAL"
        elif score >= 50:
            severity = "HIGH"
        elif score >= 25:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        cat_labels = [
            self.ABUSE_CATEGORIES.get(c, f"Kategorie {c}")
            for c in categories[:5]
        ]

        return [ToolFinding(
            tenant_id=tenant_id,
            tool="abuseipdb",
            category="ip_reputation",
            severity=severity,
            title=(
                f"AbuseIPDB: IP mit Confidence {score}% gemeldet: {ip}"
                + (" [TOR-Exit-Node]" if is_tor else "")
            ),
            description=(
                f"IP {ip} ({isp}, {country}) wurde mit {score}% Confidence "
                f"als missbräuchlich gemeldet.\n"
                f"Meldungen (90 Tage): {reports}\n"
                f"Kategorien: {', '.join(cat_labels) if cat_labels else '—'}\n"
                f"Zuletzt gemeldet: {last_reported[:10] if last_reported else '—'}\n"
                + ("⚠ Tor-Exit-Node: verschleiert Angreifer-Herkunft\n"
                   if is_tor else "")
            ),
            affected_asset=ip,
            remediation=(
                "IP sofort in Firewall-Blocklist aufnehmen. "
                "Logs rückwirkend auf Verbindungen prüfen. "
                "Bei Score >80: Incident-Response einleiten."
            ),
            raw_data=d,
        )]


# ═══════════════════════════════════════════════════════════════════════════════
# ADAPTER 9: THREAT INTELLIGENCE (AlienVault OTX + MISP)
# Alternative zu CISA AIS — weniger bürokratisch, für DE/EU-Kunden relevanter
#
# WARUM NICHT CISA AIS DIREKT:
#   - PKI-Zertifikat von Federal Bridge CA: $500-2000, US-only
#   - Interconnection Agreement + statische IPs erforderlich
#   - TAXII 1.1 Legacy-Protokoll, schlechte Python-Unterstützung
#   - Feed sehr US-lastig, für deutsche KMU-Kunden begrenzt relevant
#   - Onboarding: 4-8 Wochen
#
# STATTDESSEN:
#   AlienVault OTX: kostenlos, global, STIX/TAXII 2.1, 1 Tag Integration
#   MISP + BSI-Feed: deutschsprachig, NIS2-relevant, OpenCTI-kompatibel
# ═══════════════════════════════════════════════════════════════════════════════

class ThreatIntelAdapter:
    """
    Threat Intelligence via AlienVault OTX und/oder MISP.

    AlienVault OTX:
    - URL: https://otx.alienvault.com/api/v1/
    - Kostenlos, API-Key nach Registrierung
    - Liefert: IOC-Pulses nach Domain/IP/Hash

    MISP:
    - Self-hosted oder Community-Instanz
    - BSI-Feed: https://www.bsi.bund.de/MISP
    - CIRCL (Luxemburg): https://www.circl.lu/services/misp-feeds/
    - AIS-Daten fließen hier automatisch ein via OpenCTI-Connector
    """

    OTX_BASE = "https://otx.alienvault.com/api/v1"

    def __init__(self, otx_api_key: str = "", misp_url: str = "",
                 misp_key: str = ""):
        self.otx_key = otx_api_key
        self.misp_url = misp_url.rstrip("/")
        self.misp_key = misp_key

    def check_domain(self, tenant_id: str,
                     domain: str) -> list[ToolFinding]:
        """Prüft eine Domain gegen OTX + MISP auf bekannte IOC-Treffer."""
        findings = []
        if self.otx_key:
            findings.extend(self._otx_domain(tenant_id, domain))
        if self.misp_url and self.misp_key:
            findings.extend(self._misp_search(tenant_id, domain, "domain"))
        return findings

    def check_ip(self, tenant_id: str, ip: str) -> list[ToolFinding]:
        """Prüft eine IP gegen OTX + MISP."""
        findings = []
        if self.otx_key:
            findings.extend(self._otx_ip(tenant_id, ip))
        if self.misp_url and self.misp_key:
            findings.extend(self._misp_search(tenant_id, ip, "ip-src"))
        return findings

    def check_hash(self, tenant_id: str, hash_: str,
                   context: str = "") -> list[ToolFinding]:
        """Prüft einen Datei-Hash gegen OTX (Malware-Check)."""
        if not self.otx_key:
            return []
        return self._otx_hash(tenant_id, hash_, context)

    # ── OTX Implementierungen ──────────────────────────────────────────────────

    def _otx_request(self, path: str) -> dict:
        import urllib.request
        url = f"{self.OTX_BASE}{path}"
        try:
            req = urllib.request.Request(
                url, headers={"X-OTX-API-KEY": self.otx_key,
                               "User-Agent": "EASM-MSSP/1.0"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except Exception:
            return {}

    def _otx_domain(self, tenant_id: str,
                    domain: str) -> list[ToolFinding]:
        """OTX Domain-Lookup: Pulses, Malware-Assoziationen, Geolocation."""
        data = self._otx_request(f"/indicators/domain/{domain}/general")
        if not data:
            return []

        pulse_count = data.get("pulse_info", {}).get("count", 0)
        pulses = data.get("pulse_info", {}).get("pulses", [])
        reputation = data.get("reputation", 0)
        validation = data.get("validation", [])

        if pulse_count == 0 and reputation >= 0:
            return []  # Keine bekannten Threat-Assoziationen

        # Pulse-Details extrahieren
        pulse_names = [p.get("name", "")[:60] for p in pulses[:5]]
        tags = list(set(
            tag for p in pulses for tag in p.get("tags", [])
        ))[:10]
        adversaries = list(set(
            p.get("adversary", "") for p in pulses
            if p.get("adversary")
        ))[:3]
        malware_families = list(set(
            m.get("display_name", "")
            for p in pulses
            for m in p.get("malware_families", [])
        ))[:5]

        severity = (
            "CRITICAL" if (adversaries or malware_families or pulse_count > 10)
            else "HIGH" if pulse_count > 3
            else "MEDIUM"
        )

        return [ToolFinding(
            tenant_id=tenant_id,
            tool="alienvault_otx",
            category="threat_intel",
            severity=severity,
            title=(
                f"OTX: {domain} in {pulse_count} Threat-Intelligence-Pulses"
            ),
            description=(
                f"Domain {domain} erscheint in {pulse_count} OTX-Threat-Pulses.\n"
                + (f"Bedrohungsakteure: {', '.join(adversaries)}\n"
                   if adversaries else "")
                + (f"Malware-Familien: {', '.join(malware_families)}\n"
                   if malware_families else "")
                + (f"Tags: {', '.join(tags[:5])}\n" if tags else "")
                + (f"Pulses: {'; '.join(pulse_names)}"
                   if pulse_names else "")
            ),
            affected_asset=domain,
            remediation=(
                "Domain in Threat-Intelligence-Plattform zur Vertiefung analysieren. "
                "Prüfen ob Kunden-Domain selbst Ziel oder Quelle von Aktivität ist. "
                "Bei Malware-Assoziation: forensische Untersuchung einleiten."
            ),
            raw_data={
                "pulse_count": pulse_count,
                "adversaries": adversaries,
                "malware_families": malware_families,
                "tags": tags,
            },
        )]

    def _otx_ip(self, tenant_id: str, ip: str) -> list[ToolFinding]:
        """OTX IP-Lookup: Bekannte bösartige IPs."""
        data = self._otx_request(f"/indicators/IPv4/{ip}/general")
        if not data:
            return []

        pulse_count = data.get("pulse_info", {}).get("count", 0)
        pulses = data.get("pulse_info", {}).get("pulses", [])
        reputation = data.get("reputation", 0)
        asn = data.get("asn", "")
        country = data.get("country_name", "")

        if pulse_count == 0:
            return []

        adversaries = list(set(
            p.get("adversary", "") for p in pulses if p.get("adversary")
        ))
        severity = ("CRITICAL" if adversaries or pulse_count > 5
                    else "HIGH" if pulse_count > 2 else "MEDIUM")

        return [ToolFinding(
            tenant_id=tenant_id,
            tool="alienvault_otx",
            category="threat_intel",
            severity=severity,
            title=f"OTX: IP {ip} in {pulse_count} Threat-Pulses ({country})",
            description=(
                f"IP {ip} ({asn}, {country}) erscheint in {pulse_count} OTX-Threat-Pulses.\n"
                + (f"Bedrohungsakteure: {', '.join(adversaries)}\n"
                   if adversaries else "")
            ),
            affected_asset=ip,
            remediation=(
                "IP in Firewall-Blocklist aufnehmen. "
                "Ausgehende Verbindungen zu dieser IP sofort prüfen."
            ),
            raw_data={"pulse_count": pulse_count, "asn": asn},
        )]

    def _otx_hash(self, tenant_id: str, hash_: str,
                  context: str) -> list[ToolFinding]:
        """OTX Datei-Hash-Lookup: Malware-Erkennung."""
        # Erkennt MD5, SHA1, SHA256 automatisch
        hash_type = (
            "file" if len(hash_) in (32, 40, 64) else "file"
        )
        data = self._otx_request(
            f"/indicators/{hash_type}/{hash_}/general"
        )
        if not data:
            return []

        pulse_count = data.get("pulse_info", {}).get("count", 0)
        if pulse_count == 0:
            return []

        malware = data.get("malware_families", [])

        return [ToolFinding(
            tenant_id=tenant_id,
            tool="alienvault_otx",
            category="malware",
            severity="CRITICAL",
            title=f"OTX: Bekannte Malware-Hash: {hash_[:16]}...",
            description=(
                f"Hash {hash_[:20]}... ist in {pulse_count} OTX-Pulses bekannt.\n"
                f"Kontext: {context}\n"
                + (f"Malware: {', '.join(m.get('display_name','') for m in malware[:3])}"
                   if malware else "")
            ),
            affected_asset=context or hash_[:16],
            remediation=(
                "Betroffene Datei sofort isolieren und analysieren. "
                "Endpoint-Scan einleiten. Incident-Response-Prozess starten."
            ),
            raw_data={"hash": hash_, "pulse_count": pulse_count},
        )]

    # ── MISP Implementierung ───────────────────────────────────────────────────

    def _misp_search(self, tenant_id: str, value: str,
                     attr_type: str) -> list[ToolFinding]:
        """
        MISP REST API Suche nach IOC.
        Erfordert self-hosted MISP oder Community-Zugang (BSI, CIRCL).
        """
        import urllib.request
        if not self.misp_url or not self.misp_key:
            return []

        url = f"{self.misp_url}/attributes/restSearch"
        payload = json.dumps({
            "returnFormat": "json",
            "type": attr_type,
            "value": value,
            "enforceWarninglist": True,
            "limit": 10,
        }).encode()

        try:
            req = urllib.request.Request(
                url, data=payload,
                headers={
                    "Authorization": self.misp_key,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "EASM-MSSP/1.0",
                },
                method="POST"
            )
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                data = json.loads(resp.read().decode())
        except Exception:
            return []

        attributes = data.get("response", {}).get("Attribute", [])
        if not attributes:
            return []

        # Eindeutige Events zusammenfassen
        events = {}
        for attr in attributes:
            eid = attr.get("event_id", "?")
            if eid not in events:
                events[eid] = {
                    "info": attr.get("Event", {}).get("info", f"Event {eid}"),
                    "tags": [
                        t.get("name", "") for t in
                        attr.get("Event", {}).get("Tag", [])
                    ],
                    "date": attr.get("Event", {}).get("date", ""),
                    "tlp": next(
                        (t.get("name","") for t in
                         attr.get("Event",{}).get("Tag",[])
                         if "tlp" in t.get("name","").lower()),
                        "TLP:WHITE"
                    ),
                }

        severity = "HIGH" if len(events) > 2 else "MEDIUM"

        return [ToolFinding(
            tenant_id=tenant_id,
            tool="misp",
            category="threat_intel",
            severity=severity,
            title=f"MISP: '{value}' in {len(events)} Threat-Events",
            description=(
                f"Der Indikator '{value}' ({attr_type}) ist in {len(events)} "
                f"MISP-Threat-Events gelistet:\n"
                + "\n".join(
                    f"- {e['info'][:80]} ({e['date']}) [{e['tlp']}]"
                    for e in list(events.values())[:5]
                )
            ),
            affected_asset=value,
            remediation=(
                "MISP-Events für vollständige Kontext-Information prüfen. "
                "TLP-Level beachten für Weitergabe. "
                "Defensive Measures aus Events ableiten."
            ),
            raw_data={"events": list(events.values()), "attr_count": len(attributes)},
        )]
