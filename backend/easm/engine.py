"""
EASM Engine - External Attack Surface Management
für MSSP Palo Alto Health Check Service

Arbeitet mit:
- Shodan API (kostenloser Key: ~100 Abfragen/Monat)
- Censys Free Tier (250 Abfragen/Monat)
- DNS-basierte Techniken (kein API-Key nötig)
- CVE/NVD API (kostenlos)
- CISA KEV Feed (kostenlos)
- HaveIBeenPwned API (kostenlos für Domain-Check)
- Passive Recon: Amass-ähnliche DNS-Enumeration
"""

import json
import socket
import ssl
import subprocess
import ipaddress
import re
import hashlib
import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional
import urllib.request
import urllib.parse
import dns.resolver
import dns.zone
import dns.query

# ─── Datenmodelle ───────────────────────────────────────────────────

@dataclass
class ExposedAsset:
    ip: str
    hostname: str = ""
    port: int = 0
    service: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""
    ssl_cert: dict = field(default_factory=dict)
    vulns: list = field(default_factory=list)
    risk_score: int = 0
    risk_reason: str = ""
    source: str = ""  # shodan | censys | dns | active_scan

@dataclass
class SubdomainResult:
    subdomain: str
    ip: str = ""
    cname: str = ""
    exposed_ports: list = field(default_factory=list)
    risk: str = "unknown"
    reason: str = ""

@dataclass
class CredentialLeak:
    source: str
    breach_date: str
    compromised_count: int
    data_classes: list = field(default_factory=list)

@dataclass
class CVEFinding:
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    epss_score: float = 0.0
    cisa_kev: bool = False
    affected_version: str = ""
    fix_version: str = ""

@dataclass
class EASMReport:
    tenant_id: str
    domain: str
    ip_ranges: list
    scan_timestamp: str
    exposed_assets: list = field(default_factory=list)
    subdomains: list = field(default_factory=list)
    credential_leaks: list = field(default_factory=list)
    cve_findings: list = field(default_factory=list)
    typosquat_domains: list = field(default_factory=list)
    risk_summary: dict = field(default_factory=dict)
    score: int = 100  # startet bei 100, Abzüge pro Finding


# ─── DNS Subdomain Enumeration ────────────────────────────────────────

class DNSEnumerator:
    """Passive + aktive DNS-Aufklärung ohne Shodan/Censys"""

    # Häufigste Subdomains (Top 100 Wordlist)
    COMMON_SUBDOMAINS = [
        "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
        "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test",
        "portal", "ns", "ww1", "host", "support", "dev", "web", "bbs",
        "dns", "mx", "email", "cloud", "1", "app", "forum", "owa",
        "www2", "admin", "stage", "api", "exchange", "news", "cdn",
        "static", "en", "images", "img", "video", "files", "download",
        "git", "jenkins", "jira", "confluence", "gitlab", "grafana",
        "prometheus", "kibana", "elastic", "mongo", "redis", "mysql",
        "postgres", "phpmyadmin", "cpanel", "whm", "plesk", "webdisk",
        "autodiscover", "lyncdiscover", "sip", "voip", "asterisk",
        "backup", "nas", "storage", "share", "sharepoint", "office",
        "remote2", "citrix", "rdp", "ssh", "telnet", "printer", "scan",
        "camera", "iot", "scada", "plc", "hmi", "ics", "modbus",
        "staging", "qa", "uat", "preprod", "old", "legacy", "archive"
    ]

    # High-Risk Subdomains (exponierte Management-Interfaces)
    HIGH_RISK_SUBDOMAINS = {
        "vpn", "remote", "rdp", "ssh", "admin", "portal", "owa",
        "exchange", "webmail", "citrix", "anyconnect", "sslvpn",
        "globalprotect", "phpmyadmin", "cpanel", "whm", "plesk",
        "jenkins", "gitlab", "jira", "confluence", "grafana",
        "kibana", "elastic", "mongo", "redis", "postgres", "mysql",
        "scada", "plc", "hmi", "ics", "modbus"
    }

    def __init__(self, domain: str, resolvers: list = None):
        self.domain = domain
        self.resolver = dns.resolver.Resolver()
        if resolvers:
            self.resolver.nameservers = resolvers
        else:
            self.resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        self.resolver.timeout = 3
        self.resolver.lifetime = 5

    def resolve_ip(self, hostname: str) -> str:
        """Löst Hostname zu IP auf"""
        try:
            answers = self.resolver.resolve(hostname, "A")
            return str(answers[0])
        except Exception:
            return ""

    def resolve_cname(self, hostname: str) -> str:
        """Prüft auf CNAME (Takeover-Risiko)"""
        try:
            answers = self.resolver.resolve(hostname, "CNAME")
            return str(answers[0])
        except Exception:
            return ""

    def check_zone_transfer(self) -> list:
        """Prüft ob Zone Transfer erlaubt ist (kritisches Sicherheitsproblem)"""
        results = []
        try:
            ns_answers = self.resolver.resolve(self.domain, "NS")
            for ns in ns_answers:
                ns_str = str(ns)
                try:
                    ns_ip = self.resolve_ip(ns_str.rstrip("."))
                    if ns_ip:
                        zone = dns.zone.from_xfr(
                            dns.query.xfr(ns_ip, self.domain, timeout=5)
                        )
                        # Zone Transfer erfolgreich = kritisches Finding!
                        records = []
                        for name, node in zone.nodes.items():
                            records.append(str(name))
                        results.append({
                            "nameserver": ns_str,
                            "vulnerable": True,
                            "records_exposed": len(records)
                        })
                except Exception:
                    pass
        except Exception:
            pass
        return results

    def get_mx_records(self) -> list:
        """MX-Records → welcher Mailprovider, direkter Mailserver?"""
        try:
            answers = self.resolver.resolve(self.domain, "MX")
            return [{"priority": r.preference, "host": str(r.exchange)} for r in answers]
        except Exception:
            return []

    def get_txt_records(self) -> list:
        """TXT-Records: SPF, DMARC, DKIM, Verifikationstoken"""
        try:
            answers = self.resolver.resolve(self.domain, "TXT")
            return [str(r) for r in answers]
        except Exception:
            return []

    def check_spf_dmarc(self, txt_records: list) -> dict:
        """Prüft E-Mail-Sicherheitskonfiguration"""
        result = {
            "spf_exists": False,
            "spf_strict": False,
            "dmarc_exists": False,
            "dmarc_policy": "none",
            "risk": "HIGH"
        }

        for record in txt_records:
            record_lower = record.lower()
            if "v=spf1" in record_lower:
                result["spf_exists"] = True
                if "-all" in record_lower:
                    result["spf_strict"] = True

        # DMARC separat abfragen
        try:
            dmarc_answers = self.resolver.resolve(f"_dmarc.{self.domain}", "TXT")
            for r in dmarc_answers:
                r_str = str(r).lower()
                if "v=dmarc1" in r_str:
                    result["dmarc_exists"] = True
                    if "p=reject" in r_str:
                        result["dmarc_policy"] = "reject"
                        result["risk"] = "LOW"
                    elif "p=quarantine" in r_str:
                        result["dmarc_policy"] = "quarantine"
                        result["risk"] = "MEDIUM"
                    else:
                        result["dmarc_policy"] = "none"
        except Exception:
            pass

        if not result["spf_exists"] and not result["dmarc_exists"]:
            result["risk"] = "CRITICAL"
        elif not result["dmarc_exists"] or result["dmarc_policy"] == "none":
            result["risk"] = "HIGH"

        return result

    def enumerate_subdomains(self) -> list:
        """Subdomain-Bruteforce + Risikobewertung"""
        found = []
        for sub in self.COMMON_SUBDOMAINS:
            hostname = f"{sub}.{self.domain}"
            ip = self.resolve_ip(hostname)
            if ip:
                cname = self.resolve_cname(hostname)
                risk = "HIGH" if sub in self.HIGH_RISK_SUBDOMAINS else "MEDIUM"
                reason = ""
                if sub in self.HIGH_RISK_SUBDOMAINS:
                    reason = f"Management-Interface '{sub}' öffentlich erreichbar"
                # CNAME Takeover Check
                if cname and any(p in cname.lower() for p in [
                    "github", "heroku", "amazonaws", "cloudfront",
                    "fastly", "shopify", "zendesk", "ghost"
                ]):
                    risk = "CRITICAL"
                    reason = f"Möglicher Subdomain-Takeover: CNAME zeigt auf {cname}"

                found.append(SubdomainResult(
                    subdomain=hostname,
                    ip=ip,
                    cname=cname,
                    risk=risk,
                    reason=reason
                ))
        return found

    def get_certificate_transparency(self, limit: int = 50) -> list:
        """
        Certificate Transparency Logs: alle Subdomains aus SSL-Zertifikaten
        Nutzt die kostenlose crt.sh API
        """
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "MSSP-EASM/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                for entry in data[:limit]:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{self.domain}") and "*" not in sub:
                            subdomains.add(sub)
        except Exception as e:
            pass
        return list(subdomains)


# ─── SSL-Zertifikat-Analyse ────────────────────────────────────────────

class SSLAnalyzer:
    """Analysiert SSL/TLS-Konfiguration exponierter Services"""

    # Schwache Cipher Suites
    WEAK_CIPHERS = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5"]

    def check_certificate(self, hostname: str, port: int = 443) -> dict:
        """Prüft SSL-Zertifikat auf Schwachstellen"""
        result = {
            "valid": False,
            "subject": {},
            "issuer": {},
            "expires": "",
            "days_until_expiry": -1,
            "self_signed": False,
            "weak_protocol": False,
            "protocol": "",
            "issues": [],
            "risk": "LOW"
        }

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()

                    result["valid"] = True
                    result["protocol"] = protocol

                    # Ablauf berechnen
                    if cert.get("notAfter"):
                        expiry = ssl.cert_time_to_seconds(cert["notAfter"])
                        now = datetime.datetime.utcnow().timestamp()
                        days_left = int((expiry - now) / 86400)
                        result["expires"] = cert["notAfter"]
                        result["days_until_expiry"] = days_left

                        if days_left < 0:
                            result["issues"].append("ABGELAUFEN")
                            result["risk"] = "CRITICAL"
                        elif days_left < 30:
                            result["issues"].append(f"Läuft in {days_left} Tagen ab")
                            result["risk"] = "HIGH"

                    # Self-Signed?
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    result["subject"] = subject
                    result["issuer"] = issuer

                    if subject.get("organizationName") == issuer.get("organizationName"):
                        result["self_signed"] = True
                        result["issues"].append("Self-Signed Zertifikat")
                        if result["risk"] == "LOW":
                            result["risk"] = "HIGH"

                    # Schwaches Protokoll?
                    if protocol in ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]:
                        result["weak_protocol"] = True
                        result["issues"].append(f"Schwaches Protokoll: {protocol}")
                        result["risk"] = "HIGH"

        except ssl.SSLError as e:
            result["issues"].append(f"SSL-Fehler: {str(e)[:50]}")
            result["risk"] = "HIGH"
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

        return result


# ─── CVE Matching Engine ────────────────────────────────────────────────

class CVEMatcher:
    """Matcht PAN-OS/Software-Versionen gegen NVD + CISA KEV"""

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_API = "https://api.first.org/data/v1/epss"
    CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self):
        self._kev_cache = None

    def get_cisa_kev(self) -> set:
        """Lädt CISA Known Exploited Vulnerabilities (kostenlos)"""
        if self._kev_cache:
            return self._kev_cache
        try:
            req = urllib.request.Request(
                self.CISA_KEV,
                headers={"User-Agent": "MSSP-EASM/1.0"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                self._kev_cache = {
                    v["cveID"] for v in data.get("vulnerabilities", [])
                }
                return self._kev_cache
        except Exception:
            return set()

    def search_panos_cves(self, version: str, limit: int = 20) -> list:
        """Sucht CVEs für eine bestimmte PAN-OS Version"""
        findings = []
        try:
            params = urllib.parse.urlencode({
                "keywordSearch": f"PAN-OS {version}",
                "resultsPerPage": limit
            })
            url = f"{self.NVD_API}?{params}"
            req = urllib.request.Request(url, headers={
                "User-Agent": "MSSP-EASM/1.0",
                "apiKey": ""  # Leer = kostenlos, aber rate-limited
            })
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode())
                kev_ids = self.get_cisa_kev()

                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")

                    # CVSS Score
                    cvss_score = 0.0
                    severity = "UNKNOWN"
                    metrics = cve.get("metrics", {})
                    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        if key in metrics and metrics[key]:
                            cvss_data = metrics[key][0].get("cvssData", {})
                            cvss_score = cvss_data.get("baseScore", 0.0)
                            severity = metrics[key][0].get("baseSeverity", "UNKNOWN")
                            break

                    # Description
                    descriptions = cve.get("descriptions", [])
                    desc = next(
                        (d["value"] for d in descriptions if d.get("lang") == "en"),
                        "No description"
                    )

                    if cvss_score >= 7.0:  # Nur HIGH + CRITICAL
                        findings.append(CVEFinding(
                            cve_id=cve_id,
                            cvss_score=cvss_score,
                            severity=severity,
                            description=desc[:200],
                            cisa_kev=cve_id in kev_ids,
                            affected_version=version
                        ))

        except Exception as e:
            # Fallback: bekannte PAN-OS CVEs (statisch)
            findings = self._get_known_panos_cves(version)

        return sorted(findings, key=lambda x: x.cvss_score, reverse=True)

    def _get_known_panos_cves(self, version: str) -> list:
        """Fallback: bekannte kritische PAN-OS CVEs"""
        # Wichtige CVEs der letzten Jahre
        known_cves = [
            CVEFinding("CVE-2024-3400", 10.0, "CRITICAL",
                "OS Command Injection in GlobalProtect Gateway (aktiv ausgenutzt)",
                cisa_kev=True, affected_version="< 10.2.9, < 11.0.4, < 11.1.2"),
            CVEFinding("CVE-2024-0012", 9.8, "CRITICAL",
                "Authentication Bypass in Management Interface",
                cisa_kev=True, affected_version="< 10.2.12, < 11.1.5, < 11.2.4"),
            CVEFinding("CVE-2024-9474", 6.9, "MEDIUM",
                "Privilege Escalation in PAN-OS Management Interface",
                cisa_kev=True, affected_version="< 10.2.12, < 11.1.5"),
            CVEFinding("CVE-2022-0028", 8.6, "HIGH",
                "URL Filtering Policy Misconfiguration leads to DoS",
                cisa_kev=False, affected_version="< 10.1.6, < 10.2.2"),
            CVEFinding("CVE-2021-3064", 9.8, "CRITICAL",
                "Buffer Overflow in GlobalProtect Portal/Gateway",
                cisa_kev=True, affected_version="< 8.1.17"),
        ]
        return [c for c in known_cves if "aktiv" in c.description or c.cisa_kev]


# ─── HIBP Credential Leak Check ────────────────────────────────────────

class CredentialLeakChecker:
    """Prüft Domains auf bekannte Datenpannen via HaveIBeenPwned"""

    HIBP_API = "https://haveibeenpwned.com/api/v3"

    def check_domain(self, domain: str, api_key: str = "") -> list:
        """
        Prüft alle bekannten Breaches für eine Domain.
        Kostenlos über die HIBP Domain-Search (benötigt API-Key für v3).
        Fallback: öffentliche Breach-Suche.
        """
        breaches = []
        headers = {
            "User-Agent": "MSSP-EASM-HealthCheck/1.0",
            "hibp-api-key": api_key
        }

        try:
            url = f"{self.HIBP_API}/breacheddomain/{domain}"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                for breach_name, emails in data.items():
                    breaches.append({
                        "breach": breach_name,
                        "affected_emails": len(emails) if isinstance(emails, list) else 1,
                        "domain": domain
                    })
        except urllib.error.HTTPError as e:
            if e.code == 401:
                # Kein API-Key: öffentliche Alternative
                breaches = self._public_breach_check(domain)
            elif e.code == 404:
                pass  # Keine Breaches gefunden
        except Exception:
            breaches = self._public_breach_check(domain)

        return breaches

    def _public_breach_check(self, domain: str) -> list:
        """Fallback: öffentliche HIBP-Suche (nur Breach-Namen)"""
        try:
            url = f"https://haveibeenpwned.com/api/v3/breaches"
            req = urllib.request.Request(url, headers={"User-Agent": "MSSP-EASM/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                all_breaches = json.loads(resp.read().decode())
                # Suche nach Domain-Übereinstimmungen
                domain_clean = domain.lower()
                relevant = []
                for breach in all_breaches:
                    breach_domain = breach.get("Domain", "").lower()
                    if domain_clean in breach_domain or breach_domain in domain_clean:
                        relevant.append({
                            "breach": breach["Name"],
                            "affected_emails": breach.get("PwnCount", 0),
                            "domain": breach.get("Domain", ""),
                            "date": breach.get("BreachDate", ""),
                            "data_classes": breach.get("DataClasses", [])
                        })
                return relevant
        except Exception:
            return []

# ─── Risk Scorer ────────────────────────────────────────────────────────

class RiskScorer:
    """Berechnet Risiko-Score für EASM-Findings"""

    # Basis-Score: 100 (perfekt), Abzüge pro Finding
    DEDUCTIONS = {
        "zone_transfer_vulnerable": -25,
        "management_interface_exposed": -20,
        "ssl_expired": -15,
        "ssl_weak_protocol": -10,
        "ssl_self_signed": -8,
        "ssl_expiring_soon": -5,
        "cve_critical": -20,
        "cve_high": -10,
        "cve_medium": -5,
        "cisa_kev": -15,  # zusätzlich bei aktiv ausgenutzter CVE
        "credential_leak": -10,
        "subdomain_takeover_risk": -20,
        "high_risk_subdomain": -8,
        "no_spf": -8,
        "no_dmarc": -10,
        "dmarc_policy_none": -5,
        "typosquat_active": -5,
    }

    def calculate(self, report: 'EASMReport') -> dict:
        score = 100
        deductions = []
        findings_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        # CVE Findings
        for cve in report.cve_findings:
            if cve.cvss_score >= 9.0:
                d = self.DEDUCTIONS["cve_critical"]
                score += d
                deductions.append((f"CVE {cve.cve_id} (CVSS {cve.cvss_score})", d))
                findings_by_severity["CRITICAL"] += 1
            elif cve.cvss_score >= 7.0:
                d = self.DEDUCTIONS["cve_high"]
                score += d
                deductions.append((f"CVE {cve.cve_id} (CVSS {cve.cvss_score})", d))
                findings_by_severity["HIGH"] += 1
            if cve.cisa_kev:
                d = self.DEDUCTIONS["cisa_kev"]
                score += d
                deductions.append((f"CISA KEV: {cve.cve_id} aktiv ausgenutzt", d))

        # Subdomain Findings
        for sub in report.subdomains:
            if sub.risk == "CRITICAL":
                d = self.DEDUCTIONS["subdomain_takeover_risk"]
                score += d
                deductions.append((f"Subdomain Takeover: {sub.subdomain}", d))
                findings_by_severity["CRITICAL"] += 1
            elif sub.risk == "HIGH":
                d = self.DEDUCTIONS["high_risk_subdomain"]
                score += d
                deductions.append((f"Exponiertes Interface: {sub.subdomain}", d))
                findings_by_severity["HIGH"] += 1

        # Credential Leaks
        for leak in report.credential_leaks:
            d = self.DEDUCTIONS["credential_leak"]
            score += d
            deductions.append((f"Datenpanne: {leak.get('breach', 'Unknown')}", d))
            findings_by_severity["HIGH"] += 1

        # Typosquats
        for ts in report.typosquat_domains:
            d = self.DEDUCTIONS["typosquat_active"]
            score += d
            deductions.append((f"Aktive Typosquat-Domain: {ts['domain']}", d))
            findings_by_severity["MEDIUM"] += 1

        score = max(0, min(100, score))

        # Ampel
        if score >= 80:
            grade = "A"
            color = "green"
        elif score >= 60:
            grade = "B"
            color = "yellow"
        elif score >= 40:
            grade = "C"
            color = "orange"
        else:
            grade = "D"
            color = "red"

        return {
            "score": score,
            "grade": grade,
            "color": color,
            "deductions": deductions[:10],  # Top 10 Abzüge
            "findings_by_severity": findings_by_severity
        }


# ─── EASM Scanner (Orchestrator) ────────────────────────────────────────

class EASMScanner:
    """
    Hauptklasse: orchestriert alle EASM-Checks für einen Mandanten.

    Verwendung:
        scanner = EASMScanner(tenant_id="kunde-001")
        report = scanner.scan(
            domain="example.de",
            ip_ranges=["203.0.113.0/24"],
            panos_version="10.2.7"
        )
        print(json.dumps(asdict(report), indent=2, default=str))
    """

    def __init__(self, tenant_id: str, shodan_key: str = "", hibp_key: str = ""):
        self.tenant_id = tenant_id
        self.shodan_key = shodan_key
        self.hibp_key = hibp_key

        self.dns_enum = None
        self.ssl_analyzer = SSLAnalyzer()
        self.cve_matcher = CVEMatcher()
        self.leak_checker = CredentialLeakChecker()
        self.scorer = RiskScorer()

    def scan(self,
             domain: str,
             ip_ranges: list,
             panos_version: str = "",
             deep_scan: bool = False) -> EASMReport:
        """
        Führt vollständigen EASM-Scan durch.

        Args:
            domain: Kunden-Domain (z.B. "example.de")
            ip_ranges: Liste von IP-Ranges (z.B. ["203.0.113.0/24"])
            panos_version: Installierte PAN-OS Version
            deep_scan: Wenn True, auch langsame Checks ausführen
        """
        print(f"[*] EASM Scan gestartet: {domain} | Tenant: {self.tenant_id}")

        report = EASMReport(
            tenant_id=self.tenant_id,
            domain=domain,
            ip_ranges=ip_ranges,
            scan_timestamp=datetime.datetime.utcnow().isoformat()
        )

        self.dns_enum = DNSEnumerator(domain)

        # ── 1. DNS Enumeration ──────────────────────────────────────
        print(f"[1/6] DNS-Enumeration für {domain}...")

        # Certificate Transparency Logs
        ct_subdomains = self.dns_enum.get_certificate_transparency()
        print(f"      CT-Logs: {len(ct_subdomains)} Subdomains gefunden")

        # Subdomain Bruteforce
        found_subs = self.dns_enum.enumerate_subdomains()
        report.subdomains = found_subs
        print(f"      Bruteforce: {len(found_subs)} aktive Subdomains")

        # Zone Transfer Check
        zt_results = self.dns_enum.check_zone_transfer()
        if zt_results:
            for zt in zt_results:
                if zt.get("vulnerable"):
                    report.exposed_assets.append(ExposedAsset(
                        ip="", hostname=domain,
                        service="DNS Zone Transfer",
                        risk_score=100,
                        risk_reason=f"Zone Transfer offen: {zt['records_exposed']} Records exponiert!",
                        source="dns"
                    ))
            print(f"      ⚠ Zone Transfer VULNERABEL!")

        # MX + TXT + SPF/DMARC
        txt_records = self.dns_enum.get_txt_records()
        email_security = self.dns_enum.check_spf_dmarc(txt_records)
        report.risk_summary["email_security"] = email_security

        # ── 2. SSL Checks ───────────────────────────────────────────
        print(f"[2/6] SSL/TLS-Checks für {len(found_subs)} Subdomains...")
        ssl_issues = []
        for sub in found_subs[:20]:  # Max 20 für Performance
            ssl_result = self.ssl_analyzer.check_certificate(sub.subdomain)
            if ssl_result.get("issues"):
                ssl_issues.append({
                    "host": sub.subdomain,
                    "issues": ssl_result["issues"],
                    "risk": ssl_result["risk"],
                    "days_left": ssl_result.get("days_until_expiry", -1)
                })
        report.risk_summary["ssl_issues"] = ssl_issues
        print(f"      {len(ssl_issues)} SSL-Probleme gefunden")

        # ── 3. CVE Matching ─────────────────────────────────────────
        if panos_version:
            print(f"[3/6] CVE-Matching für PAN-OS {panos_version}...")
            cves = self.cve_matcher.search_panos_cves(panos_version)
            report.cve_findings = cves
            kev_count = sum(1 for c in cves if c.cisa_kev)
            print(f"      {len(cves)} CVEs gefunden ({kev_count} CISA KEV aktiv ausgenutzt)")
        else:
            print("[3/6] CVE-Matching übersprungen (keine PAN-OS Version angegeben)")

        # ── 4. Credential Leak Check ────────────────────────────────
        print(f"[4/6] Credential-Leak-Check für {domain}...")
        leaks = self.leak_checker.check_domain(domain, self.hibp_key)
        report.credential_leaks = leaks
        print(f"      {len(leaks)} Datenpannen gefunden")

        # ── 5. Typosquatting ────────────────────────────────────────
        # Handled by EASMPipeline Phase 7 (dnstwist_adapter) when invoked
        # through the Celery worker. EASMScanner.scan() is a legacy path used
        # only for direct CLI invocations; typosquat findings are empty here.
        print(f"[5/6] Typosquatting — wird durch EASMPipeline (dnstwist) abgedeckt")
        report.typosquat_domains = []

        # ── 6. Risk Score berechnen ─────────────────────────────────
        print(f"[6/6] Risk Score berechnen...")
        score_data = self.scorer.calculate(report)
        report.score = score_data["score"]
        report.risk_summary["score_details"] = score_data

        print(f"\n{'='*50}")
        print(f"  EASM Report: {domain}")
        print(f"  Score: {score_data['score']}/100 (Grade: {score_data['grade']})")
        print(f"  CRITICAL: {score_data['findings_by_severity']['CRITICAL']}")
        print(f"  HIGH:     {score_data['findings_by_severity']['HIGH']}")
        print(f"  MEDIUM:   {score_data['findings_by_severity']['MEDIUM']}")
        print(f"{'='*50}\n")

        return report


# ─── Demo / Beispielaufruf ──────────────────────────────────────────────

if __name__ == "__main__":
    # Beispiel: Scan einer Demo-Domain (ohne echte Kundendaten)
    scanner = EASMScanner(
        tenant_id="demo-kunde-001",
        shodan_key="",   # Leer = kein Shodan (DNS-Only Mode)
        hibp_key=""      # Leer = öffentliche HIBP API (limitiert)
    )

    report = scanner.scan(
        domain="paloaltonetworks.com",  # Demo-Domain
        ip_ranges=["66.235.200.0/24"],
        panos_version="10.2.7",
        deep_scan=False  # True für vollständigen Scan inkl. Typosquatting
    )

    # JSON-Export
    output = {
        "tenant_id": report.tenant_id,
        "domain": report.domain,
        "scan_timestamp": report.scan_timestamp,
        "score": report.score,
        "subdomains_found": len(report.subdomains),
        "high_risk_subdomains": [
            {"subdomain": s.subdomain, "ip": s.ip, "risk": s.risk, "reason": s.reason}
            for s in report.subdomains if s.risk in ("CRITICAL", "HIGH")
        ],
        "cve_findings": [
            {"cve_id": c.cve_id, "cvss": c.cvss_score, "cisa_kev": c.cisa_kev}
            for c in report.cve_findings[:5]
        ],
        "credential_leaks": report.credential_leaks[:3],
        "email_security": report.risk_summary.get("email_security", {}),
        "ssl_issues": report.risk_summary.get("ssl_issues", [])[:3],
        "score_details": report.risk_summary.get("score_details", {})
    }
    print(json.dumps(output, indent=2, default=str))
