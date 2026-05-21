"""
Email infrastructure risk scorer — heuristic, 0–100 (higher = more risk).
Pure computation: no I/O, no network calls.
"""
from __future__ import annotations

_RFC_LOOKUP_LIMIT = 10  # RFC 7208 §4.6.4
from dataclasses import dataclass, field

from .spf_parser import SpfNode, collect_all_includes, max_depth, count_includes
from .dmarc_parser import DmarcPolicy
from .enricher import EnrichedIP
from .mx_analyzer import MxServerInfo


@dataclass
class EmailFinding:
    code: str
    severity: str   # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    detail: str
    remediation: str


@dataclass
class ScoreResult:
    score: int
    band: str
    findings: list[EmailFinding] = field(default_factory=list)
    spf_depth: int = 0
    spf_include_count: int = 0
    spf_lookup_count: int = 0
    provider_count: int = 0
    ip_count: int = 0
    asn_count: int = 0
    mx_count: int = 0


def risk_band(score: int) -> str:
    if score <= 25:  return "Low"
    if score <= 50:  return "Medium"
    if score <= 75:  return "High"
    return "Critical"


def score(
    spf_tree: SpfNode | None,
    dmarc: DmarcPolicy,
    enriched_ips: list[EnrichedIP],
    mx_servers: list[MxServerInfo],
) -> ScoreResult:
    points = 0
    findings: list[EmailFinding] = []

    # ── SPF ────────────────────────────────────────────────────────────────
    if spf_tree is None or spf_tree.raw is None:
        points += 30
        findings.append(EmailFinding(
            code="SPF_MISSING", severity="CRITICAL",
            title="SPF-Record fehlt",
            detail="Es wurde kein v=spf1 TXT-Record für diese Domain gefunden.",
            remediation='Erstellen Sie einen SPF-Record: "v=spf1 include:provider.com -all"',
        ))
    else:
        q = spf_tree.all_qualifier
        if q == "+":
            points += 25
            findings.append(EmailFinding(
                code="SPF_PASS_ALL", severity="CRITICAL",
                title="SPF erlaubt alle Absender (+all)",
                detail="+all autorisiert jeden Mailserver weltweit — SPF ist damit wirkungslos.",
                remediation="Ersetzen Sie +all durch -all (Hardfail).",
            ))
        elif q == "?":
            points += 18
            findings.append(EmailFinding(
                code="SPF_NEUTRAL_ALL", severity="HIGH",
                title="SPF-Neutral-Qualifier (?all)",
                detail="?all liefert kein Pass/Fail — Spam-Filter behandeln SPF als nicht vorhanden.",
                remediation="Verwenden Sie -all oder mindestens ~all.",
            ))
        elif q == "~":
            points += 10
            findings.append(EmailFinding(
                code="SPF_SOFTFAIL_ALL", severity="MEDIUM",
                title="SPF-Softfail (~all) statt Hardfail (-all)",
                detail="~all markiert nicht-autorisierte Mails als verdächtig, blockiert sie aber nicht.",
                remediation="Wechseln Sie zu -all für strikte Durchsetzung.",
            ))
        elif q is None:
            points += 8
            findings.append(EmailFinding(
                code="SPF_NO_ALL", severity="MEDIUM",
                title="SPF-Record ohne all-Mechanismus",
                detail="Ohne terminalen all-Mechanismus ist das Verhalten laut RFC unspezifiziert.",
                remediation="Fügen Sie -all am Ende des SPF-Records ein.",
            ))

        lc = spf_tree.lookup_count
        if lc > _RFC_LOOKUP_LIMIT:
            points += 15
            findings.append(EmailFinding(
                code="SPF_LOOKUP_LIMIT", severity="HIGH",
                title=f"SPF-DNS-Lookups überschreiten RFC-Limit ({lc}/10)",
                detail="RFC 7208 erlaubt maximal 10 DNS-Lookups. Bei Überschreitung liefern empfangende Server ein PermError.",
                remediation="Reduzieren Sie includes oder nutzen Sie einen SPF-Flattening-Dienst.",
            ))
        elif lc >= 7:
            points += 5
            findings.append(EmailFinding(
                code="SPF_LOOKUP_HIGH", severity="LOW",
                title=f"SPF-DNS-Lookups nähern sich dem Limit ({lc}/10)",
                detail="Bei weiteren Provider-Hinzufügungen kann das RFC-Limit überschritten werden.",
                remediation="Überwachen Sie SPF-Lookups bei jeder Konfigurationsänderung.",
            ))

        inc_count = count_includes(spf_tree)
        if inc_count > 8:
            points += 8
            findings.append(EmailFinding(
                code="SPF_EXCESSIVE_INCLUDES", severity="MEDIUM",
                title=f"Zu viele SPF includes ({inc_count})",
                detail="Viele includes erhöhen Komplexität und DNS-Lookup-Kosten.",
                remediation="Konsolidieren Sie Provider-Includes.",
            ))

        depth = max_depth(spf_tree)
        if depth > 5:
            points += 8
            findings.append(EmailFinding(
                code="SPF_DEPTH_HIGH", severity="MEDIUM",
                title=f"Hohe SPF include-Tiefe ({depth} Ebenen)",
                detail="Tiefe Include-Ketten sind schwer verwaltbar und erschöpfen das Lookup-Budget schnell.",
                remediation="Flachen Sie verschachtelte include:-Ketten ab.",
            ))

        for err in spf_tree.errors:
            if "CYCLE_DETECTED" in err:
                points += 10
                findings.append(EmailFinding(
                    code="SPF_CYCLE", severity="HIGH",
                    title="Zyklus in SPF include-Kette",
                    detail=err,
                    remediation="Entfernen Sie den zirkulären include-Verweis.",
                ))

    # ── DMARC ──────────────────────────────────────────────────────────────
    if not dmarc.present:
        points += 25
        findings.append(EmailFinding(
            code="DMARC_MISSING", severity="CRITICAL",
            title="DMARC-Record fehlt",
            detail="Ohne DMARC können Phishing-Mails im Namen dieser Domain ungehindert zugestellt werden.",
            remediation='Erstellen Sie: "_dmarc.domain TXT v=DMARC1; p=quarantine; rua=mailto:dmarc@domain.com"',
        ))
    else:
        if dmarc.p == "none":
            points += 20
            findings.append(EmailFinding(
                code="DMARC_POLICY_NONE", severity="HIGH",
                title="DMARC-Policy 'none' — nur Monitoring, keine Durchsetzung",
                detail="p=none aktiviert ausschließlich Reporting. Phishing-Mails werden nicht blockiert.",
                remediation="Migrieren Sie schrittweise zu p=quarantine, dann p=reject.",
            ))
        elif dmarc.p == "quarantine":
            points += 5
            findings.append(EmailFinding(
                code="DMARC_QUARANTINE", severity="LOW",
                title="DMARC-Policy 'quarantine' — nicht vollständig enforced",
                detail="p=quarantine markiert Mails als Spam, löscht sie jedoch nicht.",
                remediation="Erwägen Sie die Migration zu p=reject für vollständige Durchsetzung.",
            ))

        if dmarc.pct < 100 and dmarc.p in ("quarantine", "reject"):
            points += 5
            findings.append(EmailFinding(
                code="DMARC_PARTIAL", severity="LOW",
                title=f"DMARC-Policy greift nur auf {dmarc.pct}% der Nachrichten",
                detail=f"pct={dmarc.pct} bedeutet partielle Durchsetzung.",
                remediation="Erhöhen Sie pct schrittweise auf 100.",
            ))

        if not dmarc.rua:
            points += 5
            findings.append(EmailFinding(
                code="DMARC_NO_REPORTING", severity="LOW",
                title="Kein DMARC Aggregate-Reporting konfiguriert",
                detail="Ohne rua-Adresse erhalten Sie keine Berichte über SPF/DKIM-Fehler.",
                remediation="Fügen Sie rua=mailto:dmarc@ihre-domain.com hinzu.",
            ))

    # ── Providers & IPs ────────────────────────────────────────────────────
    unknown_ips = [ip for ip in enriched_ips if ip.provider_category == "unknown"]
    if unknown_ips:
        penalty = min(len(unknown_ips) * 5, 15)
        points += penalty
        findings.append(EmailFinding(
            code="SPF_UNKNOWN_PROVIDERS", severity="LOW",
            title=f"{len(unknown_ips)} unbekannte(r) IP-Block(s) in SPF autorisiert",
            detail="IPs ohne zuordenbaren Provider erschweren das Risiko-Assessment.",
            remediation="Prüfen Sie, ob diese IPs wirklich zu Ihren Mail-Providern gehören.",
        ))

    known_providers = {ip.provider_name for ip in enriched_ips if ip.provider_name != "Unknown"}
    if len(known_providers) > 5:
        points += 8
        findings.append(EmailFinding(
            code="SPF_MANY_PROVIDERS", severity="MEDIUM",
            title=f"Hohe Anzahl externer E-Mail-Provider ({len(known_providers)})",
            detail="Jeder externe Provider ist ein potenzieller Angriffspunkt (kompromittierter Provider → Phishing).",
            remediation="Konsolidieren Sie E-Mail-Provider, wo betrieblich möglich.",
        ))

    # ── MX ─────────────────────────────────────────────────────────────────
    if not mx_servers:
        points += 5
        findings.append(EmailFinding(
            code="NO_MX_RECORDS", severity="LOW",
            title="Keine MX-Records gefunden",
            detail="Ohne MX-Records ist kein E-Mail-Empfang konfiguriert.",
            remediation="Prüfen Sie, ob diese Domain E-Mail empfangen soll.",
        ))

    # ── Compute stats ──────────────────────────────────────────────────────
    providers = collect_all_includes(spf_tree) if spf_tree else set()
    asn_set = {ip.asn.number for ip in enriched_ips if ip.asn}

    return ScoreResult(
        score=min(100, points),
        band=risk_band(min(100, points)),
        findings=findings,
        spf_depth=max_depth(spf_tree) if spf_tree else 0,
        spf_include_count=count_includes(spf_tree) if spf_tree else 0,
        spf_lookup_count=spf_tree.lookup_count if spf_tree else 0,
        provider_count=len(providers),
        ip_count=len(enriched_ips),
        asn_count=len(asn_set),
        mx_count=len(mx_servers),
    )
