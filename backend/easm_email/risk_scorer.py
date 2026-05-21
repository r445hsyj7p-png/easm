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
from .models import EmailFinding


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
    dkim_results=None,   # list[DkimResult] | None
    rbl_hits=None,       # list[RblHit] | None
    mta_sts=None,        # MtaStsResult | None
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

    # ── DKIM ───────────────────────────────────────────────────────────────
    dkim_results = dkim_results or []
    if not dkim_results:
        points += 5
        findings.append(EmailFinding(
            code="DKIM_NOT_FOUND", severity="LOW",
            title="Kein DKIM-Eintrag unter gängigen Selektoren gefunden",
            detail="Keiner der ~20 getesteten Standard-Selektoren (google, selector1, k1 …) ist publiziert. "
                   "Custom-Selektoren werden nicht geprüft — DKIM kann dennoch aktiv sein.",
            remediation="Publizieren Sie einen DKIM-TXT-Record und konfigurieren Sie Signing in Ihrem Mail-System.",
        ))
    else:
        for r in dkim_results:
            if r.revoked:
                points += 10
                findings.append(EmailFinding(
                    code="DKIM_KEY_REVOKED", severity="HIGH",
                    title=f"DKIM-Schlüssel widerrufen (Selektor: {r.selector})",
                    detail="Ein leerer p=-Tag signalisiert einen zurückgezogenen Schlüssel. "
                           "Empfangende Server werden DKIM-Signaturen mit diesem Selektor ablehnen.",
                    remediation="Entfernen Sie den widerrufenen Record oder ersetzen Sie ihn durch einen aktiven Schlüssel.",
                ))
            elif r.weak:
                points += 12
                bits_str = f"{r.key_bits_estimate} bit" if r.key_bits_estimate else "unbekannte Länge"
                findings.append(EmailFinding(
                    code="DKIM_WEAK_KEY", severity="HIGH",
                    title=f"Schwacher DKIM-RSA-Schlüssel (Selektor: {r.selector}, ~{bits_str})",
                    detail=f"RSA-Schlüssel unter 2048 bit gelten seit RFC 8301 als unsicher und können gebrochen werden.",
                    remediation="Ersetzen Sie den Schlüssel durch RSA-2048 oder besser Ed25519.",
                ))

    # ── RBL ────────────────────────────────────────────────────────────────
    rbl_hits = rbl_hits or []
    # PBL hits (severity=INFO) don't contribute to score — expected for many corporate IPs
    scored_hits = [h for h in rbl_hits if h.severity != "INFO"]
    for hit in scored_hits:
        penalty = 20 if hit.severity == "CRITICAL" else 12
        points += penalty
        findings.append(EmailFinding(
            code=f"RBL_{hit.list_name.replace('-', '_')}",
            severity=hit.severity,
            title=f"MX-IP {hit.ip} auf Spamhaus {hit.list_name} gelistet",
            detail=hit.description,
            remediation="Prüfen Sie den Host auf Kompromittierung und beantragen Sie eine Delistung bei Spamhaus.",
        ))
    # PBL as INFO finding (no points)
    pbl_hits = [h for h in rbl_hits if h.severity == "INFO"]
    if pbl_hits:
        ips_str = ", ".join(h.ip for h in pbl_hits[:3])
        ellipsis = "…" if len(pbl_hits) > 3 else ""
        findings.append(EmailFinding(
            code="RBL_PBL",
            severity="INFO",
            title=f"{len(pbl_hits)} MX-IP(s) auf Spamhaus PBL ({ips_str}{ellipsis})",
            detail="PBL-Einträge betreffen Endkunden-IPs ohne direkten SMTP-Versand. Kein akutes Risiko für korrekt konfigurierte Mailserver.",
            remediation="Stellen Sie sicher, dass ausgehende Mails über einen SMTP-Relay-Server mit rDNS gesendet werden.",
        ))

    # ── MTA-STS ────────────────────────────────────────────────────────────
    if mta_sts is not None:
        if not mta_sts.dns_declared:
            points += 5
            findings.append(EmailFinding(
                code="MTA_STS_MISSING", severity="LOW",
                title="MTA-STS nicht konfiguriert",
                detail="Ohne MTA-STS (RFC 8461) kann STARTTLS beim E-Mail-Empfang durch einen Angreifer downgraded werden.",
                remediation="Erstellen Sie _mta-sts.<domain> TXT-Record und hosten Sie die Policy-Datei unter https://mta-sts.<domain>/.well-known/mta-sts.txt",
            ))
        else:
            if not mta_sts.policy_reachable:
                points += 10
                findings.append(EmailFinding(
                    code="MTA_STS_UNREACHABLE", severity="MEDIUM",
                    title="MTA-STS deklariert, aber Policy-Datei nicht erreichbar",
                    detail=f"Der DNS-Record existiert, aber https://mta-sts.<domain>/.well-known/mta-sts.txt ist nicht abrufbar"
                           + (f": {mta_sts.policy_error}" if mta_sts.policy_error else "."),
                    remediation="Stellen Sie sicher, dass der Webserver für mta-sts.<domain> korrekt konfiguriert ist und HTTPS antwortet.",
                ))
            elif mta_sts.mode == "testing":
                points += 3
                findings.append(EmailFinding(
                    code="MTA_STS_TESTING", severity="LOW",
                    title="MTA-STS im Testing-Mode — keine Durchsetzung",
                    detail="mode=testing protokolliert Fehler, erzwingt TLS aber nicht.",
                    remediation="Wechseln Sie nach erfolgreichen Tests zu mode=enforce.",
                ))
            elif mta_sts.mode == "none":
                points += 8
                findings.append(EmailFinding(
                    code="MTA_STS_DISABLED", severity="MEDIUM",
                    title="MTA-STS deklariert aber deaktiviert (mode=none)",
                    detail="mode=none schaltet MTA-STS explizit aus, obwohl der DNS-Record vorhanden ist.",
                    remediation="Setzen Sie mode=enforce oder entfernen Sie den DNS-Record.",
                ))

        if not mta_sts.tls_rpt_present:
            findings.append(EmailFinding(
                code="TLS_RPT_MISSING", severity="INFO",
                title="TLS-RPT nicht konfiguriert",
                detail="Ohne _smtp._tls TXT-Record erhalten Sie keine Berichte über TLS-Verbindungsfehler bei eingehenden Mails.",
                remediation="Erstellen Sie: _smtp._tls.<domain> TXT \"v=TLSRPTv1; rua=mailto:tls-rpt@ihre-domain.com\"",
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
