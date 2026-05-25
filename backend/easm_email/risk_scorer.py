"""
Email infrastructure risk scorer — heuristic, 0–100 (higher = more risk).
Pure computation: no I/O, no network calls.
"""
from __future__ import annotations
import fnmatch
import ipaddress

_RFC_LOOKUP_LIMIT = 10  # RFC 7208 §4.6.4
from dataclasses import dataclass, field

from .spf_parser import (
    SpfNode, collect_all_includes, max_depth, count_includes,
    extract_spf_ips, has_mechanism_type,
)
from .dmarc_parser import DmarcPolicy
from .enricher import EnrichedIP
from .mx_analyzer import MxServerInfo
from .models import EmailFinding
from .provider_registry import PROVIDER_SPF_INCLUDES, PROVIDER_EXPECTED_SELECTORS


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
    # Structured output for UI rendering (populated by check sections below)
    spf_uncovered_ips: list[str] = field(default_factory=list)
    mta_sts_uncovered_fqdns: list[str] = field(default_factory=list)
    dkim_missing_providers: list[str] = field(default_factory=list)
    rua_external_domains: list[str] = field(default_factory=list)
    score_delta: int | None = None   # injected by task after prev-score DB lookup


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
    dkim_results=None,       # list[DkimResult] | None
    rbl_hits=None,           # list[RblHit] | None
    mta_sts=None,            # MtaStsResult | None
    dnssec_signed: bool = False,
    domain: str = "",
) -> ScoreResult:
    points = 0
    findings: list[EmailFinding] = []

    # Structured output accumulators (returned in ScoreResult for UI use)
    _spf_uncovered_ips: list[str] = []
    _mta_sts_uncovered_fqdns: list[str] = []
    _dkim_missing_providers: list[str] = []
    _rua_external_domains: list[str] = []

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

        # Parser stores CYCLE_DETECTED on the child node where the cycle is found,
        # not the root — must walk the full tree to detect it.
        def _tree_errors(node: SpfNode) -> list[str]:
            return node.errors + [e for c in node.children for e in _tree_errors(c)]

        for err in _tree_errors(spf_tree):
            if "CYCLE_DETECTED" in err:
                points += 10
                findings.append(EmailFinding(
                    code="SPF_CYCLE", severity="HIGH",
                    title="Zyklus in SPF include-Kette",
                    detail=err,
                    remediation="Entfernen Sie den zirkulären include-Verweis.",
                ))
                break  # one finding per cycle is sufficient

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

        if dmarc.sp is not None:
            _sp_strength = {"none": 1, "quarantine": 2, "reject": 3}.get(dmarc.sp, 1)
            _p_strength  = {"none": 1, "quarantine": 2, "reject": 3}.get(dmarc.p, 1)
            if _sp_strength < _p_strength:
                sev = "HIGH" if dmarc.sp == "none" else "MEDIUM"
                penalty = 10 if dmarc.sp == "none" else 5
                points += penalty
                findings.append(EmailFinding(
                    code="DMARC_SP_WEAKER", severity=sev,
                    title=f"DMARC-Subdomain-Policy (sp={dmarc.sp}) schwächer als Domain-Policy (p={dmarc.p})",
                    detail=f"sp={dmarc.sp} schützt Subdomains weniger als die Haupt-Domain (p={dmarc.p}). "
                           "Angreifer könnten Subdomains für Phishing missbrauchen.",
                    remediation=f"Setzen Sie sp={dmarc.p} oder entfernen Sie das sp=-Tag.",
                ))

        if dmarc.ruf:
            findings.append(EmailFinding(
                code="DMARC_FORENSIC_REPORTS", severity="INFO",
                title="DMARC Forensic-Reporting (ruf=) konfiguriert",
                detail=f"Forensic-Reports können Mail-Header mit personenbezogenen Daten enthalten. "
                       f"Empfänger: {', '.join(dmarc.ruf[:3])}{'…' if len(dmarc.ruf) > 3 else ''}",
                remediation="Prüfen Sie DSGVO-Konformität. Viele Provider haben ruf= aus Datenschutzgründen abgeschaltet.",
            ))

        # ── Feature 10: rua= external domain check ─────────────────────────
        if dmarc.rua and domain:
            for _addr in dmarc.rua:
                if _addr.startswith("mailto:"):
                    _local_at = _addr[7:]
                    if "@" not in _local_at:
                        continue  # malformed address — no domain part to classify
                    _rua_dom = _local_at.rsplit("@", 1)[-1].lower().strip()
                    if _rua_dom and _rua_dom != domain and not _rua_dom.endswith("." + domain):
                        _rua_external_domains.append(_rua_dom)
            _rua_external_domains = list(dict.fromkeys(_rua_external_domains))
            if _rua_external_domains:
                findings.append(EmailFinding(
                    code="DMARC_EXTERNAL_REPORTING", severity="INFO",
                    title="DMARC-Aggregate-Reports gehen an externe Domain(s)",
                    detail=f"rua= sendet Berichte an: {', '.join(_rua_external_domains)}. "
                           "Drittanbieter erhalten Einblick in E-Mail-Volumen und Authentifizierungsfehler.",
                    remediation="Prüfen Sie ob der Reporting-Anbieter vertrauenswürdig ist und DSGVO-konform.",
                ))

    # ── DNSSEC ─────────────────────────────────────────────────────────────
    if not dnssec_signed:
        points += 5
        findings.append(EmailFinding(
            code="DNSSEC_MISSING", severity="LOW",
            title="DNSSEC nicht aktiviert",
            detail="Ohne DNSSEC können DNS-Antworten durch Cache-Poisoning gefälscht werden, "
                   "was E-Mail-Umleitung und Domain-Hijacking ermöglicht.",
            remediation="Aktivieren Sie DNSSEC bei Ihrem DNS-Provider und publizieren Sie DS-Records beim Registrar.",
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

    # ── Feature 1: SPF↔MX Konsistenz ──────────────────────────────────────
    # Walk the fully-resolved SPF tree for explicit ip4/ip6 ranges and verify
    # each MX IP is covered. Skip if: tree incomplete (lookup limit hit), or
    # a bare `mx` mechanism exists (implicitly authorises all MX hosts).
    if spf_tree is not None and spf_tree.lookup_count <= _RFC_LOOKUP_LIMIT:
        if not has_mechanism_type(spf_tree, "mx"):
            _spf_nets = []
            for _cidr in extract_spf_ips(spf_tree):
                try:
                    _spf_nets.append(ipaddress.ip_network(_cidr, strict=False))
                except ValueError:
                    pass
            if _spf_nets:
                for _mx in mx_servers:
                    for _ip in _mx.ips:
                        try:
                            _addr = ipaddress.ip_address(_ip.address)
                            if not any(_addr in _net for _net in _spf_nets):
                                _spf_uncovered_ips.append(_ip.address)
                        except ValueError:
                            pass
                if _spf_uncovered_ips:
                    _n = len(_spf_uncovered_ips)
                    points += min(_n * 8, 20)
                    findings.append(EmailFinding(
                        code="MX_NOT_IN_SPF", severity="HIGH",
                        title=f"{_n} MX-IP(s) nicht durch explizite SPF-Regeln abgedeckt",
                        detail=f"Die IP(s) {', '.join(_spf_uncovered_ips[:3])}{'…' if _n > 3 else ''} "
                               f"sind in keiner ip4:/ip6:-Regel des vollständig aufgelösten SPF-Records erfasst. "
                               f"Prüfen Sie, ob der zugehörige include:-Eintrag fehlt.",
                        remediation="Ergänzen Sie den fehlenden include:-Eintrag für diesen Provider "
                                    "oder fügen Sie die IP-Range explizit als ip4: hinzu.",
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

    # ── Feature 2: Provider↔DKIM Erwartungsabgleich ────────────────────────
    if spf_tree:
        _spf_includes = collect_all_includes(spf_tree)
        _found_selectors = {r.selector for r in dkim_results if not r.revoked}
        for _pname, _include_doms in PROVIDER_SPF_INCLUDES.items():
            if not any(d in _spf_includes for d in _include_doms):
                continue
            _expected = PROVIDER_EXPECTED_SELECTORS.get(_pname, [])
            if _expected and not any(sel in _found_selectors for sel in _expected):
                _dkim_missing_providers.append(_pname)
        for _pname in _dkim_missing_providers:
            _expected = PROVIDER_EXPECTED_SELECTORS.get(_pname, [])
            findings.append(EmailFinding(
                code="DKIM_MISSING_FOR_PROVIDER", severity="LOW",
                title=f"Kein DKIM-Selector für {_pname} gefunden",
                detail=f"{_pname} ist in SPF autorisiert, aber keiner der erwarteten Selektoren "
                       f"({', '.join(_expected)}) ist publiziert.",
                remediation=f"Prüfen Sie die DKIM-Konfiguration in {_pname} und "
                            f"publizieren Sie den DKIM-TXT-Record für Ihre Domain.",
            ))

    # ── RBL ────────────────────────────────────────────────────────────────
    rbl_hits = rbl_hits or []
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

            # ── Feature 3: MTA-STS↔MX Konsistenz ──────────────────────────
            if mta_sts.policy_reachable and mta_sts.mx_entries and mx_servers:
                _mta_sts_uncovered_fqdns = [
                    mx.fqdn for mx in mx_servers
                    if not any(fnmatch.fnmatch(mx.fqdn, pat) for pat in mta_sts.mx_entries)
                ]
                if _mta_sts_uncovered_fqdns:
                    _n = len(_mta_sts_uncovered_fqdns)
                    points += 8
                    findings.append(EmailFinding(
                        code="MTA_STS_MX_NOT_COVERED", severity="MEDIUM",
                        title=f"{_n} MX-Server nicht in MTA-STS-Policy abgedeckt",
                        detail=f"Die Policy-Datei kennt folgende MX-Hosts nicht: "
                               f"{', '.join(_mta_sts_uncovered_fqdns[:3])}{'…' if _n > 3 else ''}. "
                               f"TLS-Enforcement gilt nur für in der Policy gelistete Hosts.",
                        remediation="Aktualisieren Sie die MTA-STS-Policy-Datei und erhöhen Sie die version-ID, "
                                    "damit sendende Server die neue Policy abrufen.",
                    ))

        if not mta_sts.tls_rpt_present:
            findings.append(EmailFinding(
                code="TLS_RPT_MISSING", severity="INFO",
                title="TLS-RPT nicht konfiguriert",
                detail="Ohne _smtp._tls TXT-Record erhalten Sie keine Berichte über TLS-Verbindungsfehler bei eingehenden Mails.",
                remediation='Erstellen Sie: _smtp._tls.<domain> TXT "v=TLSRPTv1; rua=mailto:tls-rpt@ihre-domain.com"',
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
        spf_uncovered_ips=_spf_uncovered_ips,
        mta_sts_uncovered_fqdns=_mta_sts_uncovered_fqdns,
        dkim_missing_providers=_dkim_missing_providers,
        rua_external_domains=_rua_external_domains,
    )
