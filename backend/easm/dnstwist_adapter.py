"""
dnstwist adapter — wraps the dnstwist library to produce ToolFindings.

dnstwist generates permutations of a domain (homoglyphs, bitsquatting,
hyphenation, TLD swaps, vowel swaps, …) and resolves each one via DNS.
Only permutations that are *registered and resolvable* (have at least one
real A/AAAA record) are surfaced as findings.

Severity:
  HIGH   — domain has MX records (can receive mail → phishing / BEC risk)
  MEDIUM — domain is registered but has no MX
"""
from __future__ import annotations

import datetime
import hashlib
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from easm.tool_adapters import ToolFinding

log = logging.getLogger(__name__)

# dnstwist signals DNS errors with a leading "!" in the record value.
_DNS_ERROR_PREFIX = "!"


def _is_real_ip(record: str) -> bool:
    return bool(record) and not record.startswith(_DNS_ERROR_PREFIX)


def _real_ips(entry: dict, key: str) -> list[str]:
    return [r for r in entry.get(key, []) if _is_real_ip(r)]


def _severity(entry: dict) -> str:
    """HIGH if the lookalike domain accepts mail, MEDIUM if just registered."""
    return "HIGH" if _real_ips(entry, "dns_mx") else "MEDIUM"


def _description(entry: dict) -> str:
    fuzzer = entry.get("fuzzer", "unknown")
    ips    = ", ".join(_real_ips(entry, "dns_a") + _real_ips(entry, "dns_aaaa"))
    mx     = ", ".join(_real_ips(entry, "dns_mx"))
    parts  = [f"Fuzzer: {fuzzer}", f"IP(s): {ips or '—'}"]
    if mx:
        parts.append(f"MX: {mx}")
    return " | ".join(parts)


def run(tenant_id: str, domain: str, timeout: int = 120) -> list["ToolFinding"]:
    """
    Run dnstwist against *domain* and return a list of ToolFindings.

    Falls back gracefully to an empty list when dnstwist is not installed
    or the scan fails.
    """
    try:
        import dnstwist  # noqa: PLC0415 — optional dependency
    except ModuleNotFoundError:
        log.warning("[dnstwist] package not installed — skipping typosquat phase")
        return []

    # ToolFinding import deferred to avoid circular imports at module level.
    from easm.tool_adapters import ToolFinding  # noqa: PLC0415

    log.info("[dnstwist] scanning %s (timeout=%ds)", domain, timeout)

    def _run_dnstwist() -> list[dict]:
        """Run dnstwist in a worker thread; stdout redirect stays local to this thread
        context, avoiding interference with other concurrently running threads."""
        import io, sys as _sys  # noqa: PLC0415
        buf = io.StringIO()
        old_stdout = _sys.stdout
        _sys.stdout = buf
        try:
            result = dnstwist.run(domain=domain, registered=True, format="json", threads=8)
        finally:
            _sys.stdout = old_stdout
        return result if isinstance(result, list) else []

    try:
        from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FutTimeout  # noqa: PLC0415
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_run_dnstwist)
            try:
                results: list[dict] = future.result(timeout=timeout)
            except _FutTimeout:
                log.warning("[dnstwist] scan timed out after %ds for %s", timeout, domain)
                return []
    except Exception as exc:
        log.error("[dnstwist] scan failed for %s: %s", domain, exc)
        return []

    findings: list[ToolFinding] = []
    seen: set[str] = set()

    for entry in results:
        lookalike = entry.get("domain", "")
        if not lookalike or lookalike == domain:
            continue

        # Only surface domains with at least one resolvable A/AAAA record.
        # Entries that only have error-prefixed records (!NXDOMAIN, !ServFail)
        # are not confirmed as registered.
        if not _real_ips(entry, "dns_a") and not _real_ips(entry, "dns_aaaa"):
            continue

        if lookalike in seen:
            continue
        seen.add(lookalike)

        sev = _severity(entry)
        title = (
            f"Typosquat: {lookalike} hat MX-Records (Phishing-Risiko)"
            if sev == "HIGH"
            else f"Typosquat: {lookalike} ist registriert"
        )
        fp = hashlib.sha256(
            f"dnstwist:typosquat:{domain}:{lookalike}".encode()
        ).hexdigest()[:16]

        findings.append(ToolFinding(
            tenant_id=tenant_id,
            tool="dnstwist",
            category="typosquat",
            severity=sev,
            title=title,
            description=_description(entry),
            affected_asset=lookalike,
            remediation=(
                "Domain überwachen oder defensiv registrieren. "
                "Bei aktivem Missbrauch: Abuse-Report an Registrar stellen."
            ),
            raw_data={
                "original_domain": domain,
                "lookalike_domain": lookalike,
                "fuzzer": entry.get("fuzzer"),
                "dns_a": _real_ips(entry, "dns_a"),
                "dns_aaaa": _real_ips(entry, "dns_aaaa"),
                "dns_mx": _real_ips(entry, "dns_mx"),
                "dns_ns": _real_ips(entry, "dns_ns"),
                "whois_created": entry.get("whois_created"),
                "ssdeep_score": entry.get("ssdeep_score"),
            },
            fingerprint=fp,
            discovered_at=datetime.datetime.utcnow().isoformat(),
        ))

    log.info("[dnstwist] %d active lookalike domains found for %s", len(findings), domain)
    return findings
