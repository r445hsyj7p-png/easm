"""
DNS collection layer — public resolvers only.
Fetches SPF (TXT), DMARC (_dmarc TXT), and MX records.
No HTTP calls. No intrusive probing.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass, field

import dns.resolver
import dns.exception

log = logging.getLogger(__name__)

_PUBLIC_RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]


@dataclass
class MxRecord:
    fqdn: str
    priority: int


@dataclass
class DnsBundle:
    domain: str
    spf_raw: str | None = None
    dmarc_raw: str | None = None
    mx_records: list[MxRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _make_resolver(timeout: float = 5.0) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = _PUBLIC_RESOLVERS
    r.timeout = timeout
    r.lifetime = timeout * 2
    return r


def _query_txt(resolver: dns.resolver.Resolver, name: str) -> list[str]:
    """Return all TXT records for name, joining multi-string records per RFC 7208 §3.3."""
    try:
        answers = resolver.resolve(name, "TXT")
        results = []
        for rdata in answers:
            parts = [
                s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                for s in rdata.strings
            ]
            results.append("".join(parts))
        return results
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return []


def collect(domain: str) -> DnsBundle:
    """Collect all email-relevant DNS records for a domain."""
    domain = domain.strip().lower()
    bundle = DnsBundle(domain=domain)
    resolver = _make_resolver()

    # SPF lives in TXT records
    txts = _query_txt(resolver, domain)
    spf_candidates = [t for t in txts if t.startswith("v=spf1")]
    if len(spf_candidates) > 1:
        bundle.errors.append(
            f"MULTIPLE_SPF_RECORDS: {len(spf_candidates)} found (RFC violation — first record used)"
        )
    if spf_candidates:
        bundle.spf_raw = spf_candidates[0]

    # DMARC
    dmarc_txts = _query_txt(resolver, f"_dmarc.{domain}")
    dmarc_candidates = [t for t in dmarc_txts if t.startswith("v=DMARC1")]
    if dmarc_candidates:
        bundle.dmarc_raw = dmarc_candidates[0]

    # MX
    try:
        answers = resolver.resolve(domain, "MX")
        for rdata in answers:
            bundle.mx_records.append(
                MxRecord(fqdn=str(rdata.exchange).rstrip("."), priority=rdata.preference)
            )
        bundle.mx_records.sort(key=lambda m: m.priority)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException) as e:
        log.debug("MX lookup failed for %s: %s", domain, e)

    return bundle
