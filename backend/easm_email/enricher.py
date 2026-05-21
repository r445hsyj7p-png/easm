"""
IP enrichment — ASN lookup via Team Cymru DNS service + provider classification.
Entirely DNS-based. Zero HTTP calls.

Team Cymru DNS lookup format:
  IPv4: {reversed_octets}.origin.asn.cymru.com TXT
  IPv6: {reversed_nibbles}.origin6.asn.cymru.com TXT
  Response: "15169 | 8.8.8.0/24 | US | arin | 2000-03-30"
"""
from __future__ import annotations
import ipaddress
import logging
from dataclasses import dataclass

import dns.resolver
import dns.exception

from .provider_registry import classify_ip, ProviderEntry

log = logging.getLogger(__name__)

_PUBLIC_RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]


@dataclass
class AsnInfo:
    number: str    # e.g. "15169"
    name: str
    country: str
    cidr: str


@dataclass
class EnrichedIP:
    address: str
    version: int
    ptr: str | None
    asn: AsnInfo | None
    provider_name: str
    provider_category: str


def _make_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = _PUBLIC_RESOLVERS
    r.timeout = 5.0
    r.lifetime = 10.0
    return r


def _cymru_lookup(resolver: dns.resolver.Resolver, ip: str, version: int) -> AsnInfo | None:
    try:
        if version == 4:
            reversed_ip = ".".join(reversed(ip.split(".")))
            query_name = f"{reversed_ip}.origin.asn.cymru.com"
        else:
            expanded = ipaddress.ip_address(ip).exploded.replace(":", "")
            reversed_nibbles = ".".join(reversed(expanded))
            query_name = f"{reversed_nibbles}.origin6.asn.cymru.com"

        answers = resolver.resolve(query_name, "TXT")
        for rdata in answers:
            parts = [
                s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                for s in rdata.strings
            ]
            txt = "".join(parts)
            # "15169 | 8.8.8.0/24 | US | arin | 2000-03-30"
            fields = [f.strip() for f in txt.split("|")]
            if len(fields) >= 3:
                asn_num = fields[0].strip()
                cidr = fields[1].strip()
                country = fields[2].strip()
                asn_name = _cymru_asn_name(resolver, asn_num) or asn_num
                return AsnInfo(number=asn_num, name=asn_name, country=country, cidr=cidr)
    except dns.exception.DNSException:
        pass
    return None


def _cymru_asn_name(resolver: dns.resolver.Resolver, asn: str) -> str | None:
    try:
        answers = resolver.resolve(f"AS{asn}.asn.cymru.com", "TXT")
        for rdata in answers:
            parts = [
                s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                for s in rdata.strings
            ]
            txt = "".join(parts)
            # "15169 | US | arin | 1992-12-01 | GOOGLE, US"
            fields = [f.strip() for f in txt.split("|")]
            if len(fields) >= 5:
                return fields[4].strip()
    except dns.exception.DNSException:
        pass
    return None


def enrich_ip_list(ips: list[tuple[str, int, str | None]]) -> list[EnrichedIP]:
    """
    Enrich a list of (address, version, ptr) tuples.
    De-duplicates by address before enriching.
    """
    resolver = _make_resolver()
    seen: set[str] = set()
    results: list[EnrichedIP] = []

    for address, version, ptr in ips:
        if address in seen:
            continue
        seen.add(address)

        asn = _cymru_lookup(resolver, address, version)
        provider = classify_ip(address, ptr)

        results.append(EnrichedIP(
            address=address,
            version=version,
            ptr=ptr,
            asn=asn,
            provider_name=provider.name if provider else "Unknown",
            provider_category=provider.category if provider else "unknown",
        ))

    return results
