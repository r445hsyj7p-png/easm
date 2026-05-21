"""
MX record analyzer — resolves exchanges to A/AAAA + PTR.
Public DNS only. No port probing.
"""
from __future__ import annotations
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import dns.resolver
import dns.reversename
import dns.exception

from .dns_collector import MxRecord

log = logging.getLogger(__name__)

_PUBLIC_RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
_MAX_MX_WORKERS = 8


@dataclass
class ResolvedIP:
    address: str
    version: int   # 4 or 6
    ptr: str | None = None


@dataclass
class MxServerInfo:
    fqdn: str
    priority: int
    ips: list[ResolvedIP] = field(default_factory=list)


def _make_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = _PUBLIC_RESOLVERS
    r.timeout = 5.0
    r.lifetime = 10.0
    return r


def _ptr(resolver: dns.resolver.Resolver, ip: str) -> str | None:
    try:
        rev = dns.reversename.from_address(ip)
        answers = resolver.resolve(rev, "PTR")
        return str(answers[0]).rstrip(".")
    except dns.exception.DNSException:
        return None


def _resolve_host(resolver: dns.resolver.Resolver, fqdn: str) -> list[ResolvedIP]:
    raw: list[tuple[str, int]] = []
    for qtype, version in [("A", 4), ("AAAA", 6)]:
        try:
            for rdata in resolver.resolve(fqdn, qtype):
                raw.append((str(rdata), version))
        except dns.exception.DNSException:
            pass

    if not raw:
        return []

    # PTR lookups in parallel (one thread per IP address)
    results: list[ResolvedIP] = [ResolvedIP(addr, ver) for addr, ver in raw]
    with ThreadPoolExecutor(max_workers=len(raw)) as pool:
        futures = {pool.submit(_ptr, resolver, addr): i for i, (addr, _) in enumerate(raw)}
        for fut in as_completed(futures):
            results[futures[fut]].ptr = fut.result()
    return results


def _resolve_one(mx: MxRecord) -> MxServerInfo:
    resolver = _make_resolver()
    return MxServerInfo(fqdn=mx.fqdn, priority=mx.priority, ips=_resolve_host(resolver, mx.fqdn))


def analyze(mx_records: list[MxRecord]) -> list[MxServerInfo]:
    if not mx_records:
        return []
    workers = min(len(mx_records), _MAX_MX_WORKERS)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_resolve_one, mx): mx for mx in mx_records}
        return [fut.result() for fut in as_completed(futures)]
