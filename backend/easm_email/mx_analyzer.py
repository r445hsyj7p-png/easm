"""
MX record analyzer — resolves exchanges to A/AAAA + PTR.
Public DNS only. No port probing.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass, field

import dns.resolver
import dns.reversename
import dns.exception

from .dns_collector import MxRecord

log = logging.getLogger(__name__)

_PUBLIC_RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]


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
    ips: list[ResolvedIP] = []
    for qtype, version in [("A", 4), ("AAAA", 6)]:
        try:
            answers = resolver.resolve(fqdn, qtype)
            for rdata in answers:
                addr = str(rdata)
                ips.append(ResolvedIP(address=addr, version=version, ptr=_ptr(resolver, addr)))
        except dns.exception.DNSException:
            pass
    return ips


def analyze(mx_records: list[MxRecord]) -> list[MxServerInfo]:
    resolver = _make_resolver()
    return [
        MxServerInfo(fqdn=mx.fqdn, priority=mx.priority, ips=_resolve_host(resolver, mx.fqdn))
        for mx in mx_records
    ]
