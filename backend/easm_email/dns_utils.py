"""Shared DNS utilities for the easm_email package."""
from __future__ import annotations

import dns.resolver
import dns.exception

PUBLIC_RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]


def make_resolver(timeout: float = 5.0) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = PUBLIC_RESOLVERS
    r.timeout = timeout
    r.lifetime = timeout * 2
    return r


def query_txt(resolver: dns.resolver.Resolver, name: str) -> list[str]:
    """Resolve TXT records, joining multi-string responses per RFC 7208 §3.3."""
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
