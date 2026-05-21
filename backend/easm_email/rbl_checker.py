"""
RBL checker — Spamhaus ZEN via DNS.
Results cached in Redis (6 h) to respect rate limits.
IPv4 and IPv6 supported.
"""
from __future__ import annotations
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

import dns.resolver
import dns.exception
import dns.reversename

log = logging.getLogger(__name__)

_PUBLIC_RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]
_REDIS_TTL = 6 * 3600
_REDIS_PREFIX = "rbl:zen:"

# Spamhaus ZEN return codes — https://www.spamhaus.org/faq/section/DNSBL%20Usage#200
_ZEN_CODES: dict[str, tuple[str, str, str]] = {
    "127.0.0.2":  ("SBL",      "HIGH",     "Spamhaus Block List — bekannte Spam-Quelle"),
    "127.0.0.3":  ("SBL-CSS",  "HIGH",     "Spamhaus CSS — Spam-Infrastructure"),
    "127.0.0.4":  ("XBL",      "CRITICAL", "Exploits Block List — kompromittierter Host / Botnet"),
    "127.0.0.5":  ("XBL",      "CRITICAL", "Exploits Block List — Malware/Proxy"),
    "127.0.0.6":  ("XBL",      "CRITICAL", "Exploits Block List — Malware/Proxy"),
    "127.0.0.7":  ("XBL",      "CRITICAL", "Exploits Block List — Malware/Proxy"),
    "127.0.0.9":  ("SBL-DROP", "CRITICAL", "DROP List — IP-Bereich an Cyberkriminelle vergeben"),
    "127.0.0.10": ("PBL-ISP",  "INFO",     "Policy Block List — ISP-Policy (Endkunden-IP, kein direktes SMTP erwartet)"),
    "127.0.0.11": ("PBL",      "INFO",     "Policy Block List — dynamische / Endkunden-IP"),
}


@dataclass
class RblHit:
    ip: str
    list_name: str    # SBL | XBL | PBL-ISP | ...
    severity: str     # CRITICAL | HIGH | INFO
    description: str
    return_code: str


def _make_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = _PUBLIC_RESOLVERS
    r.timeout = 3.0
    r.lifetime = 5.0
    return r


def _redis_client():
    try:
        import redis as redis_lib
        client = redis_lib.Redis.from_url(
            os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            socket_connect_timeout=1,
        )
        client.ping()
        return client
    except Exception:
        return None


def _build_zen_query(ip: str) -> str:
    """Build the Spamhaus ZEN query name for IPv4 or IPv6."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            rev = ".".join(reversed(ip.split(".")))
            return f"{rev}.zen.spamhaus.org"
        else:
            # IPv6: expand to full hex, remove colons, reverse nibbles
            exploded = addr.exploded.replace(":", "")
            rev = ".".join(reversed(exploded))
            return f"{rev}.zen.spamhaus.org"
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip!r}")


def _lookup_zen(ip: str) -> list[RblHit]:
    """Check a single IP against Spamhaus ZEN with Redis caching."""
    rdb = _redis_client()
    cache_key = f"{_REDIS_PREFIX}{ip}"

    if rdb:
        try:
            cached = rdb.get(cache_key)
            if cached is not None:
                return [RblHit(**h) for h in json.loads(cached)]
        except Exception:
            pass

    hits: list[RblHit] = []
    try:
        query_name = _build_zen_query(ip)
        resolver = _make_resolver()
        try:
            answers = resolver.resolve(query_name, "A")
            for rdata in answers:
                code = str(rdata)
                if code in _ZEN_CODES:
                    list_name, severity, desc = _ZEN_CODES[code]
                    hits.append(RblHit(
                        ip=ip, list_name=list_name,
                        severity=severity, description=desc, return_code=code,
                    ))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass  # Clean — not listed
    except Exception as e:
        log.debug("[rbl] ZEN lookup failed for %s: %s", ip, e)

    if rdb:
        try:
            rdb.setex(cache_key, _REDIS_TTL, json.dumps([vars(h) for h in hits]))
        except Exception:
            pass

    return hits


def check_ips(ips: list[str]) -> list[RblHit]:
    """Check all IPs against Spamhaus ZEN. Returns only actual hits (PBL excluded from score)."""
    if not ips:
        return []
    unique = list(dict.fromkeys(ips))
    all_hits: list[RblHit] = []
    with ThreadPoolExecutor(max_workers=min(len(unique), 8)) as pool:
        futures = {pool.submit(_lookup_zen, ip): ip for ip in unique}
        for fut in as_completed(futures):
            try:
                all_hits.extend(fut.result())
            except Exception as e:
                log.debug("[rbl] check_ips error: %s", e)
    return all_hits
