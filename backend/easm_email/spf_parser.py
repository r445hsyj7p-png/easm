"""
SPF record parser — RFC 7208 compliant recursive resolution.

Enforces:
- 10-lookup DNS limit (RFC 7208 §4.6.4)
- MAX_DEPTH hard cap against infinite include chains
- Cycle detection via visited-domain set
"""
from __future__ import annotations
import logging
from dataclasses import dataclass, field

import dns.resolver
import dns.exception

log = logging.getLogger(__name__)

_PUBLIC_RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
MAX_DNS_LOOKUPS = 10
MAX_DEPTH = 10


@dataclass
class SpfMechanism:
    type: str          # include|ip4|ip6|a|mx|redirect|all|exists|ptr
    qualifier: str     # +|-|~|?
    value: str | None = None
    dns_lookup: bool = False  # consumes a DNS lookup per RFC 7208 §4.6.4


@dataclass
class SpfNode:
    domain: str
    raw: str | None
    mechanisms: list[SpfMechanism] = field(default_factory=list)
    children: list["SpfNode"] = field(default_factory=list)
    depth: int = 0
    lookup_count: int = 0   # running DNS lookup total (shared counter snapshot)
    all_qualifier: str | None = None
    errors: list[str] = field(default_factory=list)
    is_redirect: bool = False


def _make_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = _PUBLIC_RESOLVERS
    r.timeout = 5.0
    r.lifetime = 10.0
    return r


def _fetch_spf_txt(resolver: dns.resolver.Resolver, domain: str) -> str | None:
    try:
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            parts = [
                s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                for s in rdata.strings
            ]
            txt = "".join(parts)
            if txt.startswith("v=spf1"):
                return txt
    except dns.exception.DNSException:
        pass
    return None


def _parse_mechanisms(raw: str) -> tuple[list[SpfMechanism], str | None]:
    """Tokenise a raw SPF string into mechanism objects."""
    mechanisms: list[SpfMechanism] = []
    all_qualifier: str | None = None

    if not raw or not raw.startswith("v=spf1"):
        return mechanisms, None

    for token in raw.split()[1:]:  # skip v=spf1
        qualifier = "+"
        if token and token[0] in "+-~?":
            qualifier = token[0]
            token = token[1:]

        tl = token.lower()

        if tl == "all":
            all_qualifier = qualifier
            mechanisms.append(SpfMechanism(type="all", qualifier=qualifier))
        elif tl.startswith("include:"):
            mechanisms.append(SpfMechanism(
                type="include", qualifier=qualifier, value=token[8:], dns_lookup=True
            ))
        elif tl.startswith("redirect="):
            mechanisms.append(SpfMechanism(
                type="redirect", qualifier=qualifier, value=token[9:], dns_lookup=True
            ))
        elif tl.startswith("ip4:"):
            mechanisms.append(SpfMechanism(type="ip4", qualifier=qualifier, value=token[4:]))
        elif tl.startswith("ip6:"):
            mechanisms.append(SpfMechanism(type="ip6", qualifier=qualifier, value=token[4:]))
        elif tl.startswith("a:") or tl == "a":
            mechanisms.append(SpfMechanism(
                type="a", qualifier=qualifier,
                value=token[2:] if ":" in token else None, dns_lookup=True,
            ))
        elif tl.startswith("mx:") or tl == "mx":
            mechanisms.append(SpfMechanism(
                type="mx", qualifier=qualifier,
                value=token[3:] if ":" in token else None, dns_lookup=True,
            ))
        elif tl.startswith("exists:"):
            mechanisms.append(SpfMechanism(
                type="exists", qualifier=qualifier, value=token[7:], dns_lookup=True
            ))
        elif tl.startswith("ptr:") or tl == "ptr":
            mechanisms.append(SpfMechanism(
                type="ptr", qualifier=qualifier,
                value=token[4:] if ":" in token else None, dns_lookup=True,
            ))

    return mechanisms, all_qualifier


def parse(domain: str, spf_raw: str | None = None) -> SpfNode:
    """Build a fully resolved SPF include tree starting at domain."""
    resolver = _make_resolver()
    lookup_counter: list[int] = [0]   # mutable shared counter
    visited: set[str] = set()
    return _parse_node(resolver, domain, spf_raw, 0, lookup_counter, visited)


def _parse_node(
    resolver: dns.resolver.Resolver,
    domain: str,
    raw: str | None,
    depth: int,
    lookup_counter: list[int],
    visited: set[str],
    is_redirect: bool = False,
) -> SpfNode:
    node = SpfNode(domain=domain, raw=raw, depth=depth, is_redirect=is_redirect)

    if domain in visited:
        node.errors.append(f"CYCLE_DETECTED: {domain} already visited in this chain")
        return node

    # Copy-on-enter: each branch gets its own view of the ancestor chain so
    # the same domain can legitimately appear in two independent sibling branches
    # without triggering a false-positive cycle detection.
    branch_visited = visited | {domain}

    if depth >= MAX_DEPTH:
        node.errors.append(f"MAX_DEPTH_REACHED at depth {depth}")
        return node

    if raw is None:
        raw = _fetch_spf_txt(resolver, domain)
        node.raw = raw

    if raw is None:
        node.errors.append(f"NO_SPF_RECORD for {domain}")
        return node

    mechanisms, all_qualifier = _parse_mechanisms(raw)
    node.mechanisms = mechanisms
    node.all_qualifier = all_qualifier

    for mech in mechanisms:
        if not mech.dns_lookup:
            continue

        if lookup_counter[0] >= MAX_DNS_LOOKUPS:
            node.errors.append(
                f"RFC_LOOKUP_LIMIT_REACHED: stopped before {mech.type}:{mech.value}"
            )
            break

        if mech.type == "include" and mech.value:
            lookup_counter[0] += 1
            child = _parse_node(
                resolver, mech.value, None, depth + 1, lookup_counter, branch_visited
            )
            node.children.append(child)

        elif mech.type == "redirect" and mech.value:
            lookup_counter[0] += 1
            child = _parse_node(
                resolver, mech.value, None, depth + 1, lookup_counter, branch_visited,
                is_redirect=True,
            )
            node.children.append(child)
            break  # redirect replaces the remainder of the record

        elif mech.type in ("a", "mx", "exists", "ptr"):
            # Count lookup but don't recurse — IPs handled by enricher
            lookup_counter[0] += 1

    node.lookup_count = lookup_counter[0]
    return node


def collect_all_includes(node: SpfNode, seen: set[str] | None = None) -> set[str]:
    """Flatten all unique include domains in the tree."""
    if seen is None:
        seen = set()
    for child in node.children:
        if child.domain not in seen:
            seen.add(child.domain)
            collect_all_includes(child, seen)
    return seen


def max_depth(node: SpfNode) -> int:
    if not node.children:
        return node.depth
    return max(max_depth(c) for c in node.children)


def count_includes(node: SpfNode) -> int:
    return len(node.children) + sum(count_includes(c) for c in node.children)
