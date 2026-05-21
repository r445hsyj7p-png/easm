"""
MTA-STS (RFC 8461) and TLS-RPT (RFC 8460) checker.
DNS lookup + HTTPS policy fetch (5 s timeout, non-fatal).
"""
from __future__ import annotations
import logging
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

from .dns_utils import make_resolver as _make_resolver, query_txt as _query_txt


@dataclass
class MtaStsResult:
    dns_declared: bool = False      # _mta-sts TXT record present
    mode: str | None = None         # enforce | testing | none
    max_age: int | None = None
    mx_entries: list[str] = field(default_factory=list)
    policy_reachable: bool = False  # HTTPS policy file was accessible
    policy_error: str | None = None
    tls_rpt_present: bool = False   # _smtp._tls TXT record present


def _fetch_policy(domain: str) -> tuple[str | None, str | None]:
    """Fetch the MTA-STS policy file over HTTPS. Returns (text, error)."""
    try:
        import httpx
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        resp = httpx.get(
            url, timeout=5.0, follow_redirects=True,
            headers={"User-Agent": "EASM-MTA-STS-Checker/1.0"},
        )
        if resp.status_code == 200:
            return resp.text, None
        return None, f"HTTP {resp.status_code}"
    except Exception as e:
        return None, str(e)[:150]


def _parse_policy(text: str) -> tuple[str | None, int | None, list[str]]:
    """Return (mode, max_age, mx_entries) from mta-sts.txt content."""
    mode: str | None = None
    max_age: int | None = None
    mx_entries: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("mode:"):
            mode = line.split(":", 1)[1].strip()
        elif line.startswith("max_age:"):
            try:
                max_age = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith("mx:"):
            mx_entries.append(line.split(":", 1)[1].strip())
    return mode, max_age, mx_entries


def check(domain: str) -> MtaStsResult:
    result = MtaStsResult()
    resolver = _make_resolver()

    # TLS-RPT: _smtp._tls.<domain>
    tls_rpt_txts = _query_txt(resolver, f"_smtp._tls.{domain}")
    result.tls_rpt_present = any(t.startswith("v=TLSRPTv1") for t in tls_rpt_txts)

    # MTA-STS DNS: _mta-sts.<domain>
    sts_txts = _query_txt(resolver, f"_mta-sts.{domain}")
    result.dns_declared = any(t.startswith("v=STSv1") for t in sts_txts)

    if not result.dns_declared:
        return result

    # Fetch policy file via HTTPS — non-fatal
    policy_text, error = _fetch_policy(domain)
    if policy_text:
        result.policy_reachable = True
        result.mode, result.max_age, result.mx_entries = _parse_policy(policy_text)
    else:
        result.policy_reachable = False
        result.policy_error = error

    return result
