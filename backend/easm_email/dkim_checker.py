"""
DKIM selector brute-force discovery.
DNS-only. Checks ~20 common selectors in parallel.
Note: False negatives are expected for custom selectors.
"""
from __future__ import annotations
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

import dns.resolver
import dns.exception

log = logging.getLogger(__name__)

from .dns_utils import make_resolver as _make_resolver

_COMMON_SELECTORS = [
    "google", "google2",            # Google Workspace
    "selector1", "selector2",       # Microsoft 365
    "k1", "k2", "k3",               # Mailchimp / Klaviyo / Mandrill
    "s1", "s2",                     # SendGrid / generic
    "default", "mail", "smtp",      # Generic
    "dkim", "email", "mta",         # Generic
    "pm", "postmark",               # Postmark
    "mandrill",                     # Mandrill
    "mailjet",                      # Mailjet
    "amazonses",                    # Amazon SES
]

# Base64 length thresholds for RSA key-size estimation.
# RSA 1024 → SubjectPublicKeyInfo DER ~162 bytes → base64 ~216 chars
# RSA 2048 → DER ~294 bytes → base64 ~392 chars
# RSA 4096 → DER ~550 bytes → base64 ~736 chars
# Ed25519  → DER ~44 bytes  → base64 ~44 chars
_B64_RSA2048_MIN = 300


@dataclass
class DkimResult:
    selector: str
    domain: str
    key_type: str               # rsa | ed25519 | unknown
    key_bits_estimate: int | None
    raw: str
    weak: bool                  # RSA < 2048-bit or revoked (p= empty)
    revoked: bool               # p= is empty → key revoked


def _check_selector(selector: str, domain: str) -> DkimResult | None:
    resolver = _make_resolver()
    name = f"{selector}._domainkey.{domain}"
    try:
        answers = resolver.resolve(name, "TXT")
        for rdata in answers:
            parts = [
                s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                for s in rdata.strings
            ]
            txt = "".join(parts)
            # Must look like a DKIM record
            if "v=DKIM1" not in txt and "k=" not in txt and "p=" not in txt:
                continue
            return _parse_record(selector, domain, txt)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    return None


def _parse_record(selector: str, domain: str, raw: str) -> DkimResult:
    tags: dict[str, str] = {}
    for part in raw.replace("; ", ";").replace(" ;", ";").split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()

    key_type = tags.get("k", "rsa").lower()
    p_clean = tags.get("p", "").replace(" ", "").replace("\t", "")

    if key_type == "ed25519":
        # Empty p= signals revocation for all key types per RFC 6376 §3.5
        if not p_clean:
            return DkimResult(
                selector=selector, domain=domain,
                key_type="ed25519", key_bits_estimate=None,
                raw=raw, weak=True, revoked=True,
            )
        return DkimResult(
            selector=selector, domain=domain,
            key_type="ed25519", key_bits_estimate=None,
            raw=raw, weak=False, revoked=False,
        )

    # RSA
    if not p_clean:
        # Empty p= means key has been revoked per RFC 6376 §3.5
        return DkimResult(
            selector=selector, domain=domain,
            key_type="rsa", key_bits_estimate=0,
            raw=raw, weak=True, revoked=True,
        )

    b64_len = len(p_clean)
    weak = b64_len < _B64_RSA2048_MIN
    # Approximate bit count: base64 → raw bytes (~b64_len*3/4), then subtract DER overhead (~38 bytes)
    decoded_bytes = b64_len * 3 // 4
    bits = max(512, (decoded_bytes - 38) * 8) if decoded_bytes > 38 else None

    return DkimResult(
        selector=selector, domain=domain,
        key_type="rsa", key_bits_estimate=bits,
        raw=raw, weak=weak, revoked=False,
    )


def discover(domain: str, extra_selectors: list[str] | None = None) -> list[DkimResult]:
    """
    Check all common selectors in parallel.
    Returns only found (published) records.
    Custom/unknown selectors will NOT be found — caller should note this in findings.
    """
    selectors = list(_COMMON_SELECTORS)
    if extra_selectors:
        for s in extra_selectors:
            if s not in selectors:
                selectors.append(s)

    found: list[DkimResult] = []
    with ThreadPoolExecutor(max_workers=min(len(selectors), 12)) as pool:
        futures = {pool.submit(_check_selector, sel, domain): sel for sel in selectors}
        for fut in as_completed(futures):
            try:
                result = fut.result()
                if result is not None:
                    found.append(result)
            except Exception as e:
                log.debug("[dkim] selector check failed for %s/%s: %s", futures[fut], domain, e)

    return sorted(found, key=lambda r: r.selector)
