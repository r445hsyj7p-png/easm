"""
Known email provider registry — CIDR ranges and PTR suffixes.
Used by the enricher to classify IPs to named providers.
No network I/O — pure in-memory lookup.
"""
from __future__ import annotations
from typing import NamedTuple


class ProviderEntry(NamedTuple):
    name: str
    category: str  # email_saas | cloud | security | cdn | unknown
    cidrs: list[str]
    ptr_suffixes: list[str]


PROVIDERS: list[ProviderEntry] = [
    ProviderEntry(
        "SendGrid", "email_saas",
        ["167.89.0.0/17", "198.37.144.0/20", "199.89.0.0/17",
         "208.115.214.0/22", "208.117.48.0/20", "69.162.98.0/24"],
        ["sendgrid.net", "sendgrid.com"],
    ),
    ProviderEntry(
        "Mailgun", "email_saas",
        ["198.61.254.0/23", "69.72.43.0/24", "104.130.122.0/23"],
        ["mailgun.org", "mailgun.net", "mailgun.info"],
    ),
    ProviderEntry(
        "Amazon SES", "cloud",
        [],
        ["amazonaws.com", "amazonses.com", "aws.com"],
    ),
    ProviderEntry(
        "Google Workspace", "email_saas",
        ["209.85.128.0/17", "66.102.0.0/20", "74.125.0.0/16",
         "64.233.160.0/19", "66.249.80.0/20", "72.14.192.0/18",
         "108.177.8.0/21", "216.239.32.0/19", "173.194.0.0/16"],
        ["google.com", "googlemail.com", "gmail.com", "googleusercontent.com"],
    ),
    ProviderEntry(
        "Microsoft 365", "email_saas",
        ["40.92.0.0/15", "40.107.0.0/16", "52.100.0.0/14", "104.47.0.0/17"],
        ["outlook.com", "hotmail.com", "protection.outlook.com",
         "microsoft.com", "office365.com", "msn.com"],
    ),
    ProviderEntry(
        "Proofpoint", "security",
        ["148.163.0.0/16", "67.231.144.0/20", "67.231.152.0/24"],
        ["pphosted.com", "proofpoint.com", "ppe-hosted.com"],
    ),
    ProviderEntry(
        "Mimecast", "security",
        [],
        ["mimecast.com", "mimecastprotect.com"],
    ),
    ProviderEntry(
        # 148.163.0.0/16 is MessageBird/SparkPost — do NOT duplicate in Mailchimp
        "SparkPost", "email_saas",
        ["148.163.0.0/16"],
        ["sparkpostmail.com", "sparkpost.com", "messagebird.com"],
    ),
    ProviderEntry(
        "Postmark", "email_saas",
        [],
        ["mtasv.net", "postmarkapp.com"],
    ),
    ProviderEntry(
        # 148.163.0.0/16 belongs to SparkPost/MessageBird — excluded here
        "Mailchimp / Mandrill", "email_saas",
        ["198.2.128.0/18", "198.2.176.0/20"],
        ["mcsv.net", "mailchimp.com", "mandrill.com", "mandrillapp.com"],
    ),
    ProviderEntry(
        "Zoho Mail", "email_saas",
        ["136.143.188.0/24", "136.143.189.0/24"],
        ["zoho.com", "zohocorp.com", "zohomail.com"],
    ),
    ProviderEntry(
        "Cloudflare", "cdn",
        ["103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
         "104.16.0.0/12", "108.162.192.0/18", "131.0.72.0/22",
         "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13",
         "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20",
         "197.234.240.0/22", "198.41.128.0/17"],
        ["cloudflare.com", "cloudflare.net", "cf-dns.net"],
    ),
    ProviderEntry(
        "Barracuda", "security",
        [],
        ["barracudanetworks.com", "cudamail.com"],
    ),
    ProviderEntry(
        "Cisco IronPort", "security",
        [],
        ["iphmx.com", "cisco.com"],
    ),
]

# Pre-build IP sets for O(1) CIDR membership testing
try:
    from netaddr import IPSet, IPAddress as _IPAddress

    _cidr_map: list[tuple[object, ProviderEntry]] = []
    for _entry in PROVIDERS:
        if _entry.cidrs:
            try:
                _cidr_map.append((IPSet(_entry.cidrs), _entry))
            except Exception:
                pass
    _HAS_NETADDR = True
except ImportError:
    _cidr_map = []
    _HAS_NETADDR = False


def classify_ip(ip: str, ptr: str | None = None) -> ProviderEntry | None:
    """Return the best matching ProviderEntry for an IP, or None."""
    if _HAS_NETADDR:
        try:
            from netaddr import IPAddress
            addr = IPAddress(ip)
            for ip_set, entry in _cidr_map:
                if addr in ip_set:
                    return entry
        except Exception:
            pass

    if ptr:
        ptr_lower = ptr.rstrip(".").lower()
        for entry in PROVIDERS:
            for suffix in entry.ptr_suffixes:
                if ptr_lower == suffix or ptr_lower.endswith("." + suffix):
                    return entry

    return None
