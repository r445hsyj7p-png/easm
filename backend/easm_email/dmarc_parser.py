"""DMARC record parser — RFC 7489."""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class DmarcPolicy:
    raw: str | None
    present: bool = False
    p: str = "none"          # none | quarantine | reject
    sp: str | None = None    # subdomain policy
    pct: int = 100           # enforcement percentage
    rua: list[str] = field(default_factory=list)
    ruf: list[str] = field(default_factory=list)
    adkim: str = "r"         # r = relaxed, s = strict (DKIM alignment)
    aspf: str = "r"          # r = relaxed, s = strict (SPF alignment)
    fo: str = "0"
    valid: bool = False
    parse_errors: list[str] = field(default_factory=list)

    @property
    def policy_strength(self) -> int:
        """0=absent, 1=none, 2=quarantine, 3=reject."""
        if not self.present:
            return 0
        return {"none": 1, "quarantine": 2, "reject": 3}.get(self.p, 1)


def parse(dmarc_raw: str | None) -> DmarcPolicy:
    if not dmarc_raw:
        return DmarcPolicy(raw=None, present=False)

    policy = DmarcPolicy(raw=dmarc_raw, present=True)

    if not dmarc_raw.startswith("v=DMARC1"):
        policy.parse_errors.append("Record does not start with v=DMARC1")
        return policy

    for tag in dmarc_raw.split(";"):
        tag = tag.strip()
        if "=" not in tag:
            continue
        key, _, value = tag.partition("=")
        key = key.strip().lower()
        value = value.strip()

        if key == "p":
            policy.p = value.lower() if value.lower() in ("none", "quarantine", "reject") else "none"
        elif key == "sp":
            sp_val = value.lower()
            policy.sp = sp_val if sp_val in ("none", "quarantine", "reject") else None
        elif key == "pct":
            try:
                policy.pct = max(0, min(100, int(value)))
            except ValueError:
                policy.parse_errors.append(f"Invalid pct value: {value!r}")
        elif key == "rua":
            policy.rua = [u.strip() for u in value.split(",") if u.strip()]
        elif key == "ruf":
            policy.ruf = [u.strip() for u in value.split(",") if u.strip()]
        elif key == "adkim":
            policy.adkim = value.lower() if value.lower() in ("r", "s") else "r"
        elif key == "aspf":
            policy.aspf = value.lower() if value.lower() in ("r", "s") else "r"
        elif key == "fo":
            policy.fo = value

    policy.valid = True
    return policy
