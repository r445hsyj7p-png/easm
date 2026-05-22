"""Pydantic I/O schemas for the email intelligence module."""
from __future__ import annotations
import re
from pydantic import BaseModel, field_validator
from typing import Optional
from datetime import datetime


class AnalyzeRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower()
        # Strip protocol/path if user pastes a URL
        v = re.sub(r"^https?://", "", v).split("/")[0].split("?")[0].rstrip(".")
        if not re.match(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", v):
            raise ValueError(f"Invalid domain: {v!r}")
        return v


class EmailFinding(BaseModel):
    code: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    detail: str
    remediation: str


class GraphSummary(BaseModel):
    provider_count: int
    spf_depth: int
    spf_include_count: int
    spf_lookup_count: int
    mx_count: int
    ip_count: int
    asn_count: int
    dkim_selectors_found: int = 0
    dkim_weak_keys: int = 0
    rbl_listed_count: int = 0
    mta_sts_mode: Optional[str] = None
    tls_rpt_present: bool = False
    dnssec_signed: bool = False


class AnalyzeResponse(BaseModel):
    job_id: str
    status: str


class ResultResponse(BaseModel):
    job_id: str
    domain: str
    status: str
    risk_score: Optional[int] = None
    risk_band: Optional[str] = None
    findings: list[EmailFinding] = []
    graph_summary: Optional[GraphSummary] = None
    graph_json: Optional[dict] = None
    spf_raw: Optional[str] = None
    dmarc_raw: Optional[str] = None
    mx_records: list[dict] = []
    created_at: datetime
    completed_at: Optional[datetime] = None
    error: Optional[str] = None


class DomainListItem(BaseModel):
    job_id: str
    domain: str
    status: str
    risk_score: Optional[int] = None
    risk_band: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None


class DomainHistoryItem(BaseModel):
    job_id: str
    risk_score: int
    risk_band: str
    findings_count: int
    created_at: datetime


class EmailIntelSettings(BaseModel):
    auto_rescan_enabled: bool = False
    rescan_interval_days: int = 7


class BulkAnalyzeRequest(BaseModel):
    domains: list[str]

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("domains list is empty")
        validated = []
        for raw in v:
            d = raw.strip().lower()
            d = re.sub(r"^https?://", "", d).split("/")[0].split("?")[0].rstrip(".")
            if not re.match(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", d):
                raise ValueError(f"Invalid domain: {d!r}")
            validated.append(d)
        deduped = list(dict.fromkeys(validated))  # preserve order
        if len(deduped) > 20:
            raise ValueError("Maximum 20 unique domains per bulk request")
        return deduped


class BulkDomainStatus(BaseModel):
    domain: str
    job_id: Optional[str] = None
    status: str
    error: Optional[str] = None


class BulkAnalyzeResponse(BaseModel):
    results: list[BulkDomainStatus]
