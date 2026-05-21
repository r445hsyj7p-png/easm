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
