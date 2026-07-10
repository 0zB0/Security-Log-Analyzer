from datetime import datetime

from pydantic import BaseModel, Field

from tracehawk_api.models.domain import Finding, Incident
from tracehawk_api.services.analysis import AnalysisResult, EvidenceLine


class ReportRedactionOptions(BaseModel):
    enabled: bool = False
    mask_ips: bool = True
    mask_users: bool = True
    mask_hosts: bool = True


class ReportRequest(BaseModel):
    incident: Incident
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[EvidenceLine] = Field(default_factory=list)
    assistant_summary: str | None = None
    redaction: ReportRedactionOptions = Field(default_factory=ReportRedactionOptions)


class ReportResponse(BaseModel):
    format: str = "markdown"
    filename: str
    content: str
    created_at: datetime


class CaseReportRequest(BaseModel):
    analysis: AnalysisResult
    assistant_summary: str | None = None
    redaction: ReportRedactionOptions = Field(default_factory=ReportRedactionOptions)
