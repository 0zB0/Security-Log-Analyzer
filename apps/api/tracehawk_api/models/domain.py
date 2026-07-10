from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]


class LogSource(BaseModel):
    id: str
    name: str
    source_type: Literal["upload", "file_watch", "folder_watch", "docker_logs", "interface_packets"]
    parser_type: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status: Literal["new", "active", "paused", "stopped", "error"] = "new"


class RawLogLine(BaseModel):
    id: str
    source_id: str
    line_number: int
    raw_text: str
    timestamp_observed: datetime = Field(default_factory=lambda: datetime.now(UTC))
    content_hash: str


class ParsedEvent(BaseModel):
    id: str
    source_id: str
    raw_line_id: str
    event_time: datetime | None = None
    event_type: str
    host: str | None = None
    service: str | None = None
    source_ip: str | None = None
    username: str | None = None
    message: str
    normalized_fields: dict[str, Any] = Field(default_factory=dict)


class RuleEvidencePolicy(BaseModel):
    include_matching_lines: bool = True
    max_lines: int = 20


class SequenceStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: str = Field(min_length=1)
    count_gte: int = Field(default=1, ge=1, le=1000)
    field_equals: dict[str, Any] = Field(default_factory=dict)
    field_in: dict[str, list[Any]] = Field(default_factory=dict)
    field_contains_any: dict[str, list[str]] = Field(default_factory=dict)


class RuleConditions(BaseModel):
    event_type: str | None = None
    group_by: list[str] = Field(default_factory=list)
    window_minutes: int = 10
    count_gte: int | None = None
    distinct_field: str | None = None
    distinct_count_gte: int | None = None
    periodic_count_gte: int | None = None
    periodic_jitter_seconds_lte: float | None = None
    periodic_interval_seconds_min: float | None = None
    periodic_interval_seconds_max: float | None = None
    sequence: list[SequenceStep] | None = Field(default=None, min_length=2, max_length=8)
    path_contains_any: list[str] | None = None
    field_equals: dict[str, Any] = Field(default_factory=dict)
    field_in: dict[str, list[Any]] = Field(default_factory=dict)
    field_contains_any: dict[str, list[str]] = Field(default_factory=dict)


class MitreMapping(BaseModel):
    tactic: str | None = None
    technique_id: str | None = None
    technique_name: str | None = None
    note: str | None = None


class DetectionRule(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    log_types: list[str]
    mitre: MitreMapping = Field(default_factory=MitreMapping)
    conditions: RuleConditions
    evidence: RuleEvidencePolicy = Field(default_factory=RuleEvidencePolicy)
    false_positives: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    id: str
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    summary: str
    reason: str
    mitre: MitreMapping
    first_seen: datetime
    last_seen: datetime
    event_count: int
    evidence_line_ids: list[str] = Field(default_factory=list)


class Incident(BaseModel):
    id: str
    title: str
    severity: Severity
    status: Literal["active", "investigating", "closed", "false_positive"] = "active"
    summary: str
    first_seen: datetime
    last_seen: datetime
    score: int
    finding_ids: list[str] = Field(default_factory=list)
    entities: list[str] = Field(default_factory=list)
    timeline: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    score_breakdown: dict[str, int] = Field(default_factory=dict)
    score_rationale: list[str] = Field(default_factory=list)


class Entity(BaseModel):
    id: str
    analysis_id: str | None = None
    entity_type: Literal["ip", "user", "host", "service", "path", "domain", "url", "container"]
    value: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    risk_score: int = 0
    event_count: int = 0
    source_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    incident_ids: list[str] = Field(default_factory=list)


class AnalystNote(BaseModel):
    id: str
    analysis_id: str
    incident_id: str
    body: str
    note_type: Literal["observation", "decision", "follow_up", "false_positive"] = "observation"
    author: str = "local"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AuditEvent(BaseModel):
    id: str
    occurred_at: datetime
    actor: str
    email: str | None = None
    role: Literal["viewer", "analyst", "admin", "anonymous"]
    auth_mode: str
    method: str
    path: str
    action: str
    status_code: int
    outcome: Literal["allowed", "denied", "error"]
    request_id: str
