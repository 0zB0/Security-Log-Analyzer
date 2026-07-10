from datetime import UTC, datetime
import re

from tracehawk_api.models.domain import Incident

from .models import CaseReportRequest, ReportRequest

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ENTITY_USER_RE = re.compile(r"\buser:[^\s,;]+", flags=re.IGNORECASE)
ENTITY_HOST_RE = re.compile(r"\bhost:[^\s,;]+", flags=re.IGNORECASE)
AUTH_USER_RE = re.compile(r"\b(?:for|user|username=)\s+([A-Za-z0-9_.@-]+)", flags=re.IGNORECASE)
HOST_ASSIGNMENT_RE = re.compile(r"\b(?:host|hostname)=([A-Za-z0-9_.-]+)", flags=re.IGNORECASE)


def _redact_values(request: ReportRequest, values: list[str]) -> list[str]:
    return [_redact_text(request, value) for value in values]


def _redact_text(request: ReportRequest, value: str | None) -> str:
    if value is None:
        return ""
    if not request.redaction.enabled:
        return value

    redacted = value
    if request.redaction.mask_ips:
        redacted = IPV4_RE.sub("[REDACTED_IP]", redacted)
        redacted = re.sub(r"\b(ip|dst|src):[^\s,;]+", r"\1:[REDACTED_IP]", redacted)
    if request.redaction.mask_users:
        redacted = ENTITY_USER_RE.sub("user:[REDACTED_USER]", redacted)
        redacted = AUTH_USER_RE.sub(lambda match: match.group(0).replace(match.group(1), "[REDACTED_USER]"), redacted)
        for username in _entity_values(request, "user:"):
            redacted = re.sub(
                rf"\b{re.escape(username)}\b",
                "[REDACTED_USER]",
                redacted,
                flags=re.IGNORECASE,
            )
    if request.redaction.mask_hosts:
        redacted = ENTITY_HOST_RE.sub("host:[REDACTED_HOST]", redacted)
        redacted = HOST_ASSIGNMENT_RE.sub(lambda match: match.group(0).replace(match.group(1), "[REDACTED_HOST]"), redacted)
        for hostname in _entity_values(request, "host:"):
            redacted = re.sub(
                rf"\b{re.escape(hostname)}\b",
                "[REDACTED_HOST]",
                redacted,
                flags=re.IGNORECASE,
            )
    return redacted


def _entity_values(request: ReportRequest, prefix: str) -> list[str]:
    values: list[str] = []
    for entity in request.incident.entities:
        if entity.lower().startswith(prefix):
            value = entity.split(":", 1)[1].strip()
            if value:
                values.append(value)
    return values


def _case_redactor(request: CaseReportRequest) -> ReportRequest:
    entities = sorted(
        {
            entity
            for incident in request.analysis.incidents
            for entity in incident.entities
        }
    )
    incident = Incident(
        id=request.analysis.analysis_id or request.analysis.source_id,
        title="Case report",
        severity="info",
        summary="Case redaction context",
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        score=0,
        entities=entities,
    )
    return ReportRequest(incident=incident, redaction=request.redaction)
