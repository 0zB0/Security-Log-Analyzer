from datetime import UTC, datetime
from hashlib import sha256

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from tracehawk_api.database import (
    AnalysisRunRecord,
    EntityRecord,
    FindingRecord,
    IncidentRecord,
    LogSourceRecord,
    ParsedEventRecord,
    RawLogLineRecord,
)
from tracehawk_api.models.domain import Entity, Finding, Incident, MitreMapping, ParsedEvent, RawLogLine
from tracehawk_api.services.analysis import AnalysisResult, EvidenceLine
from tracehawk_api.services.entities import build_entities


class AnalysisRunSummary(BaseModel):
    id: str
    source_id: str
    filename: str
    parser: str
    raw_line_count: int
    parsed_event_count: int
    finding_count: int
    incident_count: int
    created_at: datetime


def persist_analysis(
    session: Session,
    result: AnalysisResult,
    raw_lines: list[RawLogLine],
    filename: str,
    *,
    source_type: str = "upload",
    analysis_id: str | None = None,
) -> AnalysisResult:
    analysis_id = analysis_id or _analysis_id(filename, result.source_id)
    now = datetime.now(UTC)

    session.merge(
        AnalysisRunRecord(
            id=analysis_id,
            source_id=result.source_id,
            filename=filename,
            parser=result.parser,
            raw_line_count=result.raw_line_count,
            parsed_event_count=result.parsed_event_count,
            finding_count=result.finding_count,
            incident_count=result.incident_count,
            created_at=now,
        )
    )
    session.merge(
        LogSourceRecord(
            id=result.source_id,
            analysis_id=analysis_id,
            name=filename,
            source_type=source_type,
            parser_type=result.parser,
            status="stopped",
            created_at=now,
        )
    )

    for line in raw_lines:
        session.merge(
            RawLogLineRecord(
                id=line.id,
                analysis_id=analysis_id,
                source_id=line.source_id,
                line_number=line.line_number,
                raw_text=line.raw_text,
                content_hash=line.content_hash,
                timestamp_observed=line.timestamp_observed,
            )
        )
    for event in result.events:
        session.merge(_event_record(analysis_id, event))
    for finding in result.findings:
        session.merge(_finding_record(analysis_id, finding))
    for incident in result.incidents:
        session.merge(_incident_record(analysis_id, incident))
    result.entities = build_entities(analysis_id, result.events, result.findings, result.incidents)
    for entity in result.entities:
        session.merge(_entity_record(analysis_id, entity))

    session.commit()
    result.analysis_id = analysis_id
    return result


def list_analysis_runs(session: Session, limit: int = 20) -> list[AnalysisRunSummary]:
    records = session.scalars(
        select(AnalysisRunRecord).order_by(AnalysisRunRecord.created_at.desc()).limit(limit)
    ).all()
    return [
        AnalysisRunSummary(
            id=record.id,
            source_id=record.source_id,
            filename=record.filename,
            parser=record.parser,
            raw_line_count=record.raw_line_count,
            parsed_event_count=record.parsed_event_count,
            finding_count=record.finding_count,
            incident_count=record.incident_count,
            created_at=record.created_at,
        )
        for record in records
    ]


def get_analysis_result(session: Session, analysis_id: str) -> AnalysisResult | None:
    run = session.get(AnalysisRunRecord, analysis_id)
    if run is None:
        return None

    events = [
        _event_from_record(record)
        for record in session.scalars(
            select(ParsedEventRecord)
            .where(ParsedEventRecord.analysis_id == analysis_id)
            .order_by(ParsedEventRecord.event_time, ParsedEventRecord.id)
        )
    ]
    findings = [
        _finding_from_record(record)
        for record in session.scalars(
            select(FindingRecord)
            .where(FindingRecord.analysis_id == analysis_id)
            .order_by(FindingRecord.first_seen, FindingRecord.id)
        )
    ]
    incidents = [
        _incident_from_record(record)
        for record in session.scalars(
            select(IncidentRecord)
            .where(IncidentRecord.analysis_id == analysis_id)
            .order_by(IncidentRecord.score.desc(), IncidentRecord.last_seen.desc())
        )
    ]
    entities = [
        _entity_from_record(record)
        for record in session.scalars(
            select(EntityRecord)
            .where(EntityRecord.analysis_id == analysis_id)
            .order_by(EntityRecord.risk_score.desc(), EntityRecord.event_count.desc(), EntityRecord.value)
        )
    ]
    evidence = [
        EvidenceLine(
            id=record.id,
            line_number=record.line_number,
            raw_text=record.raw_text,
            content_hash=record.content_hash,
        )
        for record in session.scalars(
            select(RawLogLineRecord)
            .where(RawLogLineRecord.analysis_id == analysis_id)
            .order_by(RawLogLineRecord.line_number)
        )
    ]

    return AnalysisResult(
        analysis_id=analysis_id,
        source_id=run.source_id,
        parser=run.parser,
        raw_line_count=run.raw_line_count,
        parsed_event_count=run.parsed_event_count,
        finding_count=run.finding_count,
        incident_count=run.incident_count,
        events=events,
        findings=findings,
        incidents=incidents,
        entities=entities,
        evidence=evidence,
    )


def list_incidents(
    session: Session,
    limit: int = 50,
    analysis_id: str | None = None,
) -> list[Incident]:
    statement = select(IncidentRecord).order_by(
        IncidentRecord.score.desc(),
        IncidentRecord.last_seen.desc(),
    )
    if analysis_id is not None:
        statement = statement.where(IncidentRecord.analysis_id == analysis_id)
    records = session.scalars(statement.limit(limit)).all()
    return [_incident_from_record(record) for record in records]


def list_entities(session: Session, analysis_id: str | None = None, limit: int = 100) -> list[Entity]:
    statement = select(EntityRecord).order_by(
        EntityRecord.risk_score.desc(),
        EntityRecord.event_count.desc(),
        EntityRecord.value,
    )
    if analysis_id is not None:
        statement = statement.where(EntityRecord.analysis_id == analysis_id)
    records = session.scalars(statement.limit(limit)).all()
    return [_entity_from_record(record) for record in records]


def get_entity(session: Session, entity_id: str) -> Entity | None:
    record = session.get(EntityRecord, entity_id)
    return _entity_from_record(record) if record is not None else None


def _analysis_id(filename: str, source_id: str) -> str:
    digest = sha256(f"{filename}:{source_id}".encode()).hexdigest()[:16]
    return f"analysis:{digest}"


def _event_record(analysis_id: str, event: ParsedEvent) -> ParsedEventRecord:
    return ParsedEventRecord(
        id=event.id,
        analysis_id=analysis_id,
        source_id=event.source_id,
        raw_line_id=event.raw_line_id,
        event_time=event.event_time,
        event_type=event.event_type,
        host=event.host,
        service=event.service,
        source_ip=event.source_ip,
        username=event.username,
        message=event.message,
        normalized_fields=event.normalized_fields,
    )


def _finding_record(analysis_id: str, finding: Finding) -> FindingRecord:
    return FindingRecord(
        id=finding.id,
        analysis_id=analysis_id,
        rule_id=finding.rule_id,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        summary=finding.summary,
        reason=finding.reason,
        mitre=finding.mitre.model_dump(),
        first_seen=finding.first_seen,
        last_seen=finding.last_seen,
        event_count=finding.event_count,
        evidence_line_ids=finding.evidence_line_ids,
    )


def _incident_record(analysis_id: str, incident: Incident) -> IncidentRecord:
    return IncidentRecord(
        id=incident.id,
        analysis_id=analysis_id,
        title=incident.title,
        severity=incident.severity,
        status=incident.status,
        summary=incident.summary,
        first_seen=incident.first_seen,
        last_seen=incident.last_seen,
        score=incident.score,
        finding_ids=incident.finding_ids,
        entities=incident.entities,
        timeline=incident.timeline,
        mitre_techniques=incident.mitre_techniques,
    )


def _entity_record(analysis_id: str, entity: Entity) -> EntityRecord:
    return EntityRecord(
        id=entity.id,
        analysis_id=analysis_id,
        entity_type=entity.entity_type,
        value=entity.value,
        first_seen=entity.first_seen,
        last_seen=entity.last_seen,
        risk_score=entity.risk_score,
        event_count=entity.event_count,
        source_ids=entity.source_ids,
        finding_ids=entity.finding_ids,
        incident_ids=entity.incident_ids,
    )


def _event_from_record(record: ParsedEventRecord) -> ParsedEvent:
    return ParsedEvent(
        id=record.id,
        source_id=record.source_id,
        raw_line_id=record.raw_line_id,
        event_time=record.event_time,
        event_type=record.event_type,
        host=record.host,
        service=record.service,
        source_ip=record.source_ip,
        username=record.username,
        message=record.message,
        normalized_fields=record.normalized_fields,
    )


def _finding_from_record(record: FindingRecord) -> Finding:
    return Finding(
        id=record.id,
        rule_id=record.rule_id,
        title=record.title,
        severity=record.severity,  # type: ignore[arg-type]
        confidence=record.confidence,  # type: ignore[arg-type]
        summary=record.summary,
        reason=record.reason,
        mitre=MitreMapping.model_validate(record.mitre),
        first_seen=record.first_seen,
        last_seen=record.last_seen,
        event_count=record.event_count,
        evidence_line_ids=record.evidence_line_ids,
    )


def _incident_from_record(record: IncidentRecord) -> Incident:
    return Incident(
        id=record.id,
        title=record.title,
        severity=record.severity,  # type: ignore[arg-type]
        status=record.status,  # type: ignore[arg-type]
        summary=record.summary,
        first_seen=record.first_seen,
        last_seen=record.last_seen,
        score=record.score,
        finding_ids=record.finding_ids,
        entities=record.entities,
        timeline=record.timeline,
        mitre_techniques=record.mitre_techniques,
    )


def _entity_from_record(record: EntityRecord) -> Entity:
    return Entity(
        id=record.id,
        analysis_id=record.analysis_id,
        entity_type=record.entity_type,  # type: ignore[arg-type]
        value=record.value,
        first_seen=record.first_seen,
        last_seen=record.last_seen,
        risk_score=record.risk_score,
        event_count=record.event_count,
        source_ids=record.source_ids,
        finding_ids=record.finding_ids,
        incident_ids=record.incident_ids,
    )
