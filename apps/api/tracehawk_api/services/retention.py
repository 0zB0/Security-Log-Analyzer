from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import BaseModel, Field
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from tracehawk_api.database import (
    AnalysisRunRecord,
    AnalystNoteRecord,
    AppSettingRecord,
    EntityRecord,
    FindingRecord,
    IncidentRecord,
    LogSourceRecord,
    ParsedEventRecord,
    RawLogLineRecord,
)

RETENTION_SETTING_KEY = "retention"
PURGED_RAW_TEXT = "[PURGED_RAW_LOG]"

RetentionMode = Literal["keep_all", "keep_last_n_days", "purge_raw_keep_findings"]


class RetentionSettings(BaseModel):
    mode: RetentionMode = "keep_all"
    days: int = Field(default=30, ge=1, le=3650)
    delete_reports_with_runs: bool = False


class RetentionPreview(BaseModel):
    mode: RetentionMode
    cutoff: datetime | None = None
    analysis_runs_affected: int = 0
    raw_lines_affected: int = 0
    parsed_events_affected: int = 0
    findings_affected: int = 0
    incidents_affected: int = 0
    entities_affected: int = 0
    notes_affected: int = 0
    affected_analysis_ids: list[str] = Field(default_factory=list)


class RetentionApplyResult(BaseModel):
    preview: RetentionPreview
    applied_at: datetime


class AnalysisExport(BaseModel):
    analysis_id: str
    exported_at: datetime
    manifest: dict[str, object]
    raw_lines: list[dict[str, object]]
    parsed_events: list[dict[str, object]]
    findings: list[dict[str, object]]
    incidents: list[dict[str, object]]
    entities: list[dict[str, object]]
    notes: list[dict[str, object]]


def get_retention_settings(session: Session) -> RetentionSettings:
    record = session.get(AppSettingRecord, RETENTION_SETTING_KEY)
    if record is None:
        return RetentionSettings()
    return RetentionSettings.model_validate(record.value)


def save_retention_settings(session: Session, settings: RetentionSettings) -> RetentionSettings:
    session.merge(
        AppSettingRecord(
            key=RETENTION_SETTING_KEY,
            value=settings.model_dump(mode="json"),
            updated_at=datetime.now(UTC),
        )
    )
    session.commit()
    return settings


def preview_retention(session: Session, settings: RetentionSettings | None = None) -> RetentionPreview:
    settings = settings or get_retention_settings(session)
    if settings.mode == "keep_all":
        return RetentionPreview(mode=settings.mode)
    if settings.mode == "purge_raw_keep_findings":
        analysis_ids = session.scalars(select(AnalysisRunRecord.id)).all()
        raw_count = _count_records(
            session,
            select(RawLogLineRecord).where(RawLogLineRecord.raw_text != PURGED_RAW_TEXT),
        )
        return RetentionPreview(
            mode=settings.mode,
            analysis_runs_affected=len(analysis_ids),
            raw_lines_affected=raw_count,
            affected_analysis_ids=sorted(analysis_ids),
        )

    cutoff = datetime.now(UTC) - timedelta(days=settings.days)
    analysis_ids = session.scalars(
        select(AnalysisRunRecord.id).where(AnalysisRunRecord.created_at < cutoff)
    ).all()
    return RetentionPreview(
        mode=settings.mode,
        cutoff=cutoff,
        analysis_runs_affected=len(analysis_ids),
        raw_lines_affected=_count_by_analysis_ids(session, RawLogLineRecord, analysis_ids),
        parsed_events_affected=_count_by_analysis_ids(session, ParsedEventRecord, analysis_ids),
        findings_affected=_count_by_analysis_ids(session, FindingRecord, analysis_ids),
        incidents_affected=_count_by_analysis_ids(session, IncidentRecord, analysis_ids),
        entities_affected=_count_by_analysis_ids(session, EntityRecord, analysis_ids),
        notes_affected=_count_by_analysis_ids(session, AnalystNoteRecord, analysis_ids),
        affected_analysis_ids=sorted(analysis_ids),
    )


def apply_retention(session: Session, settings: RetentionSettings | None = None) -> RetentionApplyResult:
    settings = settings or get_retention_settings(session)
    preview = preview_retention(session, settings)
    if settings.mode == "keep_all":
        return RetentionApplyResult(preview=preview, applied_at=datetime.now(UTC))
    if settings.mode == "purge_raw_keep_findings":
        session.execute(
            update(RawLogLineRecord)
            .where(RawLogLineRecord.raw_text != PURGED_RAW_TEXT)
            .values(raw_text=PURGED_RAW_TEXT)
        )
        for run in session.scalars(select(AnalysisRunRecord)).all():
            integrity = dict(run.evidence_integrity or {})
            integrity.update(
                {
                    "status": "raw_purged",
                    "algorithm": "sha256",
                    "origin": integrity.get("origin", "legacy"),
                    "verified_line_count": integrity.get("verified_line_count", 0),
                    "attested_live_snapshot": integrity.get(
                        "attested_live_snapshot", False
                    ),
                }
            )
            run.evidence_integrity = integrity
        session.commit()
        return RetentionApplyResult(preview=preview, applied_at=datetime.now(UTC))

    _delete_analysis_ids(session, preview.affected_analysis_ids)
    session.commit()
    return RetentionApplyResult(preview=preview, applied_at=datetime.now(UTC))


def export_analysis(session: Session, analysis_id: str) -> AnalysisExport | None:
    run = session.get(AnalysisRunRecord, analysis_id)
    if run is None:
        return None
    raw_lines = _rows(
        session,
        select(RawLogLineRecord).where(RawLogLineRecord.analysis_id == analysis_id),
        ["id", "source_id", "line_number", "raw_text", "content_hash", "timestamp_observed"],
    )
    parsed_events = _rows(
        session,
        select(ParsedEventRecord).where(ParsedEventRecord.analysis_id == analysis_id),
        ["id", "source_id", "raw_line_id", "event_time", "event_type", "host", "service", "source_ip", "username", "message", "normalized_fields"],
    )
    findings = _rows(
        session,
        select(FindingRecord).where(FindingRecord.analysis_id == analysis_id),
        ["id", "rule_id", "title", "severity", "confidence", "summary", "reason", "mitre", "first_seen", "last_seen", "event_count", "evidence_line_ids"],
    )
    incidents = _rows(
        session,
        select(IncidentRecord).where(IncidentRecord.analysis_id == analysis_id),
        ["id", "title", "severity", "status", "summary", "first_seen", "last_seen", "score", "finding_ids", "entities", "timeline", "mitre_techniques"],
    )
    entities = _rows(
        session,
        select(EntityRecord).where(EntityRecord.analysis_id == analysis_id),
        ["id", "entity_type", "value", "first_seen", "last_seen", "risk_score", "event_count", "source_ids", "finding_ids", "incident_ids"],
    )
    notes = _rows(
        session,
        select(AnalystNoteRecord).where(AnalystNoteRecord.analysis_id == analysis_id),
        ["id", "incident_id", "body", "note_type", "author", "created_at", "updated_at"],
    )
    return AnalysisExport(
        analysis_id=analysis_id,
        exported_at=datetime.now(UTC),
        manifest={
            "source_id": run.source_id,
            "filename": run.filename,
            "parser": run.parser,
            "created_at": run.created_at,
            "raw_line_count": len(raw_lines),
            "parsed_event_count": len(parsed_events),
            "finding_count": len(findings),
            "incident_count": len(incidents),
            "entity_count": len(entities),
            "note_count": len(notes),
        },
        raw_lines=raw_lines,
        parsed_events=parsed_events,
        findings=findings,
        incidents=incidents,
        entities=entities,
        notes=notes,
    )


def _delete_analysis_ids(session: Session, analysis_ids: list[str]) -> None:
    if not analysis_ids:
        return
    for model in (
        AnalystNoteRecord,
        EntityRecord,
        IncidentRecord,
        FindingRecord,
        ParsedEventRecord,
        RawLogLineRecord,
        LogSourceRecord,
    ):
        session.execute(delete(model).where(model.analysis_id.in_(analysis_ids)))
    session.execute(delete(AnalysisRunRecord).where(AnalysisRunRecord.id.in_(analysis_ids)))


def _count_by_analysis_ids(session: Session, model, analysis_ids: list[str]) -> int:
    if not analysis_ids:
        return 0
    return _count_records(session, select(model).where(model.analysis_id.in_(analysis_ids)))


def _count_records(session: Session, statement) -> int:
    return len(session.scalars(statement).all())


def _rows(session: Session, statement, fields: list[str]) -> list[dict[str, object]]:
    rows = []
    for record in session.scalars(statement).all():
        row = {}
        for field in fields:
            value = getattr(record, field)
            row[field] = value.isoformat() if isinstance(value, datetime) else value
        rows.append(row)
    return rows
