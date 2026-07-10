from datetime import UTC, datetime
from hashlib import sha256
from typing import Literal

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from tracehawk_api.database import AnalystNoteRecord, IncidentRecord
from tracehawk_api.models.domain import AnalystNote

NoteType = Literal["observation", "decision", "follow_up", "false_positive"]


class AnalystNoteCreate(BaseModel):
    analysis_id: str
    body: str = Field(min_length=1, max_length=5000)
    note_type: NoteType = "observation"
    author: str = Field(default="local", min_length=1, max_length=120)


class AnalystNoteUpdate(BaseModel):
    body: str | None = Field(default=None, min_length=1, max_length=5000)
    note_type: NoteType | None = None


def list_incident_notes(session: Session, analysis_id: str, incident_id: str) -> list[AnalystNote]:
    records = session.scalars(
        select(AnalystNoteRecord)
        .where(
            AnalystNoteRecord.analysis_id == analysis_id,
            AnalystNoteRecord.incident_id == incident_id,
        )
        .order_by(AnalystNoteRecord.created_at.desc(), AnalystNoteRecord.id)
    ).all()
    return [_note_from_record(record) for record in records]


def create_incident_note(
    session: Session,
    incident_id: str,
    request: AnalystNoteCreate,
) -> AnalystNote:
    _require_incident(session, request.analysis_id, incident_id)
    now = datetime.now(UTC)
    note = AnalystNote(
        id=_note_id(request.analysis_id, incident_id, request.body, now),
        analysis_id=request.analysis_id,
        incident_id=incident_id,
        body=request.body.strip(),
        note_type=request.note_type,
        author=request.author.strip() or "local",
        created_at=now,
        updated_at=now,
    )
    session.add(_record_from_note(note))
    session.commit()
    return note


def update_note(session: Session, note_id: str, request: AnalystNoteUpdate) -> AnalystNote | None:
    record = session.get(AnalystNoteRecord, note_id)
    if record is None:
        return None
    if request.body is not None:
        record.body = request.body.strip()
    if request.note_type is not None:
        record.note_type = request.note_type
    record.updated_at = datetime.now(UTC)
    session.commit()
    return _note_from_record(record)


def delete_note(session: Session, note_id: str) -> bool:
    record = session.get(AnalystNoteRecord, note_id)
    if record is None:
        return False
    session.delete(record)
    session.commit()
    return True


def _require_incident(session: Session, analysis_id: str, incident_id: str) -> None:
    incident = session.get(IncidentRecord, incident_id)
    if incident is None or incident.analysis_id != analysis_id:
        raise ValueError("Incident not found for analysis.")


def _note_id(analysis_id: str, incident_id: str, body: str, created_at: datetime) -> str:
    digest = sha256(f"{analysis_id}:{incident_id}:{created_at.isoformat()}:{body}".encode("utf-8")).hexdigest()[:16]
    return f"note:{digest}"


def _record_from_note(note: AnalystNote) -> AnalystNoteRecord:
    return AnalystNoteRecord(
        id=note.id,
        analysis_id=note.analysis_id,
        incident_id=note.incident_id,
        body=note.body,
        note_type=note.note_type,
        author=note.author,
        created_at=note.created_at,
        updated_at=note.updated_at,
    )


def _note_from_record(record: AnalystNoteRecord) -> AnalystNote:
    return AnalystNote(
        id=record.id,
        analysis_id=record.analysis_id,
        incident_id=record.incident_id,
        body=record.body,
        note_type=record.note_type,  # type: ignore[arg-type]
        author=record.author,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )
