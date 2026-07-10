from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from tracehawk_api.database import get_session
from tracehawk_api.models.domain import AnalystNote
from tracehawk_api.services.notes import (
    AnalystNoteCreate,
    AnalystNoteUpdate,
    create_incident_note,
    delete_note,
    list_incident_notes,
    update_note,
)

router = APIRouter(prefix="/api/notes", tags=["notes"])
SessionDep = Annotated[Session, Depends(get_session)]


@router.get("/incidents/{incident_id}", response_model=list[AnalystNote])
def incident_notes(
    incident_id: str,
    session: SessionDep,
    analysis_id: Annotated[str, Query(min_length=1)],
) -> list[AnalystNote]:
    return list_incident_notes(session, analysis_id, incident_id)


@router.post("/incidents/{incident_id}", response_model=AnalystNote)
def create_note(
    incident_id: str,
    note: AnalystNoteCreate,
    session: SessionDep,
    request: Request,
) -> AnalystNote:
    try:
        principal = request.state.principal
        attributed_note = note.model_copy(update={"author": principal.audit_actor})
        return create_incident_note(session, incident_id, attributed_note)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/{note_id}", response_model=AnalystNote)
def patch_note(note_id: str, request: AnalystNoteUpdate, session: SessionDep) -> AnalystNote:
    note = update_note(session, note_id, request)
    if note is None:
        raise HTTPException(status_code=404, detail="Note not found.")
    return note


@router.delete("/{note_id}", response_model=dict[str, bool])
def remove_note(note_id: str, session: SessionDep) -> dict[str, bool]:
    deleted = delete_note(session, note_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Note not found.")
    return {"deleted": True}
