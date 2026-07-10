from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from tracehawk_api.database import get_session
from tracehawk_api.models.domain import AuditEvent
from tracehawk_api.services.audit import list_audit_events


router = APIRouter(prefix="/api/audit", tags=["audit"])
SessionDep = Annotated[Session, Depends(get_session)]


@router.get("/events", response_model=list[AuditEvent])
def audit_events(
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[AuditEvent]:
    return list_audit_events(session, limit=limit)
