from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from tracehawk_api.auth import Principal
from tracehawk_api.database import AuditEventRecord
from tracehawk_api.models.domain import AuditEvent


def record_audit_event(
    session: Session,
    *,
    principal: Principal | None,
    method: str,
    path: str,
    status_code: int,
    request_id: str,
    attempted_email: str | None = None,
    auth_mode: str | None = None,
) -> AuditEvent:
    occurred_at = datetime.now(UTC)
    outcome = _outcome(status_code)
    actor = principal.audit_actor if principal else attempted_email or "anonymous"
    record = AuditEventRecord(
        id=f"audit:{uuid4().hex}",
        occurred_at=occurred_at,
        actor=actor,
        email=principal.email if principal else attempted_email,
        role=principal.role if principal else "anonymous",
        auth_mode=principal.auth_mode if principal else auth_mode or "unknown",
        method=method.upper(),
        path=path,
        action=f"{method.upper()} {path}",
        status_code=status_code,
        outcome=outcome,
        request_id=request_id,
    )
    session.add(record)
    session.commit()
    return _from_record(record)


def list_audit_events(session: Session, *, limit: int = 100) -> list[AuditEvent]:
    records = session.scalars(
        select(AuditEventRecord)
        .order_by(AuditEventRecord.occurred_at.desc(), AuditEventRecord.id.desc())
        .limit(limit)
    ).all()
    return [_from_record(record) for record in records]


def _outcome(status_code: int) -> str:
    if status_code in {401, 403}:
        return "denied"
    if status_code >= 500:
        return "error"
    return "allowed"


def _from_record(record: AuditEventRecord) -> AuditEvent:
    return AuditEvent(
        id=record.id,
        occurred_at=record.occurred_at,
        actor=record.actor,
        email=record.email,
        role=record.role,  # type: ignore[arg-type]
        auth_mode=record.auth_mode,
        method=record.method,
        path=record.path,
        action=record.action,
        status_code=record.status_code,
        outcome=record.outcome,  # type: ignore[arg-type]
        request_id=record.request_id,
    )
