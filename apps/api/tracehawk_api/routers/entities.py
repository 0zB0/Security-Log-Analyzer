from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from tracehawk_api.database import get_session
from tracehawk_api.models.domain import Entity
from tracehawk_api.services.persistence import get_entity, list_entities

router = APIRouter(prefix="/api/entities", tags=["entities"])
SessionDep = Annotated[Session, Depends(get_session)]


@router.get("", response_model=list[Entity])
def entity_inventory(
    session: SessionDep,
    analysis_id: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[Entity]:
    return list_entities(session, analysis_id=analysis_id, limit=limit)


@router.get("/{entity_id}", response_model=Entity)
def entity_detail(entity_id: str, session: SessionDep) -> Entity:
    entity = get_entity(session, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found.")
    return entity
