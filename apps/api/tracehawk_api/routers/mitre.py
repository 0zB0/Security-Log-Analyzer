from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from tracehawk_api.database import get_session
from tracehawk_api.services.mitre import MitreSummary, build_mitre_summary
from tracehawk_api.services.persistence import get_analysis_result

router = APIRouter(prefix="/api/mitre", tags=["mitre"])
SessionDep = Annotated[Session, Depends(get_session)]


@router.get("/summary/{analysis_id}", response_model=MitreSummary)
def mitre_summary(analysis_id: str, session: SessionDep) -> MitreSummary:
    analysis = get_analysis_result(session, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis run not found.")
    return build_mitre_summary(analysis_id, analysis.findings)
