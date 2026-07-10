from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from tracehawk_api.database import get_session
from tracehawk_api.services.retention import (
    AnalysisExport,
    RetentionApplyResult,
    RetentionPreview,
    RetentionSettings,
    apply_retention,
    export_analysis,
    get_retention_settings,
    preview_retention,
    save_retention_settings,
)

router = APIRouter(prefix="/api/retention", tags=["retention"])
SessionDep = Annotated[Session, Depends(get_session)]


@router.get("/settings", response_model=RetentionSettings)
def retention_settings(session: SessionDep) -> RetentionSettings:
    return get_retention_settings(session)


@router.put("/settings", response_model=RetentionSettings)
def update_retention_settings(settings: RetentionSettings, session: SessionDep) -> RetentionSettings:
    return save_retention_settings(session, settings)


@router.post("/preview", response_model=RetentionPreview)
def retention_preview(session: SessionDep, settings: RetentionSettings | None = None) -> RetentionPreview:
    return preview_retention(session, settings)


@router.post("/apply", response_model=RetentionApplyResult)
def retention_apply(session: SessionDep, settings: RetentionSettings | None = None) -> RetentionApplyResult:
    return apply_retention(session, settings)


@router.get("/exports/analysis/{analysis_id}", response_model=AnalysisExport)
def analysis_export(analysis_id: str, session: SessionDep) -> AnalysisExport:
    export = export_analysis(session, analysis_id)
    if export is None:
        raise HTTPException(status_code=404, detail="Analysis run not found.")
    return export
