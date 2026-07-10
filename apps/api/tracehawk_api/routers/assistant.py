from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from tracehawk_api.database import get_session
from tracehawk_api.services.llm import (
    AssistantRequest,
    AssistantResponse,
    DisabledLocalLLMProvider,
    LocalLLMStatus,
    PromptBuildResult,
    build_incident_prompt,
    get_llm_provider,
)
from tracehawk_api.services.settings_store import (
    AssistantSettings,
    get_assistant_settings,
    save_assistant_settings,
)


router = APIRouter(prefix="/api/assistant", tags=["assistant"])
SessionDep = Annotated[Session, Depends(get_session)]


@router.get("/status", response_model=LocalLLMStatus)
def assistant_status(session: SessionDep) -> LocalLLMStatus:
    assistant_settings = get_assistant_settings(session)
    if not assistant_settings.ai_enabled:
        status = DisabledLocalLLMProvider().status()
        status.error = "Local AI is disabled in TraceHawk settings."
        return status
    return get_llm_provider(assistant_settings.default_model).status()


@router.post("/explain", response_model=AssistantResponse)
def explain_incident(request: AssistantRequest, session: SessionDep) -> AssistantResponse:
    assistant_settings = get_assistant_settings(session)
    model = request.model or assistant_settings.default_model
    if not assistant_settings.ai_enabled:
        return DisabledLocalLLMProvider().explain(request)
    return get_llm_provider(model).explain(request)


@router.post("/prompt-preview", response_model=PromptBuildResult)
def prompt_preview(request: AssistantRequest, session: SessionDep) -> PromptBuildResult:
    assistant_settings = get_assistant_settings(session)
    return build_incident_prompt(
        request,
        max_evidence_lines=assistant_settings.max_evidence_lines,
        max_evidence_chars=assistant_settings.max_evidence_chars,
    )


@router.get("/settings", response_model=AssistantSettings)
def read_assistant_settings(session: SessionDep) -> AssistantSettings:
    return get_assistant_settings(session)


@router.put("/settings", response_model=AssistantSettings)
def update_assistant_settings(settings_update: AssistantSettings, session: SessionDep) -> AssistantSettings:
    return save_assistant_settings(session, settings_update)
