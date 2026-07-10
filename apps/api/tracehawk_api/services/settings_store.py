from datetime import UTC, datetime

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from tracehawk_api.config import settings
from tracehawk_api.database import AppSettingRecord

ASSISTANT_SETTING_KEY = "assistant"


class AssistantSettings(BaseModel):
    ai_enabled: bool = True
    default_model: str = Field(default_factory=lambda: settings.ollama_model)
    show_prompt_preview: bool = True
    max_evidence_lines: int = Field(default=20, ge=1, le=100)
    max_evidence_chars: int = Field(default=4000, ge=200, le=50000)


def get_assistant_settings(session: Session) -> AssistantSettings:
    record = session.get(AppSettingRecord, ASSISTANT_SETTING_KEY)
    if record is None:
        return AssistantSettings()
    return AssistantSettings.model_validate(record.value)


def save_assistant_settings(session: Session, assistant_settings: AssistantSettings) -> AssistantSettings:
    session.merge(
        AppSettingRecord(
            key=ASSISTANT_SETTING_KEY,
            value=assistant_settings.model_dump(mode="json"),
            updated_at=datetime.now(UTC),
        )
    )
    session.commit()
    return assistant_settings
