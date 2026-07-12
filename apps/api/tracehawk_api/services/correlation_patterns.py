from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from tracehawk_api.models.domain import DetectionRule


class CorrelationPatternStage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    any_behaviors: list[str] = Field(min_length=1)

    @field_validator("any_behaviors")
    @classmethod
    def validate_behaviors(cls, behaviors: list[str]) -> list[str]:
        if len(behaviors) != len(set(behaviors)):
            raise ValueError("Stage behaviors must be unique.")
        return behaviors


class CorrelationPattern(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    title: str = Field(min_length=1)
    stages: list[CorrelationPatternStage] = Field(min_length=2, max_length=4)
    max_gap_minutes: int = Field(ge=1, le=1440)
    score: int = Field(ge=1, le=25)
    rationale: str = Field(min_length=1)
    summary: str = Field(min_length=1)


class CorrelationPatternLibrary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    patterns: list[CorrelationPattern] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_pattern_ids(self) -> Self:
        pattern_ids = [pattern.id for pattern in self.patterns]
        if len(pattern_ids) != len(set(pattern_ids)):
            raise ValueError("Correlation pattern IDs must be unique.")
        return self


def load_correlation_patterns(
    path: Path,
    rules: list[DetectionRule],
) -> list[CorrelationPattern]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    patterns = CorrelationPatternLibrary.model_validate(data).patterns

    known_behaviors = {
        behavior
        for rule in rules
        for behavior in rule.correlation.behaviors
    }
    referenced_behaviors = {
        behavior
        for pattern in patterns
        for stage in pattern.stages
        for behavior in stage.any_behaviors
    }
    unknown = sorted(referenced_behaviors - known_behaviors)
    if unknown:
        raise ValueError(
            f"Correlation patterns reference unknown behaviors: {', '.join(unknown)}"
        )
    return patterns


def default_correlation_pattern_path(rules_root: Path) -> Path:
    return rules_root.parent / "correlation" / "patterns.yml"
