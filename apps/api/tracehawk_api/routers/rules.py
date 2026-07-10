from pathlib import Path

from fastapi import APIRouter
from pydantic import BaseModel

from tracehawk_api.models.domain import Confidence, Severity
from tracehawk_api.services.rules import load_rules


router = APIRouter(prefix="/api/rules", tags=["rules"])


class RuleLibraryItem(BaseModel):
    id: str
    title: str
    category: str
    description: str
    danger_summary: str
    severity: Severity
    confidence: Confidence
    log_types: list[str]
    mitre_tactic: str | None
    mitre_technique_id: str | None
    mitre_technique_name: str | None
    look_for: list[str]
    false_positives: list[str]
    recommendations: list[str]


class RuleLibraryResponse(BaseModel):
    rule_count: int
    categories: list[str]
    rules: list[RuleLibraryItem]


@router.get("/library", response_model=RuleLibraryResponse)
def rule_library() -> RuleLibraryResponse:
    rules = load_rules(_project_root() / "packages/rules")
    items = [
        RuleLibraryItem(
            id=rule.id,
            title=rule.title,
            category=_rule_category(rule.log_types),
            description=rule.description,
            danger_summary=_danger_summary(rule.severity, rule.mitre.tactic),
            severity=rule.severity,
            confidence=rule.confidence,
            log_types=rule.log_types,
            mitre_tactic=rule.mitre.tactic,
            mitre_technique_id=rule.mitre.technique_id,
            mitre_technique_name=rule.mitre.technique_name,
            look_for=_look_for(rule.conditions.model_dump(exclude_none=True)),
            false_positives=rule.false_positives,
            recommendations=rule.recommendations,
        )
        for rule in rules
    ]
    return RuleLibraryResponse(
        rule_count=len(items),
        categories=sorted({item.category for item in items}),
        rules=items,
    )


def _project_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _rule_category(log_types: list[str]) -> str:
    if any(log_type == "linux_auth" for log_type in log_types):
        return "Auth"
    if any(log_type.startswith("zeek") for log_type in log_types):
        return "Zeek"
    if any(log_type == "suricata_eve" for log_type in log_types):
        return "Suricata"
    if any(log_type == "network_packet" for log_type in log_types):
        return "Network"
    if any(log_type == "web_access" for log_type in log_types):
        return "Web"
    if any(log_type == "json_log" for log_type in log_types):
        return "Json"
    if any(log_type == "csv_log" for log_type in log_types):
        return "Csv"
    if any(log_type == "syslog" for log_type in log_types):
        return "Syslog"
    return (log_types[0] if log_types else "Other").replace("_", " ").title()


def _danger_summary(severity: Severity, tactic: str | None) -> str:
    if tactic:
        return f"{severity.title()} severity pattern connected to {tactic.lower()} behavior."
    return f"{severity.title()} severity pattern that should be reviewed with source context."


def _look_for(conditions: dict[str, object]) -> list[str]:
    clues: list[str] = []
    if event_type := conditions.get("event_type"):
        clues.append(f"event type `{event_type}`")
    if count := conditions.get("count_gte"):
        window = conditions.get("window_minutes", "configured")
        clues.append(f"at least {count} matching events in {window} minutes")
    if distinct_count := conditions.get("distinct_count_gte"):
        field = conditions.get("distinct_field", "configured field")
        clues.append(f"at least {distinct_count} distinct `{field}` values")
    if group_by := conditions.get("group_by"):
        clues.append(f"grouped by {', '.join(f'`{field}`' for field in group_by)}")
    if field_equals := conditions.get("field_equals"):
        clues.extend(f"`{field}` equals `{value}`" for field, value in field_equals.items())
    if field_in := conditions.get("field_in"):
        for field, values in field_in.items():
            clues.append(f"`{field}` is one of {', '.join(f'`{value}`' for value in values)}")
    if field_contains_any := conditions.get("field_contains_any"):
        for field, values in field_contains_any.items():
            clues.append(f"`{field}` contains one of {', '.join(f'`{value}`' for value in values)}")
    if path_values := conditions.get("path_contains_any"):
        clues.append(f"path contains one of {', '.join(f'`{value}`' for value in path_values)}")
    if conditions.get("periodic_count_gte"):
        clues.append("regular repeated timing that can indicate beaconing")
    if conditions.get("sequence"):
        clues.append("ordered event sequence")
    return clues or ["matching events defined by this rule"]
