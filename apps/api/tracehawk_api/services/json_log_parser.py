import json
from datetime import UTC, datetime
from typing import Any

from tracehawk_api.models.domain import ParsedEvent
from tracehawk_api.services.parsers import LogParser


class JsonLogParser(LogParser):
    parser_name = "json_log"
    supported_types = ["json_log"]

    def can_parse(self, sample: str) -> bool:
        parsed = _loads_object(sample)
        return parsed is not None

    def parse_line(self, raw_line_id: str, source_id: str, raw_line: str) -> ParsedEvent | None:
        data = _loads_object(raw_line)
        if data is None:
            return None

        flattened = _flatten(data)
        message = _first_text(
            flattened,
            ["message", "msg", "event.original", "log.message", "error.message"],
        ) or raw_line

        event_type = _first_text(
            flattened,
            ["event_type", "event.type", "event.action", "action", "type", "category"],
        ) or "json_event"

        return ParsedEvent(
            id=f"event:{raw_line_id}",
            source_id=source_id,
            raw_line_id=raw_line_id,
            event_time=_parse_time(
                _first_text(flattened, ["@timestamp", "timestamp", "time", "event.created"])
            ),
            event_type=event_type,
            host=_first_text(flattened, ["host", "host.name", "hostname", "agent.hostname"]),
            service=_first_text(flattened, ["service", "service.name", "app", "logger"]),
            source_ip=_first_text(
                flattened,
                ["source_ip", "src_ip", "source.ip", "client.ip", "remote_addr", "ip"],
            ),
            username=_first_text(
                flattened,
                ["username", "user", "user.name", "user.username", "actor.name"],
            ),
            message=message,
            normalized_fields=flattened,
        )


def _loads_object(raw_line: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(raw_line)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _flatten(data: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    for key, value in data.items():
        field = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            flattened.update(_flatten(value, field))
        else:
            flattened[field] = value
    return flattened


def _first_text(data: dict[str, Any], fields: list[str]) -> str | None:
    for field in fields:
        value = data.get(field)
        if value is not None and str(value).strip():
            return str(value)
    return None


def _parse_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed
