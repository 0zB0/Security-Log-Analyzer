import json
from datetime import UTC, datetime
from typing import Any

from tracehawk_api.models.domain import ParsedEvent
from tracehawk_api.services.json_log_parser import _flatten
from tracehawk_api.services.parsers import LogParser


class CloudTrailParser(LogParser):
    parser_name = "cloudtrail"
    supported_types = ["cloudtrail"]

    def can_parse(self, sample: str) -> bool:
        data = _loads_object(sample)
        return bool(data and {"eventSource", "eventName", "eventTime"} <= set(data))

    def parse_line(self, raw_line_id: str, source_id: str, raw_line: str) -> ParsedEvent | None:
        data = _loads_object(raw_line)
        if data is None:
            return None
        flattened = _flatten(data)
        event_name = _text(flattened.get("eventName")) or "cloudtrail_event"
        event_source = _text(flattened.get("eventSource")) or "aws"
        username = (
            _text(flattened.get("userIdentity.userName"))
            or _text(flattened.get("userIdentity.arn"))
            or _text(flattened.get("userIdentity.principalId"))
        )
        source_ip = _text(flattened.get("sourceIPAddress"))
        region = _text(flattened.get("awsRegion"))
        message = f"{event_source}:{event_name}"
        if username:
            message = f"{message} by {username}"
        if source_ip:
            message = f"{message} from {source_ip}"

        return ParsedEvent(
            id=f"event:{raw_line_id}",
            source_id=source_id,
            raw_line_id=raw_line_id,
            event_time=_parse_time(_text(flattened.get("eventTime"))),
            event_type=event_name,
            host=region,
            service=event_source,
            source_ip=source_ip,
            username=username,
            message=message,
            normalized_fields=flattened,
        )


def _loads_object(raw_line: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(raw_line)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


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
