import csv
from datetime import UTC, datetime

from tracehawk_api.models.domain import ParsedEvent
from tracehawk_api.services.parsers import LogParser


class CsvLogParser(LogParser):
    parser_name = "csv_log"
    supported_types = ["csv_log"]

    def __init__(self) -> None:
        self.headers: list[str] | None = None

    def can_parse(self, sample: str) -> bool:
        headers = _parse_csv_row(sample)
        if len(headers) < 2:
            return False
        normalized = {_normalize_header(header) for header in headers}
        return bool(
            normalized
            & {
                "timestamp",
                "time",
                "event_time",
                "source_ip",
                "src_ip",
                "client_ip",
                "username",
                "user",
                "event_type",
                "action",
                "message",
            }
        )

    def parse_line(self, raw_line_id: str, source_id: str, raw_line: str) -> ParsedEvent | None:
        row = _parse_csv_row(raw_line)
        if not row:
            return None

        if self.headers is None:
            if not self.can_parse(raw_line):
                return None
            self.headers = [_normalize_header(header) for header in row]
            return None

        if len(row) != len(self.headers):
            return None

        data = {
            header: value.strip()
            for header, value in zip(self.headers, row, strict=True)
            if value.strip()
        }
        message = _first_text(data, ["message", "msg", "event_original", "raw"]) or raw_line
        event_type = (
            _first_text(data, ["event_type", "event_action", "action", "type", "category"])
            or "csv_event"
        )

        return ParsedEvent(
            id=f"event:{raw_line_id}",
            source_id=source_id,
            raw_line_id=raw_line_id,
            event_time=_parse_time(_first_text(data, ["timestamp", "time", "event_time", "date"])),
            event_type=event_type,
            host=_first_text(data, ["host", "hostname", "host_name"]),
            service=_first_text(data, ["service", "service_name", "app", "application"]),
            source_ip=_first_text(
                data,
                ["source_ip", "src_ip", "sourceip", "client_ip", "remote_addr", "ip"],
            ),
            username=_first_text(data, ["username", "user", "user_name", "user_username"]),
            message=message,
            normalized_fields=data,
        )


def _parse_csv_row(raw_line: str) -> list[str]:
    try:
        return next(csv.reader([raw_line]))
    except csv.Error:
        return []


def _normalize_header(header: str) -> str:
    return (
        header.strip()
        .lower()
        .replace("@", "")
        .replace(".", "_")
        .replace("-", "_")
        .replace(" ", "_")
    )


def _first_text(data: dict[str, str], fields: list[str]) -> str | None:
    for field in fields:
        value = data.get(field)
        if value:
            return value
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
