import re
from datetime import UTC, datetime

from tracehawk_api.models.domain import ParsedEvent
from tracehawk_api.services.parsers import LogParser


SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>[A-Za-z0-9_.@/-]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

IPV4_RE = re.compile(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")
ERROR_WORD_RE = re.compile(
    r"\b(fail(?:ed|ure)?|error|denied|refused|reject(?:ed)?|unauthorized|timeout)\b",
    flags=re.IGNORECASE,
)


class GenericSyslogParser(LogParser):
    parser_name = "syslog"
    supported_types = ["syslog"]

    def can_parse(self, sample: str) -> bool:
        return bool(SYSLOG_RE.match(sample))

    def parse_line(self, raw_line_id: str, source_id: str, raw_line: str) -> ParsedEvent | None:
        match = SYSLOG_RE.match(raw_line)
        if not match:
            return None

        data = match.groupdict()
        message = data["message"]
        service = data["service"]
        source_ip_match = IPV4_RE.search(message)
        normalized_fields = {
            "pid": int(data["pid"]) if data.get("pid") else None,
            "syslog_message": message,
        }
        normalized_fields = {key: value for key, value in normalized_fields.items() if value is not None}

        return ParsedEvent(
            id=f"event:{raw_line_id}",
            source_id=source_id,
            raw_line_id=raw_line_id,
            event_time=_parse_syslog_time(data["month"], data["day"], data["time"]),
            event_type=_event_type(service, message),
            host=data["host"],
            service=service,
            source_ip=source_ip_match.group("ip") if source_ip_match else None,
            message=message,
            normalized_fields=normalized_fields,
        )


def _event_type(service: str, message: str) -> str:
    lowered = f"{service} {message}".lower()
    if ERROR_WORD_RE.search(lowered):
        return "syslog_error"
    if "started" in lowered or "start" in lowered:
        return "syslog_service_started"
    if "stopped" in lowered or "stop" in lowered:
        return "syslog_service_stopped"
    return "syslog_message"


def _parse_syslog_time(month: str, day: str, time_value: str) -> datetime:
    year = datetime.now(UTC).year
    return datetime.strptime(f"{year} {month} {day} {time_value}", "%Y %b %d %H:%M:%S")
