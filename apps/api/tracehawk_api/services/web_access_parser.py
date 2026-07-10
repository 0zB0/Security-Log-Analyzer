import re
from datetime import datetime
from urllib.parse import urlsplit

from tracehawk_api.models.domain import ParsedEvent
from tracehawk_api.services.parsers import LogParser


COMBINED_LOG_RE = re.compile(
    r'^(?P<source_ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<target>\S+) (?P<protocol>[^"]+)" '
    r"(?P<status_code>\d{3}) (?P<body_bytes>\S+)"
    r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?$'
)


class WebAccessParser(LogParser):
    parser_name = "web_access"
    supported_types = ["web_access"]

    def can_parse(self, sample: str) -> bool:
        return bool(COMBINED_LOG_RE.match(sample))

    def parse_line(self, raw_line_id: str, source_id: str, raw_line: str) -> ParsedEvent | None:
        match = COMBINED_LOG_RE.match(raw_line)
        if not match:
            return None

        data = match.groupdict()
        target = data["target"]
        parsed_target = urlsplit(target)
        path = parsed_target.path or target
        status_code = int(data["status_code"])
        body_bytes = None if data["body_bytes"] == "-" else int(data["body_bytes"])

        return ParsedEvent(
            id=f"event:{raw_line_id}",
            source_id=source_id,
            raw_line_id=raw_line_id,
            event_time=_parse_access_time(data["timestamp"]),
            event_type="http_request",
            service="web",
            source_ip=data["source_ip"],
            message=raw_line,
            normalized_fields={
                "http_method": data["method"],
                "url_target": target,
                "url_path": path,
                "url_query": parsed_target.query,
                "protocol": data["protocol"],
                "status_code": status_code,
                "body_bytes": body_bytes,
                "referer": data.get("referer") or None,
                "user_agent": data.get("user_agent") or None,
            },
        )


def _parse_access_time(timestamp: str) -> datetime:
    return datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")

