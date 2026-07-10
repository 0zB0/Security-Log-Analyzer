import re
from datetime import UTC, datetime

from tracehawk_api.models.domain import ParsedEvent
from tracehawk_api.services.parsers import LogParser


SYSLOG_PREFIX_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>[A-Za-z0-9_.-]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<username>\S+) from "
    r"(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)

ACCEPTED_PASSWORD_RE = re.compile(
    r"Accepted password for (?P<username>\S+) from "
    r"(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)

SUDO_RE = re.compile(
    r"(?P<username>\S+)\s+:\s+TTY=(?P<tty>[^;]+)\s+;\s+PWD=(?P<pwd>[^;]+)\s+;\s+"
    r"USER=(?P<run_as>[^;]+)\s+;\s+COMMAND=(?P<command>.+)$"
)


class LinuxAuthParser(LogParser):
    parser_name = "linux_auth"
    supported_types = ["linux_auth"]

    def can_parse(self, sample: str) -> bool:
        return bool(SYSLOG_PREFIX_RE.match(sample)) and ("sshd" in sample or "sudo" in sample)

    def parse_line(self, raw_line_id: str, source_id: str, raw_line: str) -> ParsedEvent | None:
        prefix = SYSLOG_PREFIX_RE.match(raw_line)
        if not prefix:
            return None

        parts = prefix.groupdict()
        message = parts["message"]
        event_time = self._parse_syslog_time(parts["month"], parts["day"], parts["time"])
        common = {
            "id": f"event:{raw_line_id}",
            "source_id": source_id,
            "raw_line_id": raw_line_id,
            "event_time": event_time,
            "host": parts["host"],
            "service": parts["service"],
            "message": message,
        }

        failed = FAILED_PASSWORD_RE.search(message)
        if failed:
            data = failed.groupdict()
            return ParsedEvent(
                **common,
                event_type="ssh_failed_login",
                source_ip=data["source_ip"],
                username=data["username"],
                normalized_fields={"port": int(data["port"])},
            )

        accepted = ACCEPTED_PASSWORD_RE.search(message)
        if accepted:
            data = accepted.groupdict()
            return ParsedEvent(
                **common,
                event_type="ssh_successful_login",
                source_ip=data["source_ip"],
                username=data["username"],
                normalized_fields={"port": int(data["port"])},
            )

        sudo = SUDO_RE.search(message)
        if sudo:
            data = sudo.groupdict()
            return ParsedEvent(
                **common,
                event_type="sudo_command",
                username=data["username"],
                normalized_fields={
                    "tty": data["tty"].strip(),
                    "pwd": data["pwd"].strip(),
                    "run_as": data["run_as"].strip(),
                    "command": data["command"].strip(),
                },
            )

        return ParsedEvent(**common, event_type="linux_auth_message")

    def _parse_syslog_time(self, month: str, day: str, time_value: str) -> datetime:
        # Syslog often omits the year. Use the current year for local investigation ordering.
        year = datetime.now(UTC).year
        return datetime.strptime(f"{year} {month} {day} {time_value}", "%Y %b %d %H:%M:%S")
