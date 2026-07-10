from typing import Any

from tracehawk_api.models.domain import ParsedEvent
from tracehawk_api.services.parsers import LogParser
from tracehawk_api.services.zeek_json_parser import _event_from_fields


class ZeekTsvParser(LogParser):
    parser_name = "zeek_tsv"
    supported_types = ["zeek_tsv"]

    def __init__(self) -> None:
        self.separator = "\t"
        self.empty_field = "(empty)"
        self.unset_field = "-"
        self.path: str | None = None
        self.fields: list[str] | None = None

    def can_parse(self, sample: str) -> bool:
        return sample.startswith("#separator") or sample.startswith("#fields") or sample.startswith("#path")

    def parse_line(self, raw_line_id: str, source_id: str, raw_line: str) -> ParsedEvent | None:
        if raw_line.startswith("#"):
            self._parse_metadata(raw_line)
            return None

        if not self.fields or not self.path:
            return None

        values = raw_line.split(self.separator)
        if len(values) != len(self.fields):
            return None

        data = {
            field: _coerce_value(value, self.empty_field, self.unset_field)
            for field, value in zip(self.fields, values, strict=True)
        }
        return _event_from_fields(raw_line_id, source_id, self.path, data)

    def _parse_metadata(self, raw_line: str) -> None:
        if raw_line.startswith("#separator"):
            value = raw_line.removeprefix("#separator").strip()
            self.separator = _decode_separator(value)
        elif raw_line.startswith("#empty_field"):
            self.empty_field = raw_line.removeprefix("#empty_field").strip() or self.empty_field
        elif raw_line.startswith("#unset_field"):
            self.unset_field = raw_line.removeprefix("#unset_field").strip() or self.unset_field
        elif raw_line.startswith("#path"):
            self.path = _normalize_path(raw_line.removeprefix("#path").strip())
        elif raw_line.startswith("#fields"):
            fields_text = raw_line.removeprefix("#fields").strip()
            self.fields = (
                fields_text.split(self.separator)
                if self.separator in fields_text
                else fields_text.split()
            )


def _decode_separator(value: str) -> str:
    if value in {r"\x09", r"\x 09"}:
        return "\t"
    return value or "\t"


def _coerce_value(value: str, empty_field: str, unset_field: str) -> Any:
    if value in {empty_field, unset_field, ""}:
        return None
    if value in {"T", "F"}:
        return value == "T"
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def _normalize_path(value: str) -> str:
    normalized = value.strip().lower()
    return "ssl" if normalized == "tls" else normalized
