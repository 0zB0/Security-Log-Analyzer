import json
from datetime import UTC, datetime
from typing import Any

from tracehawk_api.models.domain import ParsedEvent
from tracehawk_api.services.parsers import LogParser


class ZeekJsonParser(LogParser):
    parser_name = "zeek_json"
    supported_types = ["zeek_json"]

    def can_parse(self, sample: str) -> bool:
        data = _loads_object(sample)
        if data is None:
            return False
        return _zeek_path(data) is not None

    def parse_line(self, raw_line_id: str, source_id: str, raw_line: str) -> ParsedEvent | None:
        data = _loads_object(raw_line)
        if data is None:
            return None
        path = _zeek_path(data)
        if path is None:
            return None

        normalized = _normalize_values(data)
        return _event_from_fields(raw_line_id, source_id, path, normalized)


def _loads_object(raw_line: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(raw_line)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _zeek_path(data: dict[str, Any]) -> str | None:
    path_value = data.get("_path") or data.get("path") or data.get("log_type")
    if path_value:
        return _normalize_path(str(path_value))
    fields = set(data)
    if {"id.orig_h", "id.resp_h", "conn_state"} <= fields:
        return "conn"
    if {"id.orig_h", "id.resp_h", "query"} <= fields and ("qtype_name" in fields or "qtype" in fields):
        return "dns"
    if {"id.orig_h", "id.resp_h", "method", "host", "uri"} <= fields:
        return "http"
    if {"id.orig_h", "id.resp_h", "server_name"} <= fields:
        return "ssl"
    if "note" in fields and ("msg" in fields or "sub" in fields):
        return "notice"
    return None


def _event_from_fields(
    raw_line_id: str,
    source_id: str,
    path: str,
    fields: dict[str, Any],
) -> ParsedEvent:
    source_ip = _first_text(fields, ["id.orig_h", "src", "source_ip"])
    destination_ip = _first_text(fields, ["id.resp_h", "dst", "destination_ip"])
    source_port = _int_or_none(_first_value(fields, ["id.orig_p", "source_port"]))
    destination_port = _int_or_none(_first_value(fields, ["id.resp_p", "destination_port"]))
    transport_protocol = _first_text(fields, ["proto"])
    normalized_fields = dict(fields)
    normalized_fields.update(
        {
            key: value
            for key, value in {
                "zeek_log_type": path,
                "destination_ip": destination_ip,
                "source_port": source_port,
                "destination_port": destination_port,
                "transport_protocol": transport_protocol,
                "conn_state": _first_text(fields, ["conn_state"]),
                "dns_query": _first_text(fields, ["query"]),
                "http_method": _first_text(fields, ["method"]),
                "http_hostname": _first_text(fields, ["host"]),
                "url_path": _first_text(fields, ["uri"]),
                "tls_sni": _first_text(fields, ["server_name"]),
                "notice_note": _first_text(fields, ["note"]),
            }.items()
            if value is not None
        }
    )

    return ParsedEvent(
        id=f"event:{raw_line_id}",
        source_id=source_id,
        raw_line_id=raw_line_id,
        event_time=_timestamp_from_zeek(_first_value(fields, ["ts"])),
        event_type=f"zeek_{path}",
        host=_first_text(fields, ["host", "id.resp_h"]),
        service=_service(path, fields, destination_port),
        source_ip=source_ip,
        message=_message(path, fields),
        normalized_fields=normalized_fields,
    )


def _normalize_values(data: dict[str, Any]) -> dict[str, Any]:
    return {str(key): _coerce_value(value) for key, value in data.items() if not str(key).startswith("_")}


def _coerce_value(value: Any) -> Any:
    if value in {"-", "(empty)", ""}:
        return None
    return value


def _first_value(data: dict[str, Any], fields: list[str]) -> Any | None:
    for field in fields:
        value = data.get(field)
        if value is not None and str(value).strip():
            return value
    return None


def _first_text(data: dict[str, Any], fields: list[str]) -> str | None:
    value = _first_value(data, fields)
    return str(value) if value is not None else None


def _int_or_none(value: Any | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _timestamp_from_zeek(value: Any | None) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=UTC)
    except (TypeError, ValueError, OSError):
        if isinstance(value, str):
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
        return None


def _service(path: str, fields: dict[str, Any], destination_port: int | None) -> str:
    service = _first_text(fields, ["service"])
    if service:
        return service
    if path in {"dns", "http", "ssl", "notice"}:
        return path
    if destination_port is not None:
        return f"port:{destination_port}"
    return "zeek"


def _message(path: str, fields: dict[str, Any]) -> str:
    if path == "conn":
        return (
            f"Zeek connection {_first_text(fields, ['id.orig_h']) or '?'}:"
            f"{_first_text(fields, ['id.orig_p']) or '?'} -> "
            f"{_first_text(fields, ['id.resp_h']) or '?'}:"
            f"{_first_text(fields, ['id.resp_p']) or '?'} "
            f"{_first_text(fields, ['conn_state']) or ''}"
        ).strip()
    if path == "dns":
        return f"Zeek DNS query {_first_text(fields, ['query']) or 'unknown'}"
    if path == "http":
        return f"Zeek HTTP {_first_text(fields, ['method']) or 'request'} {_first_text(fields, ['host']) or ''}{_first_text(fields, ['uri']) or ''}".strip()
    if path == "ssl":
        return f"Zeek TLS {_first_text(fields, ['server_name']) or 'session'}"
    if path == "notice":
        return f"Zeek notice {_first_text(fields, ['note']) or ''}: {_first_text(fields, ['msg']) or _first_text(fields, ['sub']) or ''}".strip()
    return f"Zeek {path} event"


def _normalize_path(value: str) -> str:
    normalized = value.strip().lower()
    return "ssl" if normalized == "tls" else normalized
