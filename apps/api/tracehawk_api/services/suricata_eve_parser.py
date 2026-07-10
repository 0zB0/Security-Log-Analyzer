import json
from datetime import UTC, datetime
from typing import Any

from tracehawk_api.models.domain import ParsedEvent
from tracehawk_api.services.parsers import LogParser


SURICATA_EVENT_TYPES = {
    "alert",
    "anomaly",
    "dns",
    "flow",
    "http",
    "tls",
    "fileinfo",
    "ssh",
}


class SuricataEveParser(LogParser):
    parser_name = "suricata_eve"
    supported_types = ["suricata_eve"]

    def can_parse(self, sample: str) -> bool:
        data = _loads_object(sample)
        if data is None:
            return False
        event_type = str(data.get("event_type", "")).lower()
        return event_type in SURICATA_EVENT_TYPES and (
            "src_ip" in data or "dest_ip" in data or event_type == "alert"
        )

    def parse_line(self, raw_line_id: str, source_id: str, raw_line: str) -> ParsedEvent | None:
        data = _loads_object(raw_line)
        if data is None or not self.can_parse(raw_line):
            return None

        flattened = _flatten(data)
        event_type = str(data.get("event_type", "event")).lower()
        normalized_event_type = f"suricata_{event_type}"
        source_ip = _first_text(flattened, ["src_ip", "source.ip"])
        destination_ip = _first_text(flattened, ["dest_ip", "destination.ip"])
        source_port = _int_or_none(_first_value(flattened, ["src_port"]))
        destination_port = _int_or_none(_first_value(flattened, ["dest_port"]))
        transport_protocol = _first_text(flattened, ["proto"])
        signature = _first_text(flattened, ["alert.signature"])
        category = _first_text(flattened, ["alert.category"])
        message = _message(event_type, signature, data)

        normalized_fields = dict(flattened)
        normalized_fields.update(
            {
                key: value
                for key, value in {
                    "destination_ip": destination_ip,
                    "source_port": source_port,
                    "destination_port": destination_port,
                    "transport_protocol": transport_protocol.lower()
                    if transport_protocol
                    else None,
                    "signature": signature,
                    "category": category,
                    "dns_query": _dns_query(data),
                    "http_hostname": _first_text(flattened, ["http.hostname"]),
                    "url_path": _first_text(flattened, ["http.url"]),
                    "http_method": _first_text(flattened, ["http.http_method"]),
                    "user_agent": _first_text(flattened, ["http.http_user_agent"]),
                    "tls_sni": _first_text(flattened, ["tls.sni"]),
                }.items()
                if value is not None
            }
        )

        return ParsedEvent(
            id=f"event:{raw_line_id}",
            source_id=source_id,
            raw_line_id=raw_line_id,
            event_time=_parse_time(_first_text(flattened, ["timestamp"])),
            event_type=normalized_event_type,
            host=_first_text(flattened, ["host", "host.name"]),
            service=_service(event_type, destination_port),
            source_ip=source_ip,
            message=message,
            normalized_fields=normalized_fields,
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


def _dns_query(data: dict[str, Any]) -> str | None:
    dns = data.get("dns")
    if not isinstance(dns, dict):
        return None
    queries = dns.get("queries")
    if isinstance(queries, list):
        for query in queries:
            if isinstance(query, dict) and query.get("rrname"):
                return str(query["rrname"])
    if dns.get("rrname"):
        return str(dns["rrname"])
    return None


def _service(event_type: str, destination_port: int | None) -> str:
    if event_type in {"http", "dns", "tls", "ssh"}:
        return event_type
    if destination_port is not None:
        return f"port:{destination_port}"
    return "suricata"


def _message(event_type: str, signature: str | None, data: dict[str, Any]) -> str:
    if signature:
        return signature
    if event_type == "dns":
        return f"DNS query {(_dns_query(data) or 'unknown')}"
    if event_type == "http":
        http = data.get("http") if isinstance(data.get("http"), dict) else {}
        return f"HTTP {http.get('http_method', 'request')} {http.get('hostname', '')}{http.get('url', '')}".strip()
    if event_type == "tls":
        tls = data.get("tls") if isinstance(data.get("tls"), dict) else {}
        return f"TLS {tls.get('sni', 'session')}"
    return f"Suricata {event_type} event"
