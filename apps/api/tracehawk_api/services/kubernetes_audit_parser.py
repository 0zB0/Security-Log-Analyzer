import json
from datetime import UTC, datetime
from typing import Any

from tracehawk_api.models.domain import ParsedEvent
from tracehawk_api.services.json_log_parser import _flatten
from tracehawk_api.services.parsers import LogParser


class KubernetesAuditParser(LogParser):
    parser_name = "kubernetes_audit"
    supported_types = ["kubernetes_audit"]

    def can_parse(self, sample: str) -> bool:
        data = _loads_object(sample)
        return bool(
            data
            and str(data.get("apiVersion", "")).startswith("audit.k8s.io/")
            and data.get("kind") == "Event"
        )

    def parse_line(self, raw_line_id: str, source_id: str, raw_line: str) -> ParsedEvent | None:
        data = _loads_object(raw_line)
        if data is None:
            return None
        flattened = _flatten(data)
        verb = _text(flattened.get("verb")) or "unknown"
        resource = _text(flattened.get("objectRef.resource")) or "unknown"
        subresource = _text(flattened.get("objectRef.subresource"))
        event_type = f"{verb}_{resource}" + (f"_{subresource}" if subresource else "")
        username = _text(flattened.get("user.username"))
        source_ip = _source_ip(data)
        namespace = _text(flattened.get("objectRef.namespace"))
        name = _text(flattened.get("objectRef.name"))
        flattened["source_ip"] = source_ip
        flattened["privileged_container"] = _has_privileged_container(data)
        message = f"kubernetes {verb} {resource}"
        if subresource:
            message = f"{message}/{subresource}"
        if namespace or name:
            message = f"{message} {namespace or ''}/{name or ''}".strip()

        return ParsedEvent(
            id=f"event:{raw_line_id}",
            source_id=source_id,
            raw_line_id=raw_line_id,
            event_time=_parse_time(_text(flattened.get("requestReceivedTimestamp"))),
            event_type=event_type,
            host=namespace,
            service="kubernetes-audit",
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


def _source_ip(data: dict[str, Any]) -> str | None:
    source_ips = data.get("sourceIPs")
    if isinstance(source_ips, list) and source_ips:
        return str(source_ips[0])
    return None


def _has_privileged_container(data: dict[str, Any]) -> bool:
    spec = data.get("requestObject", {}).get("spec", {})
    containers = spec.get("containers", []) if isinstance(spec, dict) else []
    if not isinstance(containers, list):
        return False
    return any(
        isinstance(container, dict)
        and container.get("securityContext", {}).get("privileged") is True
        for container in containers
    )


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
