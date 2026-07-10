from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from hashlib import sha256
from typing import Any, Literal

from tracehawk_api.models.domain import Entity, Finding, Incident, ParsedEvent

EntityType = Literal["ip", "user", "host", "service", "path", "domain", "url", "container"]

SEVERITY_RISK = {
    "info": 10,
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 95,
}


@dataclass
class EntityAccumulator:
    entity_type: EntityType
    value: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    event_count: int = 0
    source_ids: set[str] = field(default_factory=set)
    finding_ids: set[str] = field(default_factory=set)
    incident_ids: set[str] = field(default_factory=set)
    risk_score: int = 0


def build_entities(
    analysis_id: str | None,
    events: list[ParsedEvent],
    findings: list[Finding],
    incidents: list[Incident],
) -> list[Entity]:
    accumulators: dict[tuple[EntityType, str], EntityAccumulator] = {}
    event_entities: dict[str, set[tuple[EntityType, str]]] = {}

    for event in events:
        keys = _event_entity_keys(event)
        event_entities[event.raw_line_id] = keys
        for entity_type, value in keys:
            accumulator = accumulators.setdefault(
                (entity_type, value),
                EntityAccumulator(entity_type=entity_type, value=value),
            )
            accumulator.event_count += 1
            accumulator.source_ids.add(event.source_id)
            if event.event_time is not None:
                accumulator.first_seen = _min_time(accumulator.first_seen, event.event_time)
                accumulator.last_seen = _max_time(accumulator.last_seen, event.event_time)

    finding_by_id = {finding.id: finding for finding in findings}
    for finding in findings:
        keys = set().union(
            *(event_entities.get(line_id, set()) for line_id in finding.evidence_line_ids)
        )
        for key in keys:
            accumulator = accumulators[key]
            accumulator.finding_ids.add(finding.id)
            accumulator.risk_score = max(accumulator.risk_score, SEVERITY_RISK[finding.severity])

    for incident in incidents:
        linked_findings = [finding_by_id[finding_id] for finding_id in incident.finding_ids if finding_id in finding_by_id]
        keys = set().union(
            *(
                event_entities.get(line_id, set())
                for finding in linked_findings
                for line_id in finding.evidence_line_ids
            )
        )
        keys |= _incident_entity_keys(incident)
        for key in keys:
            accumulator = accumulators.get(key)
            if accumulator is None:
                accumulator = accumulators.setdefault(
                    key,
                    EntityAccumulator(entity_type=key[0], value=key[1]),
                )
            accumulator.incident_ids.add(incident.id)
            accumulator.risk_score = max(accumulator.risk_score, incident.score)

    return sorted(
        (
            Entity(
                id=_entity_id(analysis_id, accumulator.entity_type, accumulator.value),
                analysis_id=analysis_id,
                entity_type=accumulator.entity_type,
                value=accumulator.value,
                first_seen=accumulator.first_seen,
                last_seen=accumulator.last_seen,
                risk_score=min(100, accumulator.risk_score),
                event_count=accumulator.event_count,
                source_ids=sorted(accumulator.source_ids),
                finding_ids=sorted(accumulator.finding_ids),
                incident_ids=sorted(accumulator.incident_ids),
            )
            for accumulator in accumulators.values()
        ),
        key=lambda entity: (entity.risk_score, entity.event_count, entity.value),
        reverse=True,
    )


def _event_entity_keys(event: ParsedEvent) -> set[tuple[EntityType, str]]:
    keys: set[tuple[EntityType, str]] = set()
    _add(keys, "ip", event.source_ip)
    _add(keys, "user", event.username)
    _add(keys, "host", event.host)
    _add(keys, "service", event.service)

    fields = event.normalized_fields
    for name in ("destination_ip", "dest_ip", "dst_ip", "id.resp_h", "server_ip"):
        _add(keys, "ip", fields.get(name))
    for name in ("host", "hostname", "server_name"):
        _add(keys, "host", fields.get(name))
    for name in ("url_path", "path", "uri", "file_path"):
        _add(keys, "path", fields.get(name))
    for name in ("url", "request_url"):
        _add(keys, "url", fields.get(name))
    for name in ("query", "dns_query", "domain", "server_name"):
        _add(keys, "domain", fields.get(name))
    for name in ("container", "container_name"):
        _add(keys, "container", fields.get(name))

    return keys


def _incident_entity_keys(incident: Incident) -> set[tuple[EntityType, str]]:
    keys: set[tuple[EntityType, str]] = set()
    for value in incident.entities:
        if not value:
            continue
        if _looks_like_ip(value):
            keys.add(("ip", value))
        elif "/" in value:
            keys.add(("path", value))
        elif "." in value:
            keys.add(("domain", value))
        else:
            keys.add(("user", value))
    return keys


def _add(keys: set[tuple[EntityType, str]], entity_type: EntityType, value: Any) -> None:
    if value is None:
        return
    text = str(value).strip()
    if not text:
        return
    keys.add((entity_type, text))


def _entity_id(analysis_id: str | None, entity_type: str, value: str) -> str:
    scope = analysis_id or "transient"
    digest = sha256(f"{scope}:{entity_type}:{value}".encode("utf-8")).hexdigest()[:16]
    return f"entity:{digest}"


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def _min_time(left: datetime | None, right: datetime) -> datetime:
    return right if left is None or right < left else left


def _max_time(left: datetime | None, right: datetime) -> datetime:
    return right if left is None or right > left else left
