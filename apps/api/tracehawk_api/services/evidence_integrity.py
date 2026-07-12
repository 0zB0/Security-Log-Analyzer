from hashlib import sha256
from hmac import compare_digest
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from tracehawk_api.models.domain import RawLogLine


EvidenceOrigin = Literal[
    "legacy",
    "upload",
    "case_bundle",
    "live_snapshot",
    "file_watch",
    "folder_watch",
    "docker_logs",
    "interface_packets",
    "syslog",
]


class LiveRetentionSummary(BaseModel):
    raw_line_capacity: int = Field(ge=1)
    event_capacity: int = Field(ge=1)
    total_raw_lines: int = Field(ge=0)
    total_parsed_events: int = Field(ge=0)
    retained_raw_lines: int = Field(ge=0)
    retained_parsed_events: int = Field(ge=0)
    dropped_raw_lines: int = Field(ge=0)
    dropped_parsed_events: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_counters(self) -> "LiveRetentionSummary":
        if self.retained_raw_lines > self.raw_line_capacity:
            raise ValueError("Retained raw-line count exceeds its configured capacity.")
        if self.retained_parsed_events > self.event_capacity:
            raise ValueError("Retained event count exceeds its configured capacity.")
        if self.total_raw_lines != self.retained_raw_lines + self.dropped_raw_lines:
            raise ValueError("Raw-line retention counters are inconsistent.")
        if (
            self.total_parsed_events
            != self.retained_parsed_events + self.dropped_parsed_events
        ):
            raise ValueError("Parsed-event retention counters are inconsistent.")
        return self


class EvidenceIntegritySummary(BaseModel):
    status: Literal["verified", "legacy_unverified", "raw_purged"] = "verified"
    algorithm: Literal["sha256"] = "sha256"
    origin: EvidenceOrigin
    verified_line_count: int = Field(ge=0)
    attested_live_snapshot: bool = False
    live_retention: LiveRetentionSummary | None = None


class EvidenceIntegrityError(ValueError):
    pass


def verify_analysis_integrity(
    result: Any,
    raw_lines: list[RawLogLine],
    *,
    origin: EvidenceOrigin,
    attested_live_snapshot: bool = False,
) -> EvidenceIntegritySummary:
    _require_unique("raw line", [line.id for line in raw_lines])
    _require_unique("event", [event.id for event in result.events])
    _require_unique("finding", [finding.id for finding in result.findings])
    _require_unique("incident", [incident.id for incident in result.incidents])
    _require_unique("selected evidence line", [line.id for line in result.evidence])

    if result.raw_line_count != len(raw_lines):
        raise EvidenceIntegrityError("Raw-line count does not match the submitted evidence graph.")
    if result.parsed_event_count != len(result.events):
        raise EvidenceIntegrityError("Parsed-event count does not match the submitted evidence graph.")
    if result.finding_count != len(result.findings):
        raise EvidenceIntegrityError("Finding count does not match the submitted evidence graph.")
    if result.incident_count != len(result.incidents):
        raise EvidenceIntegrityError("Incident count does not match the submitted evidence graph.")

    live_retention = getattr(result, "live_retention", None)
    if live_retention is not None:
        if live_retention.retained_raw_lines != result.raw_line_count:
            raise EvidenceIntegrityError(
                "Live-retention raw-line count does not match the evidence graph."
            )
        if live_retention.retained_parsed_events != result.parsed_event_count:
            raise EvidenceIntegrityError(
                "Live-retention event count does not match the evidence graph."
            )

    raw_by_id = {line.id: line for line in raw_lines}
    for line in raw_lines:
        expected_hash = sha256(line.raw_text.encode("utf-8")).hexdigest()
        if not compare_digest(expected_hash, line.content_hash):
            raise EvidenceIntegrityError(
                f"Evidence content hash does not match raw text for line {line.line_number}."
            )

    for evidence in result.evidence:
        raw_line = raw_by_id.get(evidence.id)
        if raw_line is None:
            raise EvidenceIntegrityError("Selected evidence references an unknown raw line.")
        if evidence.line_number != raw_line.line_number or evidence.raw_text != raw_line.raw_text:
            raise EvidenceIntegrityError("Selected evidence does not match its stored raw line.")
        if not compare_digest(evidence.content_hash, raw_line.content_hash):
            raise EvidenceIntegrityError("Selected evidence hash does not match its stored raw line.")

    allowed_source_ids = {result.source_id}
    allowed_source_ids.update(source.source_id for source in result.sources)
    for line in raw_lines:
        if line.source_id not in allowed_source_ids:
            raise EvidenceIntegrityError("Raw evidence references an unknown source.")

    event_ids = {event.id for event in result.events}
    for event in result.events:
        if event.raw_line_id not in raw_by_id:
            raise EvidenceIntegrityError("Parsed event references an unknown raw line.")
        if event.source_id not in allowed_source_ids:
            raise EvidenceIntegrityError("Parsed event references an unknown source.")

    finding_ids = {finding.id for finding in result.findings}
    for finding in result.findings:
        if any(line_id not in raw_by_id for line_id in finding.evidence_line_ids):
            raise EvidenceIntegrityError("Finding references unknown evidence.")

    for incident in result.incidents:
        if any(finding_id not in finding_ids for finding_id in incident.finding_ids):
            raise EvidenceIntegrityError("Incident references an unknown finding.")

    for link in result.cross_source_links:
        if link.source_event_id not in event_ids or link.target_event_id not in event_ids:
            raise EvidenceIntegrityError("Cross-source link references an unknown event.")
        if (
            link.source_raw_line_id not in raw_by_id
            or link.target_raw_line_id not in raw_by_id
        ):
            raise EvidenceIntegrityError("Cross-source link references unknown raw evidence.")

    return EvidenceIntegritySummary(
        origin=origin,
        verified_line_count=len(raw_lines),
        attested_live_snapshot=attested_live_snapshot,
        live_retention=live_retention,
    )


def _require_unique(kind: str, identifiers: list[str]) -> None:
    if len(identifiers) != len(set(identifiers)):
        raise EvidenceIntegrityError(f"Duplicate {kind} identifier in evidence graph.")
