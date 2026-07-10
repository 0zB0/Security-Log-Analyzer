from dataclasses import dataclass
from datetime import UTC
from hashlib import sha256
from pathlib import Path

from pydantic import BaseModel, Field

from tracehawk_api.models.domain import (
    DetectionRule,
    Entity,
    Finding,
    Incident,
    ParsedEvent,
    RawLogLine,
)
from tracehawk_api.services.correlation import correlate_incidents
from tracehawk_api.services.detection import run_detection
from tracehawk_api.services.ingest import build_raw_lines_from_text
from tracehawk_api.services.parser_registry import default_parsers
from tracehawk_api.services.parsers import LogParser
from tracehawk_api.services.rules import load_rules


class EvidenceLine(BaseModel):
    id: str
    line_number: int
    raw_text: str
    content_hash: str


class SourceSummary(BaseModel):
    filename: str
    source_id: str
    parser: str
    raw_line_count: int
    parsed_event_count: int
    finding_count: int
    incident_count: int
    content_sha256: str


class CrossSourceLink(BaseModel):
    id: str
    link_type: str
    source_event_id: str
    target_event_id: str
    source_raw_line_id: str
    target_raw_line_id: str
    source_label: str
    target_label: str
    source_event_type: str
    target_event_type: str
    event_time: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: str | None = None
    match_value: str | None = None
    summary: str
    confidence: str = "medium"


class CaseQualitySummary(BaseModel):
    strongest_incident_id: str | None = None
    strongest_incident_title: str | None = None
    strongest_incident_score: int = 0
    sequence_backed_incident_count: int = 0
    cross_source_corroborated_incident_count: int = 0
    total_cross_source_links: int = 0
    top_scoring_reason: str | None = None


class AnalysisResult(BaseModel):
    analysis_id: str | None = None
    source_id: str
    parser: str
    raw_line_count: int
    parsed_event_count: int
    finding_count: int
    incident_count: int
    events: list[ParsedEvent] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    incidents: list[Incident] = Field(default_factory=list)
    entities: list[Entity] = Field(default_factory=list)
    evidence: list[EvidenceLine] = Field(default_factory=list)
    sources: list[SourceSummary] = Field(default_factory=list)
    cross_source_links: list[CrossSourceLink] = Field(default_factory=list)
    case_quality: CaseQualitySummary | None = None


@dataclass(frozen=True)
class ParserSelection:
    label: str
    parsers: list[LogParser]


def analyze_text(
    text: str,
    filename: str,
    rules_root: Path,
    parsers: list[LogParser] | None = None,
) -> AnalysisResult:
    source_id = _source_id(filename, text)
    raw_lines = build_raw_lines_from_text(text, source_id)
    selection = _select_parsers(
        raw_lines,
        parsers or default_parsers(),
    )
    events = _parse_selected_lines(raw_lines, selection)
    rules = load_rules(rules_root)
    findings = _run_parser_scoped_detection(rules, events, selection)
    incidents = correlate_incidents(findings, events)

    evidence_by_id = {line.id: line for line in raw_lines}
    evidence_ids = {
        evidence_id for finding in findings for evidence_id in finding.evidence_line_ids
    }
    evidence = [
        EvidenceLine(
            id=line.id,
            line_number=line.line_number,
            raw_text=line.raw_text,
            content_hash=line.content_hash,
        )
        for evidence_id in sorted(evidence_ids)
        if (line := evidence_by_id.get(evidence_id)) is not None
    ]

    return AnalysisResult(
        source_id=source_id,
        parser=selection.label,
        raw_line_count=len(raw_lines),
        parsed_event_count=len(events),
        finding_count=len(findings),
        incident_count=len(incidents),
        events=events,
        findings=findings,
        incidents=incidents,
        evidence=evidence,
    )


def _source_id(filename: str, text: str) -> str:
    digest = sha256(f"{filename}\n{text}".encode("utf-8")).hexdigest()[:12]
    safe_name = "".join(char if char.isalnum() else "-" for char in filename.lower()).strip("-")
    return f"{safe_name or 'upload'}:{digest}"


PARSER_SPECIFICITY = {
    "suricata_eve": 100,
    "zeek_json": 98,
    "zeek_tsv": 98,
    "cloudtrail": 95,
    "kubernetes_audit": 95,
    "windows_event": 95,
    "linux_auth": 90,
    "web_access": 90,
    "csv_log": 80,
    "json_log": 20,
    "syslog": 10,
}
STATEFUL_PARSERS = {"csv_log", "zeek_tsv"}
GENERIC_FALLBACK_PARSERS = {"json_log", "syslog"}


def _select_parsers(raw_lines: list[RawLogLine], parsers: list[LogParser]) -> ParserSelection:
    samples = _stratified_samples(raw_lines)
    hits: dict[str, int] = {}
    for sample in samples:
        parser = _best_parser_for_line(sample.raw_text, parsers)
        if parser is not None:
            hits[parser.parser_name] = hits.get(parser.parser_name, 0) + 1

    if not hits:
        raise ValueError("No supported parser matched the uploaded log content.")

    hits = _significant_parser_hits(hits)

    selected_names = sorted(hits)
    selected = [parser for parser in parsers if parser.parser_name in hits]
    if len(selected_names) > 1:
        return ParserSelection(label="mixed", parsers=selected)

    parser_name = selected_names[0]
    return ParserSelection(
        label=parser_name,
        parsers=[next(parser for parser in parsers if parser.parser_name == parser_name)],
    )


def _significant_parser_hits(hits: dict[str, int]) -> dict[str, int]:
    specific_hits = {
        parser_name: count
        for parser_name, count in hits.items()
        if parser_name not in GENERIC_FALLBACK_PARSERS
    }
    if not specific_hits:
        return hits

    strongest_specific_count = max(specific_hits.values())
    minimum_fallback_hits = max(2, round(strongest_specific_count * 0.25))
    return {
        parser_name: count
        for parser_name, count in hits.items()
        if parser_name not in GENERIC_FALLBACK_PARSERS or count >= minimum_fallback_hits
    }


def _stratified_samples(
    raw_lines: list[RawLogLine],
    max_samples: int = 120,
) -> list[RawLogLine]:
    candidates = [line for line in raw_lines if line.raw_text.strip()]
    if len(candidates) <= max_samples:
        return candidates
    indexes = {
        round(index * (len(candidates) - 1) / (max_samples - 1))
        for index in range(max_samples)
    }
    return [candidates[index] for index in sorted(indexes)]


def _best_parser_for_line(raw_line: str, parsers: list[LogParser]) -> LogParser | None:
    matching = [parser for parser in parsers if parser.can_parse(raw_line)]
    if not matching:
        return None
    return max(
        matching,
        key=lambda parser: (
            PARSER_SPECIFICITY.get(parser.parser_name, 50),
            parser.parser_name,
        ),
    )


def _parse_selected_lines(
    raw_lines: list[RawLogLine],
    selection: ParserSelection,
) -> list[ParsedEvent]:
    if selection.label != "mixed":
        return _parse_lines(raw_lines, selection.parsers[0])

    events: list[ParsedEvent] = []
    stateful_parser: LogParser | None = None
    for line in raw_lines:
        parser = _best_parser_for_line(line.raw_text, selection.parsers)
        if parser is not None:
            stateful_parser = parser if parser.parser_name in STATEFUL_PARSERS else None
        elif stateful_parser is not None:
            parser = stateful_parser
        if parser is None:
            continue
        event = parser.parse_line(line.id, line.source_id, line.raw_text)
        if event is not None:
            _annotate_event(event, parser.parser_name)
            events.append(event)
    return events


def _run_parser_scoped_detection(
    rules: list[DetectionRule],
    events: list[ParsedEvent],
    selection: ParserSelection,
) -> list[Finding]:
    findings: list[Finding] = []
    for parser in selection.parsers:
        parser_events = [
            event
            for event in events
            if event.normalized_fields.get("_tracehawk_parser") == parser.parser_name
        ]
        applicable_rules = [rule for rule in rules if parser.parser_name in rule.log_types]
        findings.extend(run_detection(applicable_rules, parser_events))
    return findings


def _parse_lines(raw_lines: list[RawLogLine], parser: LogParser) -> list[ParsedEvent]:
    events: list[ParsedEvent] = []
    for line in raw_lines:
        event = parser.parse_line(line.id, line.source_id, line.raw_text)
        if event is not None:
            _annotate_event(event, parser.parser_name)
            events.append(event)
    return events


def _annotate_event(event: ParsedEvent, parser_name: str) -> None:
    if event.event_time is not None and event.event_time.tzinfo is None:
        event.event_time = event.event_time.replace(tzinfo=UTC)
    event.normalized_fields.setdefault("_tracehawk_parser", parser_name)
