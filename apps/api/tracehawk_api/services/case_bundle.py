from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any

from tracehawk_api.models.domain import ParsedEvent, RawLogLine
from tracehawk_api.services.analysis import (
    AnalysisResult,
    CaseQualitySummary,
    CrossSourceLink,
    EvidenceLine,
    SourceSummary,
    analyze_text,
)
from tracehawk_api.services.correlation import correlate_incidents
from tracehawk_api.services.ingest import build_raw_lines_from_text


@dataclass(frozen=True)
class CaseBundleInput:
    filename: str
    text: str


@dataclass(frozen=True)
class CaseBundleAnalysis:
    result: AnalysisResult
    raw_lines: list[RawLogLine]


def analyze_case_bundle(
    inputs: list[CaseBundleInput],
    *,
    rules_root: Path,
    case_name: str = "case-bundle",
) -> CaseBundleAnalysis:
    if len(inputs) < 2:
        raise ValueError("Case bundle requires at least two log files.")

    source_results: list[AnalysisResult] = []
    raw_lines: list[RawLogLine] = []
    for item in inputs:
        if not item.text.strip():
            raise ValueError(f"{item.filename} is empty.")
        source_result = analyze_text(
            text=item.text,
            filename=item.filename,
            rules_root=rules_root,
        )
        source_results.append(source_result)
        raw_lines.extend(build_raw_lines_from_text(item.text, source_result.source_id))

    events = sorted(
        (event for result in source_results for event in result.events),
        key=lambda event: (event.event_time is None, event.event_time, event.id),
    )
    findings = sorted(
        (finding for result in source_results for finding in result.findings),
        key=lambda finding: (finding.first_seen, finding.rule_id, finding.id),
    )
    sources = [
        SourceSummary(
            filename=item.filename,
            source_id=result.source_id,
            parser=result.parser,
            raw_line_count=result.raw_line_count,
            parsed_event_count=result.parsed_event_count,
            finding_count=result.finding_count,
            incident_count=result.incident_count,
            content_sha256=sha256(item.text.encode("utf-8")).hexdigest(),
        )
        for item, result in zip(inputs, source_results, strict=True)
    ]
    cross_source_links = _cross_source_links(events, sources)
    incidents = correlate_incidents(findings, events, cross_source_links=cross_source_links)
    evidence = _case_evidence(findings, raw_lines, cross_source_links)
    case_quality = _case_quality_summary(incidents, cross_source_links)

    case_source_id = _case_source_id(case_name, inputs)
    result = AnalysisResult(
        source_id=case_source_id,
        parser="case_bundle",
        raw_line_count=sum(source.raw_line_count for source in sources),
        parsed_event_count=len(events),
        finding_count=len(findings),
        incident_count=len(incidents),
        events=events,
        findings=findings,
        incidents=incidents,
        evidence=evidence,
        sources=sources,
        cross_source_links=cross_source_links,
        case_quality=case_quality,
    )
    return CaseBundleAnalysis(result=result, raw_lines=raw_lines)


def _case_source_id(case_name: str, inputs: list[CaseBundleInput]) -> str:
    digest = sha256(
        "\n".join(f"{item.filename}:{sha256(item.text.encode('utf-8')).hexdigest()}" for item in inputs).encode(
            "utf-8"
        )
    ).hexdigest()[:12]
    safe_name = "".join(char if char.isalnum() else "-" for char in case_name.lower()).strip("-")
    return f"{safe_name or 'case-bundle'}:{digest}"


def _case_evidence(
    findings: list[Any],
    raw_lines: list[RawLogLine],
    cross_source_links: list[CrossSourceLink],
) -> list[EvidenceLine]:
    evidence_by_id = {line.id: line for line in raw_lines}
    evidence_ids = {evidence_id for finding in findings for evidence_id in finding.evidence_line_ids}
    evidence_ids.update(link.source_raw_line_id for link in cross_source_links)
    evidence_ids.update(link.target_raw_line_id for link in cross_source_links)
    return [
        EvidenceLine(
            id=line.id,
            line_number=line.line_number,
            raw_text=line.raw_text,
            content_hash=line.content_hash,
        )
        for evidence_id in sorted(evidence_ids)
        if (line := evidence_by_id.get(evidence_id)) is not None
    ]


def _cross_source_links(events: list[ParsedEvent], sources: list[SourceSummary]) -> list[CrossSourceLink]:
    source_by_id = {source.source_id: source for source in sources}
    zeek_events = [event for event in events if event.event_type.startswith("zeek_")]
    suricata_events = [event for event in events if event.event_type.startswith("suricata_")]
    links: list[CrossSourceLink] = []
    seen: set[tuple[str, str, str]] = set()

    for suricata_event in suricata_events:
        for zeek_event in zeek_events:
            if suricata_event.source_id == zeek_event.source_id:
                continue
            if not _within_window(suricata_event, zeek_event, minutes=5):
                continue
            link_type = _link_type(suricata_event, zeek_event)
            if link_type is None:
                continue
            key = (link_type, suricata_event.id, zeek_event.id)
            if key in seen:
                continue
            seen.add(key)
            source_label = source_by_id.get(suricata_event.source_id)
            target_label = source_by_id.get(zeek_event.source_id)
            links.append(
                CrossSourceLink(
                    id=f"case-link:{sha256(':'.join(key).encode('utf-8')).hexdigest()[:12]}",
                    link_type=link_type,
                    source_event_id=suricata_event.id,
                    target_event_id=zeek_event.id,
                    source_raw_line_id=suricata_event.raw_line_id,
                    target_raw_line_id=zeek_event.raw_line_id,
                    source_label=source_label.filename if source_label else suricata_event.source_id,
                    target_label=target_label.filename if target_label else zeek_event.source_id,
                    source_event_type=suricata_event.event_type,
                    target_event_type=zeek_event.event_type,
                    event_time=_link_time(suricata_event, zeek_event),
                    source_ip=suricata_event.source_ip or zeek_event.source_ip,
                    destination_ip=_field_text(suricata_event, "destination_ip")
                    or _field_text(zeek_event, "destination_ip"),
                    destination_port=_field_text(suricata_event, "destination_port")
                    or _field_text(zeek_event, "destination_port"),
                    match_value=_match_value(link_type, suricata_event, zeek_event),
                    summary=_link_summary(link_type, suricata_event, zeek_event),
                    confidence="high" if link_type in {"http_path_match", "dns_query_match"} else "medium",
                )
            )
            if len(links) >= 80:
                return links
    return links


def _within_window(left: ParsedEvent, right: ParsedEvent, *, minutes: int) -> bool:
    if left.event_time is None or right.event_time is None:
        return True
    return abs(left.event_time - right.event_time) <= timedelta(minutes=minutes)


def _link_type(left: ParsedEvent, right: ParsedEvent) -> str | None:
    if _same_text_field(left, right, "url_path"):
        return "http_path_match"
    if _same_text_field(left, right, "dns_query"):
        return "dns_query_match"
    if _same_flow(left, right):
        return "flow_match"
    return None


def _same_text_field(left: ParsedEvent, right: ParsedEvent, field: str) -> bool:
    left_value = _field_text(left, field)
    right_value = _field_text(right, field)
    return bool(left_value and right_value and left_value.lower() == right_value.lower())


def _same_flow(left: ParsedEvent, right: ParsedEvent) -> bool:
    application_fields = ("url_path", "dns_query")
    if any(_field_text(event, field) for event in (left, right) for field in application_fields):
        return False
    return (
        left.source_ip is not None
        and left.source_ip == right.source_ip
        and _field_text(left, "destination_ip") == _field_text(right, "destination_ip")
        and _field_text(left, "destination_port") == _field_text(right, "destination_port")
    )


def _field_text(event: ParsedEvent, field: str) -> str | None:
    value = getattr(event, field, None)
    if value is None:
        value = event.normalized_fields.get(field)
    return str(value) if value is not None and str(value).strip() else None


def _link_time(left: ParsedEvent, right: ParsedEvent) -> str | None:
    event_time = left.event_time or right.event_time
    return event_time.isoformat() if event_time else None


def _match_value(link_type: str, left: ParsedEvent, right: ParsedEvent) -> str | None:
    if link_type == "http_path_match":
        return _field_text(left, "url_path") or _field_text(right, "url_path")
    if link_type == "dns_query_match":
        return _field_text(left, "dns_query") or _field_text(right, "dns_query")
    destination_ip = _field_text(left, "destination_ip") or _field_text(right, "destination_ip")
    destination_port = _field_text(left, "destination_port") or _field_text(right, "destination_port")
    return f"{left.source_ip or right.source_ip} -> {destination_ip}:{destination_port}"


def _link_summary(link_type: str, left: ParsedEvent, right: ParsedEvent) -> str:
    if link_type == "http_path_match":
        return f"Suricata and Zeek both observed HTTP path {_field_text(left, 'url_path')}."
    if link_type == "dns_query_match":
        return f"Suricata and Zeek both observed DNS query {_field_text(left, 'dns_query')}."
    return (
        "Suricata and Zeek share flow "
        f"{left.source_ip} -> {_field_text(left, 'destination_ip')}:{_field_text(left, 'destination_port')}."
    )


def _case_quality_summary(
    incidents: list[Any],
    cross_source_links: list[CrossSourceLink],
) -> CaseQualitySummary:
    strongest = incidents[0] if incidents else None
    return CaseQualitySummary(
        strongest_incident_id=strongest.id if strongest else None,
        strongest_incident_title=strongest.title if strongest else None,
        strongest_incident_score=strongest.score if strongest else 0,
        sequence_backed_incident_count=sum(
            1
            for incident in incidents
            if incident.score_breakdown.get("sequence_quality", 0) > 0
        ),
        cross_source_corroborated_incident_count=sum(
            1
            for incident in incidents
            if incident.score_breakdown.get("cross_source_corroboration", 0) > 0
        ),
        total_cross_source_links=len(cross_source_links),
        top_scoring_reason=_top_scoring_reason(strongest),
    )


def _top_scoring_reason(incident: Any | None) -> str | None:
    if incident is None:
        return None
    for rationale in incident.score_rationale:
        if rationale.startswith("Sequence quality:"):
            return rationale
    return incident.score_rationale[0] if incident.score_rationale else None
