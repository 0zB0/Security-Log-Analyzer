from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

from tracehawk_api.models.domain import (
    CorrelationEntityField,
    DetectionRule,
    Finding,
    Incident,
    ParsedEvent,
    RuleCorrelationMetadata,
    Severity,
)
from tracehawk_api.services.correlation_patterns import CorrelationPattern


SEVERITY_SCORE: dict[Severity, int] = {
    "info": 10,
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 95,
}
DEFAULT_CORRELATION_POLICY = RuleCorrelationMetadata()


@dataclass(frozen=True)
class ScoreDetails:
    total: int
    breakdown: dict[str, int]
    rationale: list[str]
    pattern_titles: list[str]
    pattern_summaries: list[str]


def correlate_incidents(
    findings: list[Finding],
    events: list[ParsedEvent],
    cross_source_links: list[Any] | None = None,
    *,
    rules: list[DetectionRule] | None = None,
    patterns: list[CorrelationPattern] | None = None,
) -> list[Incident]:
    event_by_line_id = {event.raw_line_id: event for event in events}
    policies = {rule.id: rule.correlation for rule in rules or []}
    grouped = _bounded_finding_groups(findings, event_by_line_id, policies)
    incidents = [
        _build_incident(
            grouped_findings,
            event_by_line_id,
            cross_source_links or [],
            policies,
            patterns or [],
        )
        for grouped_findings in grouped
    ]
    return sorted(incidents, key=lambda incident: (incident.score, incident.last_seen), reverse=True)


@dataclass
class _FindingGroup:
    findings: list[Finding]
    common_entities: set[str]
    first_seen: datetime
    last_seen: datetime
    max_gap_minutes: int


def _bounded_finding_groups(
    findings: list[Finding],
    event_by_line_id: dict[str, ParsedEvent],
    policies: dict[str, RuleCorrelationMetadata],
) -> list[list[Finding]]:
    if not findings:
        return []

    groups: list[_FindingGroup] = []
    ordered = sorted(findings, key=lambda finding: (finding.first_seen, finding.id))
    for finding in ordered:
        policy = _policy_for(finding, policies)
        entities = _correlation_entities(
            _events_for_finding(finding, event_by_line_id),
            policy.entity_fields,
        )
        candidates: list[tuple[int, int, _FindingGroup]] = []
        for group in groups:
            shared = group.common_entities & entities
            first_seen = min(group.first_seen, finding.first_seen)
            last_seen = max(group.last_seen, finding.last_seen)
            allowed_gap = min(group.max_gap_minutes, policy.max_gap_minutes)
            if shared and last_seen - first_seen <= timedelta(minutes=allowed_gap):
                candidates.append((len(shared), len(group.findings), group))

        if not candidates:
            groups.append(
                _FindingGroup(
                    findings=[finding],
                    common_entities=entities,
                    first_seen=finding.first_seen,
                    last_seen=finding.last_seen,
                    max_gap_minutes=policy.max_gap_minutes,
                )
            )
            continue

        _, _, selected = max(candidates, key=lambda item: (item[0], item[1]))
        selected.findings.append(finding)
        selected.common_entities &= entities
        selected.first_seen = min(selected.first_seen, finding.first_seen)
        selected.last_seen = max(selected.last_seen, finding.last_seen)
        selected.max_gap_minutes = min(selected.max_gap_minutes, policy.max_gap_minutes)

    return [group.findings for group in groups]


def _build_incident(
    findings: list[Finding],
    event_by_line_id: dict[str, ParsedEvent],
    cross_source_links: list[Any],
    policies: dict[str, RuleCorrelationMetadata],
    patterns: list[CorrelationPattern],
) -> Incident:
    events = _events_for_findings(findings, event_by_line_id)
    first_seen = min((finding.first_seen for finding in findings), default=datetime.min)
    last_seen = max((finding.last_seen for finding in findings), default=first_seen)
    severity = _max_severity([finding.severity for finding in findings])
    score = _incident_score(severity, findings, cross_source_links, policies, patterns)
    entities = _entities(events)
    mitre_techniques = sorted(
        {
            finding.mitre.technique_id
            for finding in findings
            if finding.mitre.technique_id is not None
        }
    )
    title = _incident_title(findings, score, policies)
    entity_key = ",".join(
        _correlation_entities(events, ["source_ip", "destination_ip", "username", "host"])
    ) or "no-entity"
    finding_key = ",".join(sorted(finding.id for finding in findings))
    digest = sha256(f"{entity_key}:{first_seen.isoformat()}:{finding_key}".encode()).hexdigest()[:12]

    return Incident(
        id=f"incident:{digest}",
        title=title,
        severity=severity,
        summary=_incident_summary(
            title,
            findings,
            entities,
            cross_source_links,
            score.pattern_summaries,
        ),
        first_seen=first_seen,
        last_seen=last_seen,
        score=score.total,
        finding_ids=[finding.id for finding in findings],
        entities=entities,
        timeline=_timeline(events),
        mitre_techniques=mitre_techniques,
        score_breakdown=score.breakdown,
        score_rationale=score.rationale,
    )


def _incident_score(
    severity: Severity,
    findings: list[Finding],
    cross_source_links: list[Any],
    policies: dict[str, RuleCorrelationMetadata],
    patterns: list[CorrelationPattern],
) -> ScoreDetails:
    base_score = SEVERITY_SCORE[severity]
    finding_score = min(20, max(0, len(findings) - 1) * 4)
    sequence_score, sequence_rationale, pattern_titles, pattern_summaries = _sequence_score(
        findings, policies, patterns
    )
    time_window_score, time_window_rationale = _time_window_score(findings)
    cross_source_score, cross_source_rationale = _cross_source_score(findings, cross_source_links)
    diversity_score, diversity_rationale = _rule_family_diversity_score(findings, policies)
    breakdown = {
        "base_severity": base_score,
        "finding_volume": finding_score,
        "sequence_quality": sequence_score,
        "time_window_proximity": time_window_score,
        "cross_source_corroboration": cross_source_score,
        "rule_family_diversity": diversity_score,
    }
    rationale = [
        f"{severity} severity baseline contributes {base_score}.",
        f"{len(findings)} finding(s) contribute {finding_score} volume point(s).",
    ]
    rationale.extend(sequence_rationale)
    rationale.extend(time_window_rationale)
    rationale.extend(cross_source_rationale)
    rationale.extend(diversity_rationale)
    total = min(100, sum(breakdown.values()))
    return ScoreDetails(
        total=total,
        breakdown=breakdown,
        rationale=rationale,
        pattern_titles=pattern_titles,
        pattern_summaries=pattern_summaries,
    )


def _sequence_score(
    findings: list[Finding],
    policies: dict[str, RuleCorrelationMetadata],
    patterns: list[CorrelationPattern],
) -> tuple[int, list[str], list[str], list[str]]:
    rationale: list[str] = []
    pattern_titles: list[str] = []
    pattern_summaries: list[str] = []
    score = 0
    for finding in findings:
        policy = _policy_for(finding, policies)
        if policy.intrinsic_sequence_score:
            score += policy.intrinsic_sequence_score
            rationale.append(
                "Sequence quality: declared intrinsic sequence: "
                f"{policy.intrinsic_sequence_rationale or finding.title}"
            )
            if policy.intrinsic_sequence_summary:
                pattern_summaries.append(policy.intrinsic_sequence_summary)

    for pattern in patterns:
        if not _pattern_matches(pattern, findings, policies):
            continue
        score += pattern.score
        rationale.append(f"Sequence quality: pattern {pattern.id}: {pattern.rationale}")
        pattern_titles.append(pattern.title)
        pattern_summaries.append(pattern.summary)

    return min(score, 25), rationale, pattern_titles, pattern_summaries


def _pattern_matches(
    pattern: CorrelationPattern,
    findings: list[Finding],
    policies: dict[str, RuleCorrelationMetadata],
) -> bool:
    ordered = sorted(findings, key=lambda finding: (finding.last_seen, finding.id))
    return _match_pattern_stage(
        pattern,
        ordered,
        policies,
        stage_index=0,
        used_finding_ids=set(),
        first_time=None,
        previous_time=None,
    )


def _match_pattern_stage(
    pattern: CorrelationPattern,
    ordered: list[Finding],
    policies: dict[str, RuleCorrelationMetadata],
    *,
    stage_index: int,
    used_finding_ids: set[str],
    first_time: datetime | None,
    previous_time: datetime | None,
) -> bool:
    if stage_index == len(pattern.stages):
        return True

    stage_behaviors = set(pattern.stages[stage_index].any_behaviors)
    for candidate in ordered:
        if candidate.id in used_finding_ids:
            continue
        if previous_time is not None and candidate.last_seen < previous_time:
            continue
        if not set(_policy_for(candidate, policies).behaviors) & stage_behaviors:
            continue
        sequence_start = first_time or candidate.last_seen
        if candidate.last_seen - sequence_start > timedelta(minutes=pattern.max_gap_minutes):
            continue
        if _match_pattern_stage(
            pattern,
            ordered,
            policies,
            stage_index=stage_index + 1,
            used_finding_ids=used_finding_ids | {candidate.id},
            first_time=sequence_start,
            previous_time=candidate.last_seen,
        ):
            return True
    return False


def _time_window_score(findings: list[Finding]) -> tuple[int, list[str]]:
    if len(findings) < 2:
        return 0, []
    first_seen = min(finding.first_seen for finding in findings)
    last_seen = max(finding.last_seen for finding in findings)
    span_seconds = max(0.0, (last_seen - first_seen).total_seconds())
    if span_seconds <= 5 * 60:
        return 10, ["Time-window proximity: related findings occur within five minutes."]
    if span_seconds <= 15 * 60:
        return 6, ["Time-window proximity: related findings occur within fifteen minutes."]
    if span_seconds <= 60 * 60:
        return 3, ["Time-window proximity: related findings occur within one hour."]
    return 0, []


def _cross_source_score(findings: list[Finding], cross_source_links: list[Any]) -> tuple[int, list[str]]:
    related_links = _related_cross_source_links(findings, cross_source_links)
    if not related_links:
        return 0, []
    link_types = {
        str(getattr(link, "link_type", "unknown"))
        for link in related_links
        if getattr(link, "link_type", None)
    }
    source_pairs = {
        (str(getattr(link, "source_label", "")), str(getattr(link, "target_label", "")))
        for link in related_links
    }
    score = min(18, len(related_links) * 2 + len(link_types) * 3 + len(source_pairs))
    type_text = ", ".join(sorted(link_types)) or "unknown link type"
    return score, [
        "Cross-source corroboration: "
        f"{len(related_links)} related link(s) across {type_text} contribute {score} point(s)."
    ]


def _related_cross_source_links(findings: list[Finding], cross_source_links: list[Any]) -> list[Any]:
    if not cross_source_links:
        return []
    finding_line_ids = {line_id for finding in findings for line_id in finding.evidence_line_ids}
    return [
        link
        for link in cross_source_links
        if getattr(link, "source_raw_line_id", None) in finding_line_ids
        or getattr(link, "target_raw_line_id", None) in finding_line_ids
    ]


def _rule_family_diversity_score(
    findings: list[Finding],
    policies: dict[str, RuleCorrelationMetadata],
) -> tuple[int, list[str]]:
    families = {_family_for(finding, policies) for finding in findings}
    if len(families) < 2:
        return 0, []
    score = min(10, (len(families) - 1) * 2)
    return score, [
        f"Rule-family diversity: {len(families)} families ({', '.join(sorted(families))}) contribute {score} point(s)."
    ]


def _family_for(
    finding: Finding,
    policies: dict[str, RuleCorrelationMetadata],
) -> str:
    policy = _policy_for(finding, policies)
    if policy.family:
        return policy.family
    tactic = finding.mitre.tactic or "unclassified"
    return tactic.strip().lower().replace(" ", "_")


def _policy_for(
    finding: Finding,
    policies: dict[str, RuleCorrelationMetadata],
) -> RuleCorrelationMetadata:
    return policies.get(finding.rule_id, DEFAULT_CORRELATION_POLICY)


def _events_for_findings(
    findings: list[Finding], event_by_line_id: dict[str, ParsedEvent]
) -> list[ParsedEvent]:
    events: list[ParsedEvent] = []
    seen: set[str] = set()
    for finding in findings:
        for event in _events_for_finding(finding, event_by_line_id):
            if event.id not in seen:
                events.append(event)
                seen.add(event.id)
    return sorted(events, key=_event_time_sort_key)


def _event_time_sort_key(event: ParsedEvent) -> tuple[bool, float, str]:
    event_time = event.event_time
    if event_time is None:
        return True, 0.0, event.id
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=UTC)
    return False, event_time.timestamp(), event.id


def _events_for_finding(
    finding: Finding, event_by_line_id: dict[str, ParsedEvent]
) -> list[ParsedEvent]:
    return [
        event
        for line_id in finding.evidence_line_ids
        if (event := event_by_line_id.get(line_id)) is not None
    ]


def _entities(events: list[ParsedEvent]) -> list[str]:
    values: set[str] = set()
    for event in events:
        if event.source_ip:
            values.add(f"ip:{event.source_ip}")
        if destination_ip := event.normalized_fields.get("destination_ip"):
            values.add(f"dst:{destination_ip}")
        if destination_port := event.normalized_fields.get("destination_port"):
            values.add(f"port:{destination_port}")
        if event.username:
            values.add(f"user:{event.username}")
        if event.host:
            values.add(f"host:{event.host}")
    return sorted(values)


def _correlation_entities(
    events: list[ParsedEvent],
    fields: list[CorrelationEntityField],
) -> set[str]:
    values: set[str] = set()
    enabled = set(fields)
    for event in events:
        if "source_ip" in enabled and event.source_ip:
            values.add(f"ip:{event.source_ip}")
        if (
            "destination_ip" in enabled
            and (destination_ip := event.normalized_fields.get("destination_ip"))
        ):
            values.add(f"dst:{destination_ip}")
        if "username" in enabled and event.username:
            values.add(f"user:{event.username}")
    if values or "host" not in enabled:
        return values
    return {f"host:{event.host}" for event in events if event.host}


def _timeline(events: list[ParsedEvent]) -> list[str]:
    items: list[str] = []
    for event in events[:30]:
        timestamp = event.event_time.isoformat() if event.event_time else "unknown-time"
        actor = event.source_ip or event.username or event.host or "unknown-entity"
        items.append(f"{timestamp} | {event.event_type} | {actor} | {event.message}")
    return items


def _max_severity(severities: list[Severity]) -> Severity:
    return max(severities, key=lambda severity: SEVERITY_SCORE[severity], default="info")


def _incident_title(
    findings: list[Finding],
    score: ScoreDetails,
    policies: dict[str, RuleCorrelationMetadata],
) -> str:
    if score.pattern_titles:
        return score.pattern_titles[0]
    if len(findings) == 1:
        return findings[0].title
    declared = [
        (finding, policy.incident_title)
        for finding in findings
        if (policy := _policy_for(finding, policies)).incident_title
    ]
    if declared:
        _, title = max(
            declared,
            key=lambda item: (
                SEVERITY_SCORE[item[0].severity],
                item[0].event_count,
                item[0].id,
            ),
        )
        assert title is not None
        return title
    dominant = max(
        findings,
        key=lambda finding: (SEVERITY_SCORE[finding.severity], finding.event_count, finding.id),
    )
    return f"{dominant.title} and related activity"


def _incident_summary(
    title: str,
    findings: list[Finding],
    entities: list[str],
    cross_source_links: list[Any],
    pattern_summaries: list[str],
) -> str:
    entity_text = ", ".join(entities[:5]) if entities else "unknown entities"
    parts = [f"{title} grouped {len(findings)} finding(s) involving {entity_text}."]
    parts.extend(dict.fromkeys(pattern_summaries))
    corroborated_count = _cross_source_corroboration_count(findings, cross_source_links)
    if corroborated_count:
        parts.append(f"Cross-source corroboration links {corroborated_count} related evidence pair(s).")
    return " ".join(parts)


def _cross_source_corroboration_count(findings: list[Finding], cross_source_links: list[Any]) -> int:
    if not cross_source_links:
        return 0
    finding_line_ids = {line_id for finding in findings for line_id in finding.evidence_line_ids}
    return sum(
        1
        for link in cross_source_links
        if getattr(link, "source_raw_line_id", None) in finding_line_ids
        or getattr(link, "target_raw_line_id", None) in finding_line_ids
    )
