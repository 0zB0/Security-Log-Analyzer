from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

from tracehawk_api.models.domain import Finding, Incident, ParsedEvent, Severity


SEVERITY_SCORE: dict[Severity, int] = {
    "info": 10,
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 95,
}


@dataclass(frozen=True)
class ScoreDetails:
    total: int
    breakdown: dict[str, int]
    rationale: list[str]


def correlate_incidents(
    findings: list[Finding],
    events: list[ParsedEvent],
    cross_source_links: list[Any] | None = None,
) -> list[Incident]:
    event_by_line_id = {event.raw_line_id: event for event in events}
    grouped = _connected_finding_groups(findings, event_by_line_id)
    incidents = [
        _build_incident(grouped_findings, event_by_line_id, cross_source_links or [])
        for grouped_findings in grouped
    ]
    return sorted(incidents, key=lambda incident: (incident.score, incident.last_seen), reverse=True)


def _connected_finding_groups(
    findings: list[Finding], event_by_line_id: dict[str, ParsedEvent]
) -> list[list[Finding]]:
    if not findings:
        return []

    entities_by_finding = {
        finding.id: _correlation_entities(_events_for_finding(finding, event_by_line_id))
        for finding in findings
    }
    adjacency: dict[str, set[str]] = {finding.id: set() for finding in findings}

    for index, left in enumerate(findings):
        left_entities = entities_by_finding[left.id]
        for right in findings[index + 1 :]:
            if left_entities & entities_by_finding[right.id]:
                adjacency[left.id].add(right.id)
                adjacency[right.id].add(left.id)

    finding_by_id = {finding.id: finding for finding in findings}
    seen: set[str] = set()
    groups: list[list[Finding]] = []
    for finding in findings:
        if finding.id in seen:
            continue

        stack = [finding.id]
        component_ids: list[str] = []
        seen.add(finding.id)
        while stack:
            current = stack.pop()
            component_ids.append(current)
            for linked in sorted(adjacency[current]):
                if linked not in seen:
                    seen.add(linked)
                    stack.append(linked)

        groups.append([finding_by_id[finding_id] for finding_id in component_ids])

    return groups


def _build_incident(
    findings: list[Finding],
    event_by_line_id: dict[str, ParsedEvent],
    cross_source_links: list[Any],
) -> Incident:
    events = _events_for_findings(findings, event_by_line_id)
    first_seen = min((finding.first_seen for finding in findings), default=datetime.min)
    last_seen = max((finding.last_seen for finding in findings), default=first_seen)
    severity = _max_severity([finding.severity for finding in findings])
    score = _incident_score(severity, findings, cross_source_links)
    entities = _entities(events)
    mitre_techniques = sorted(
        {
            finding.mitre.technique_id
            for finding in findings
            if finding.mitre.technique_id is not None
        }
    )
    title = _incident_title(findings)
    entity_key = ",".join(_correlation_entities(events)) or "no-entity"
    finding_key = ",".join(sorted(finding.id for finding in findings))
    digest = sha256(f"{entity_key}:{first_seen.isoformat()}:{finding_key}".encode()).hexdigest()[:12]

    return Incident(
        id=f"incident:{digest}",
        title=title,
        severity=severity,
        summary=_incident_summary(title, findings, entities, cross_source_links),
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
) -> ScoreDetails:
    base_score = SEVERITY_SCORE[severity]
    finding_score = min(20, max(0, len(findings) - 1) * 4)
    sequence_score, sequence_rationale = _sequence_score(findings)
    time_window_score, time_window_rationale = _time_window_score(findings)
    cross_source_score, cross_source_rationale = _cross_source_score(findings, cross_source_links)
    diversity_score, diversity_rationale = _rule_family_diversity_score(findings)
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
    return ScoreDetails(total=total, breakdown=breakdown, rationale=rationale)


def _sequence_score(findings: list[Finding]) -> tuple[int, list[str]]:
    rule_ids = {finding.rule_id for finding in findings}
    rationale: list[str] = []
    score = 0
    if "ssh-compromise-sequence-001" in rule_ids:
        score += 5
        rationale.append(
            "Sequence quality: a three-step SSH failure, success, and privileged action chain matched."
        )
    if {"ssh-bruteforce-001", "ssh-success-after-failures-001"} <= rule_ids and _rules_ordered_within(
        findings, {"ssh-bruteforce-001"}, {"ssh-success-after-failures-001"}, minutes=15
    ):
        score += 15
        rationale.append("Sequence quality: SSH failures are followed by a successful login.")
    if (
        "ssh-success-after-failures-001" in rule_ids
        and any(rule_id.startswith("sudo-") for rule_id in rule_ids)
        and _rules_ordered_within(findings, {"ssh-success-after-failures-001"}, _sudo_rule_ids(rule_ids), minutes=30)
    ):
        score += 5
        rationale.append("Sequence quality: successful SSH login is followed by sudo activity.")
    if _has_scan(rule_ids) and _has_sensitive_http(rule_ids) and _rules_ordered_within(
        findings, _scan_rule_ids(rule_ids), _sensitive_http_rule_ids(rule_ids), minutes=15
    ):
        score += 10
        rationale.append("Sequence quality: scan activity is followed by sensitive HTTP access.")
    if _has_dns_burst(rule_ids) and _has_c2_or_high_alert(rule_ids) and _rules_ordered_within(
        findings, _dns_burst_rule_ids(rule_ids), _c2_or_high_alert_rule_ids(rule_ids), minutes=15
    ):
        score += 10
        rationale.append("Sequence quality: DNS burst is followed by alert or C2 activity.")
    if {
        "suricata-alert-burst-001",
        "suricata-high-severity-alert-001",
    } <= rule_ids:
        score += 10
        rationale.append("Sequence quality: alert burst includes high severity Suricata evidence.")
    return min(score, 25), rationale


def _rules_ordered_within(
    findings: list[Finding],
    first_rule_ids: set[str],
    second_rule_ids: set[str],
    *,
    minutes: int,
) -> bool:
    first_findings = [finding for finding in findings if finding.rule_id in first_rule_ids]
    second_findings = [finding for finding in findings if finding.rule_id in second_rule_ids]
    if not first_findings or not second_findings:
        return False
    window = timedelta(minutes=minutes)
    return any(
        first.first_seen <= second.last_seen and second.last_seen - first.first_seen <= window
        for first in first_findings
        for second in second_findings
    )


def _scan_rule_ids(rule_ids: set[str]) -> set[str]:
    return {rule_id for rule_id in rule_ids if _is_scan_rule(rule_id)}


def _sensitive_http_rule_ids(rule_ids: set[str]) -> set[str]:
    return {rule_id for rule_id in rule_ids if _is_sensitive_http_rule(rule_id)}


def _dns_burst_rule_ids(rule_ids: set[str]) -> set[str]:
    return {rule_id for rule_id in rule_ids if "dns-burst" in rule_id}


def _c2_or_high_alert_rule_ids(rule_ids: set[str]) -> set[str]:
    return {rule_id for rule_id in rule_ids if "c2" in rule_id or "high-severity-alert" in rule_id}


def _sudo_rule_ids(rule_ids: set[str]) -> set[str]:
    return {rule_id for rule_id in rule_ids if rule_id.startswith("sudo-")}


def _has_scan(rule_ids: set[str]) -> bool:
    return any(_is_scan_rule(rule_id) for rule_id in rule_ids)


def _is_scan_rule(rule_id: str) -> bool:
    return "scan" in rule_id or "reconnaissance" in rule_id


def _has_sensitive_http(rule_ids: set[str]) -> bool:
    return any(_is_sensitive_http_rule(rule_id) for rule_id in rule_ids)


def _is_sensitive_http_rule(rule_id: str) -> bool:
    return any(
        marker in rule_id
        for marker in ("sensitive-path", "sensitive-file", "source-code-extension")
    )


def _has_dns_burst(rule_ids: set[str]) -> bool:
    return any("dns-burst" in rule_id for rule_id in rule_ids)


def _has_c2_or_high_alert(rule_ids: set[str]) -> bool:
    return any("c2" in rule_id or "high-severity-alert" in rule_id for rule_id in rule_ids)


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


def _rule_family_diversity_score(findings: list[Finding]) -> tuple[int, list[str]]:
    families = {_rule_family(finding.rule_id) for finding in findings}
    if len(families) < 2:
        return 0, []
    score = min(10, (len(families) - 1) * 2)
    return score, [
        f"Rule-family diversity: {len(families)} families ({', '.join(sorted(families))}) contribute {score} point(s)."
    ]


def _rule_family(rule_id: str) -> str:
    if "dns" in rule_id:
        return "dns"
    if "http" in rule_id or "web" in rule_id:
        return "http"
    if "ssh" in rule_id:
        return "ssh"
    if "sudo" in rule_id:
        return "sudo"
    if "scan" in rule_id or "reconnaissance" in rule_id:
        return "scan"
    if "c2" in rule_id:
        return "c2"
    if "alert" in rule_id:
        return "alert"
    return rule_id.split("-", maxsplit=1)[0]


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


def _correlation_entities(events: list[ParsedEvent]) -> set[str]:
    values: set[str] = set()
    for event in events:
        if event.source_ip:
            values.add(f"ip:{event.source_ip}")
        if destination_ip := event.normalized_fields.get("destination_ip"):
            values.add(f"dst:{destination_ip}")
        if event.username:
            values.add(f"user:{event.username}")

    if values:
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


def _incident_title(findings: list[Finding]) -> str:
    rule_ids = {finding.rule_id for finding in findings}
    if "ssh-success-after-failures-001" in rule_ids:
        return "Possible SSH credential compromise"
    if "ssh-bruteforce-001" in rule_ids:
        return "SSH brute force activity"
    if any(rule_id.startswith("sudo-") for rule_id in rule_ids):
        return "Privileged sudo activity"
    if "web-sensitive-file-access-001" in rule_ids:
        return "Web probing against sensitive files"
    if len(findings) == 1:
        return findings[0].title
    return "Correlated security activity"


def _incident_summary(
    title: str,
    findings: list[Finding],
    entities: list[str],
    cross_source_links: list[Any],
) -> str:
    entity_text = ", ".join(entities[:5]) if entities else "unknown entities"
    parts = [f"{title} grouped {len(findings)} finding(s) involving {entity_text}."]
    parts.extend(_sequence_summary_parts({finding.rule_id for finding in findings}))
    corroborated_count = _cross_source_corroboration_count(findings, cross_source_links)
    if corroborated_count:
        parts.append(f"Cross-source corroboration links {corroborated_count} related evidence pair(s).")
    return " ".join(parts)


def _sequence_summary_parts(rule_ids: set[str]) -> list[str]:
    parts: list[str] = []
    if {"ssh-bruteforce-001", "ssh-success-after-failures-001"} <= rule_ids:
        parts.append("Sequence: SSH failures followed by a successful login.")
    if "ssh-success-after-failures-001" in rule_ids and any(rule_id.startswith("sudo-") for rule_id in rule_ids):
        parts.append("Sequence: successful SSH login followed by sudo activity.")
    if _has_scan(rule_ids) and _has_sensitive_http(rule_ids):
        parts.append("Sequence: scan activity followed by sensitive HTTP access.")
    if _has_dns_burst(rule_ids) and _has_c2_or_high_alert(rule_ids):
        parts.append("Sequence: DNS burst followed by alert or C2 activity.")
    if "suricata-alert-burst-001" in rule_ids and "suricata-high-severity-alert-001" in rule_ids:
        parts.append("Sequence: alert burst includes high severity Suricata evidence.")
    return parts


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
