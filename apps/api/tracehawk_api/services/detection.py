from collections import Counter, defaultdict, deque
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

from tracehawk_api.models.domain import (
    DetectionRule,
    Finding,
    MitreMapping,
    ParsedEvent,
    SequenceStep,
)


def run_detection(rules: list[DetectionRule], events: list[ParsedEvent]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        if rule.conditions.sequence:
            findings.extend(_run_sequence_rule(rule, events))
        elif rule.conditions.periodic_count_gte is not None:
            findings.extend(_run_periodic_rule(rule, events))
        elif rule.conditions.distinct_count_gte is not None:
            findings.extend(_run_distinct_rule(rule, events))
        elif rule.conditions.count_gte is not None:
            findings.extend(_run_threshold_rule(rule, events))
        elif (
            rule.conditions.path_contains_any
            or rule.conditions.field_contains_any
            or rule.conditions.field_in
            or rule.conditions.field_equals
        ):
            findings.extend(_run_field_match_rule(rule, events))
    return findings


def _run_threshold_rule(rule: DetectionRule, events: list[ParsedEvent]) -> list[Finding]:
    matching = [event for event in events if _event_matches_conditions(event, rule.conditions)]
    grouped = _group_events(matching, rule.conditions.group_by)
    findings: list[Finding] = []
    for group_key, group_events in grouped.items():
        group_events = _sort_events(group_events)
        for window in _matching_windows(
            group_events, rule.conditions.window_minutes, rule.conditions.count_gte or 1
        ):
            findings.append(_build_finding(rule, window, group_key))
            break
    return findings


def _run_distinct_rule(rule: DetectionRule, events: list[ParsedEvent]) -> list[Finding]:
    distinct_field = rule.conditions.distinct_field
    if distinct_field is None:
        return []

    matching = [event for event in events if _event_matches_conditions(event, rule.conditions)]
    grouped = _group_events(matching, rule.conditions.group_by)
    findings: list[Finding] = []
    for group_key, group_events in grouped.items():
        group_events = _sort_events(group_events)
        window = _matching_distinct_window(
            group_events,
            rule.conditions.window_minutes,
            distinct_field,
            rule.conditions.distinct_count_gte or 1,
        )
        if window:
            findings.append(_build_finding(rule, window, group_key))
    return findings


def _run_periodic_rule(rule: DetectionRule, events: list[ParsedEvent]) -> list[Finding]:
    matching = [event for event in events if _event_matches_conditions(event, rule.conditions)]
    grouped = _group_events(matching, rule.conditions.group_by)
    findings: list[Finding] = []
    for group_key, group_events in grouped.items():
        group_events = _sort_events(group_events)
        window = _matching_periodic_window(
            group_events,
            rule.conditions.window_minutes,
            rule.conditions.periodic_count_gte or 1,
            rule.conditions.periodic_jitter_seconds_lte,
            rule.conditions.periodic_interval_seconds_min,
            rule.conditions.periodic_interval_seconds_max,
        )
        if window:
            findings.append(_build_finding(rule, window, group_key))
    return findings


def _run_sequence_rule(rule: DetectionRule, events: list[ParsedEvent]) -> list[Finding]:
    grouped = _group_events(events, rule.conditions.group_by)
    findings: list[Finding] = []
    for group_key, group_events in grouped.items():
        ordered = _sort_events(group_events)
        steps = rule.conditions.sequence or []
        matched = _matching_sequence(ordered, steps, rule.conditions.window_minutes)
        if matched:
            findings.append(
                _build_finding(
                    rule,
                    matched,
                    group_key,
                    sequence_step_count=len(steps),
                )
            )
    return findings


def _matching_sequence(
    events: list[ParsedEvent],
    steps: list[SequenceStep],
    window_minutes: int,
) -> list[ParsedEvent] | None:
    if not steps:
        return None

    for start_index, start in enumerate(events):
        if start.event_time is None or not _event_matches_sequence_step(start, steps[0]):
            continue

        window_end = start.event_time + timedelta(minutes=window_minutes)
        cursor = start_index
        matched: list[ParsedEvent] = []
        complete = True
        for step in steps:
            step_matches: list[ParsedEvent] = []
            while cursor < len(events) and len(step_matches) < step.count_gte:
                candidate = events[cursor]
                cursor += 1
                if candidate.event_time is None:
                    continue
                if candidate.event_time > window_end:
                    break
                if _event_matches_sequence_step(candidate, step):
                    step_matches.append(candidate)
            if len(step_matches) < step.count_gte:
                complete = False
                break
            matched.extend(step_matches)
        if complete:
            return matched
    return None


def _event_matches_sequence_step(event: ParsedEvent, step: SequenceStep) -> bool:
    if event.event_type != step.event_type:
        return False
    for field, expected in step.field_equals.items():
        if not _values_equal(_field_value(event, field), expected):
            return False
    for field, expected_values in step.field_in.items():
        if not any(_values_equal(_field_value(event, field), value) for value in expected_values):
            return False
    for field, needles in step.field_contains_any.items():
        value_text = str(_field_value(event, field) or "").lower()
        if not any(needle.lower() in value_text for needle in needles):
            return False
    return True


def _run_field_match_rule(rule: DetectionRule, events: list[ParsedEvent]) -> list[Finding]:
    matching = [event for event in events if _event_matches_conditions(event, rule.conditions)]
    grouped = _group_events(matching, rule.conditions.group_by or ["source_ip"])
    return [_build_finding(rule, group_events, group_key) for group_key, group_events in grouped.items()]


def _group_events(events: list[ParsedEvent], fields: list[str]) -> dict[tuple[Any, ...], list[ParsedEvent]]:
    grouped: dict[tuple[Any, ...], list[ParsedEvent]] = defaultdict(list)
    for event in events:
        key = tuple(_field_value(event, field) for field in fields) if fields else ("all",)
        if all(value is not None for value in key):
            grouped[key].append(event)
    return grouped


def _matching_windows(
    events: list[ParsedEvent], window_minutes: int, minimum_count: int
) -> Iterator[list[ParsedEvent]]:
    for start_index, start in enumerate(events):
        if start.event_time is None:
            continue
        window_end = start.event_time + timedelta(minutes=window_minutes)
        window = [
            event
            for event in events[start_index:]
            if event.event_time is not None and start.event_time <= event.event_time <= window_end
        ]
        if len(window) >= minimum_count:
            yield window


def _matching_distinct_window(
    events: list[ParsedEvent],
    window_minutes: int,
    distinct_field: str,
    minimum_distinct: int,
) -> list[ParsedEvent] | None:
    window: deque[ParsedEvent] = deque()
    value_counts: Counter[Any] = Counter()
    maximum_span = timedelta(minutes=window_minutes)
    for event in events:
        if event.event_time is None:
            continue
        while window:
            first_time = window[0].event_time
            if first_time is None or event.event_time - first_time <= maximum_span:
                break
            removed = window.popleft()
            removed_value = _field_value(removed, distinct_field)
            if removed_value is not None:
                value_counts[removed_value] -= 1
                if value_counts[removed_value] <= 0:
                    del value_counts[removed_value]
        window.append(event)
        value = _field_value(event, distinct_field)
        if value is not None:
            value_counts[value] += 1
        if len(value_counts) >= minimum_distinct:
            return list(window)
    return None


def _matching_periodic_window(
    events: list[ParsedEvent],
    window_minutes: int,
    minimum_count: int,
    jitter_seconds_lte: float | None,
    interval_seconds_min: float | None,
    interval_seconds_max: float | None,
) -> list[ParsedEvent] | None:
    timed_events = [event for event in events if event.event_time is not None]
    if len(timed_events) < minimum_count:
        return None

    for start_index, start in enumerate(timed_events):
        if start.event_time is None:
            continue
        window_end = start.event_time + timedelta(minutes=window_minutes)
        window = [
            event
            for event in timed_events[start_index:]
            if event.event_time is not None and start.event_time <= event.event_time <= window_end
        ]
        if len(window) < minimum_count:
            continue
        for end_index in range(minimum_count, len(window) + 1):
            candidate = window[:end_index]
            if _is_periodic(
                candidate,
                jitter_seconds_lte,
                interval_seconds_min,
                interval_seconds_max,
            ):
                return candidate
    return None


def _is_periodic(
    events: list[ParsedEvent],
    jitter_seconds_lte: float | None,
    interval_seconds_min: float | None,
    interval_seconds_max: float | None,
) -> bool:
    if len(events) < 2:
        return False
    timestamps = [event.event_time for event in events if event.event_time is not None]
    if len(timestamps) != len(events):
        return False

    deltas = [
        (timestamps[index] - timestamps[index - 1]).total_seconds()
        for index in range(1, len(timestamps))
    ]
    average_delta = sum(deltas) / len(deltas)
    if interval_seconds_min is not None and average_delta < interval_seconds_min:
        return False
    if interval_seconds_max is not None and average_delta > interval_seconds_max:
        return False
    if jitter_seconds_lte is not None:
        max_jitter = max(abs(delta - average_delta) for delta in deltas)
        if max_jitter > jitter_seconds_lte:
            return False
    return True


def _sort_events(events: list[ParsedEvent]) -> list[ParsedEvent]:
    def sort_key(event: ParsedEvent) -> tuple[bool, float, str]:
        event_time = event.event_time
        if event_time is None:
            return True, 0.0, event.id
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=UTC)
        return False, event_time.timestamp(), event.id

    return sorted(events, key=sort_key)


def _build_finding(
    rule: DetectionRule,
    events: list[ParsedEvent],
    group_key: tuple[Any, ...],
    *,
    sequence_step_count: int = 0,
) -> Finding:
    ordered = _sort_events(events)
    evidence_ids = [event.raw_line_id for event in ordered]
    limited_evidence_ids = evidence_ids[: rule.evidence.max_lines]
    first_seen = ordered[0].event_time or datetime.now(UTC)
    last_seen = ordered[-1].event_time or first_seen
    group_label = ", ".join(str(value) for value in group_key)
    finding_hash = sha256(
        f"{rule.id}:{group_label}:{first_seen.isoformat()}:{last_seen.isoformat()}".encode("utf-8")
    ).hexdigest()[:12]

    summary = f"{rule.title} matched {len(ordered)} event(s) for {group_label}."
    if sequence_step_count:
        summary = (
            f"{rule.title} matched {sequence_step_count} ordered sequence steps "
            f"across {len(ordered)} event(s) for {group_label}."
        )

    return Finding(
        id=f"finding:{rule.id}:{finding_hash}",
        rule_id=rule.id,
        title=rule.title,
        severity=rule.severity,
        confidence=rule.confidence,
        summary=summary,
        reason=rule.description,
        mitre=MitreMapping.model_validate(rule.mitre.model_dump()),
        first_seen=first_seen,
        last_seen=last_seen,
        event_count=len(ordered),
        evidence_line_ids=limited_evidence_ids,
    )


def _event_matches_conditions(event: ParsedEvent, conditions: Any) -> bool:
    if conditions.event_type is not None and event.event_type != conditions.event_type:
        return False

    for field, expected in conditions.field_equals.items():
        if _field_value(event, field) != expected:
            return False

    for field, expected_values in conditions.field_in.items():
        if not any(_values_equal(_field_value(event, field), expected) for expected in expected_values):
            return False

    field_contains_any = dict(conditions.field_contains_any)
    if conditions.path_contains_any:
        field_contains_any.setdefault("url_path", []).extend(conditions.path_contains_any)

    for field, needles in field_contains_any.items():
        value = _field_value(event, field)
        value_text = str(value or "").lower()
        if not any(needle.lower() in value_text for needle in needles):
            return False

    return True


def _values_equal(left: Any, right: Any) -> bool:
    if left == right:
        return True
    return str(left) == str(right)


def _field_value(event: ParsedEvent, field: str) -> Any:
    if hasattr(event, field):
        return getattr(event, field)
    return event.normalized_fields.get(field)
