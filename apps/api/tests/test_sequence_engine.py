from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from tracehawk_api.models.domain import DetectionRule, ParsedEvent
from tracehawk_api.services.detection import run_detection


BASE = datetime(2026, 7, 9, 10, 0, tzinfo=UTC)


def test_three_step_sequence_matches_ordered_events_and_evidence() -> None:
    rule = _rule(
        [
            {"event_type": "failure", "count_gte": 2},
            {"event_type": "success"},
            {
                "event_type": "sudo",
                "field_contains_any": {"command": ["useradd"]},
            },
        ]
    )
    events = [
        _event(1, "failure"),
        _event(2, "failure"),
        _event(3, "success"),
        _event(4, "sudo", command="/usr/sbin/useradd backup"),
    ]

    findings = run_detection([rule], events)

    assert len(findings) == 1
    assert findings[0].event_count == 4
    assert findings[0].evidence_line_ids == ["line:1", "line:2", "line:3", "line:4"]
    assert "3 ordered sequence steps" in findings[0].summary


@pytest.mark.parametrize(
    "event_specs",
    [
        [(1, "failure"), (2, "failure"), (3, "sudo")],
        [(1, "success"), (2, "failure"), (3, "sudo")],
        [(1, "failure"), (2, "failure"), (20, "success"), (21, "sudo")],
    ],
    ids=["missing-middle", "wrong-order", "outside-window"],
)
def test_three_step_sequence_rejects_incomplete_or_unordered_events(
    event_specs: list[tuple[int, str]],
) -> None:
    rule = _rule(
        [
            {"event_type": "failure", "count_gte": 2},
            {"event_type": "success"},
            {"event_type": "sudo"},
        ],
        window_minutes=10,
    )

    events = [_event(minute, event_type) for minute, event_type in event_specs]
    assert run_detection([rule], events) == []


def test_sequence_grouping_does_not_mix_users() -> None:
    rule = _rule(
        [
            {"event_type": "failure", "count_gte": 2},
            {"event_type": "success"},
        ]
    )
    events = [
        _event(1, "failure", username="alice"),
        _event(2, "failure", username="bob"),
        _event(3, "success", username="alice"),
    ]

    assert run_detection([rule], events) == []


def test_existing_two_step_shape_remains_supported() -> None:
    rule = _rule(
        [
            {"event_type": "failure", "count_gte": 2},
            {"event_type": "success"},
        ]
    )

    findings = run_detection(
        [rule],
        [_event(1, "failure"), _event(2, "failure"), _event(3, "success")],
    )

    assert len(findings) == 1
    assert findings[0].event_count == 3


@pytest.mark.parametrize(
    "steps",
    [
        [{"event_type": "one"}],
        [{"event_type": f"step-{index}"} for index in range(9)],
        [{"event_type": "one"}, {"event_type": "two", "unknown": True}],
    ],
    ids=["one-step", "nine-steps", "unknown-field"],
)
def test_invalid_sequence_rules_fail_validation(steps: list[dict]) -> None:
    with pytest.raises(ValidationError):
        _rule(steps)


def _rule(steps: list[dict], *, window_minutes: int = 15) -> DetectionRule:
    return DetectionRule.model_validate(
        {
            "id": "test-sequence-001",
            "title": "Test sequence",
            "description": "Test ordered sequence.",
            "severity": "high",
            "confidence": "high",
            "log_types": ["test"],
            "conditions": {
                "sequence": steps,
                "group_by": ["username"],
                "window_minutes": window_minutes,
            },
        }
    )


def _event(
    minute: int,
    event_type: str,
    *,
    username: str = "alice",
    command: str | None = None,
) -> ParsedEvent:
    fields = {"command": command} if command else {}
    return ParsedEvent(
        id=f"event:{minute}:{event_type}:{username}",
        source_id="sequence-test",
        raw_line_id=f"line:{minute}",
        event_time=BASE + timedelta(minutes=minute),
        event_type=event_type,
        username=username,
        message=event_type,
        normalized_fields=fields,
    )
