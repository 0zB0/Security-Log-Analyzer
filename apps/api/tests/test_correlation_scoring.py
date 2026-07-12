from datetime import UTC, datetime, timedelta
from pathlib import Path

from tracehawk_api.models.domain import Finding, MitreMapping, ParsedEvent
from tracehawk_api.services.analysis import CrossSourceLink
from tracehawk_api.services.correlation import correlate_incidents
from tracehawk_api.services.correlation_patterns import (
    default_correlation_pattern_path,
    load_correlation_patterns,
)
from tracehawk_api.services.rules import load_rules


BASE_TIME = datetime(2026, 7, 9, 8, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[3]
RULES = load_rules(ROOT / "packages/rules")
PATTERNS = load_correlation_patterns(
    default_correlation_pattern_path(ROOT / "packages/rules"), RULES
)


def test_dns_burst_without_alert_or_c2_gets_no_sequence_score() -> None:
    incidents = _correlate(
        [
            _finding("zeek-dns-burst-001", "medium", 0),
            _finding("zeek-http-sensitive-path-001", "high", 2),
        ],
        [
            _event("line:zeek-dns-burst-001", 0),
            _event("line:zeek-http-sensitive-path-001", 2),
        ],
    )

    assert len(incidents) == 1
    assert incidents[0].score_breakdown["sequence_quality"] == 0
    assert not any("DNS burst is followed" in item for item in incidents[0].score_rationale)


def test_scan_without_sensitive_http_follow_up_gets_no_sequence_score() -> None:
    incidents = _correlate(
        [
            _finding("zeek-conn-port-scan-001", "high", 0),
            _finding("suricata-high-severity-alert-001", "critical", 2),
        ],
        [
            _event("line:zeek-conn-port-scan-001", 0),
            _event("line:suricata-high-severity-alert-001", 2),
        ],
    )

    assert len(incidents) == 1
    assert incidents[0].score_breakdown["sequence_quality"] == 0
    assert not any("scan activity is followed" in item for item in incidents[0].score_rationale)


def test_unrelated_cross_source_link_does_not_increase_incident_score() -> None:
    incidents = _correlate(
        [_finding("zeek-conn-port-scan-001", "high", 0)],
        [_event("line:zeek-conn-port-scan-001", 0)],
        cross_source_links=[
            CrossSourceLink(
                id="case-link:unrelated",
                link_type="flow_match",
                source_event_id="event:unrelated-source",
                target_event_id="event:unrelated-target",
                source_raw_line_id="line:unrelated-source",
                target_raw_line_id="line:unrelated-target",
                source_label="eve.json",
                target_label="conn.log",
                source_event_type="suricata_flow",
                target_event_type="zeek_conn",
                summary="Unrelated flow match.",
            )
        ],
    )

    assert len(incidents) == 1
    assert incidents[0].score_breakdown["cross_source_corroboration"] == 0
    assert not any("Cross-source corroboration" in item for item in incidents[0].score_rationale)


def test_far_apart_findings_get_no_time_window_or_ordered_sequence_score() -> None:
    incidents = _correlate(
        [
            _finding("suricata-dns-burst-001", "medium", 0),
            _finding("suricata-c2-category-001", "high", 120),
        ],
        [
            _event("line:suricata-dns-burst-001", 0),
            _event("line:suricata-c2-category-001", 120),
        ],
    )

    assert len(incidents) == 2
    assert all(
        incident.score_breakdown["time_window_proximity"] == 0 for incident in incidents
    )
    assert all(incident.score_breakdown["sequence_quality"] == 0 for incident in incidents)


def test_transitive_entity_bridge_does_not_merge_unrelated_endpoints() -> None:
    incidents = _correlate(
        [
            _finding("bridge-a", "medium", 0),
            _finding("bridge-b", "medium", 1),
            _finding("bridge-c", "medium", 2),
        ],
        [
            _event("line:bridge-a", 0, source_ip=None, username="alice"),
            _event("line:bridge-b", 1, source_ip="10.20.0.25", username="alice"),
            _event("line:bridge-c", 2, source_ip="10.20.0.25", username=None),
        ],
    )

    assert len(incidents) == 2
    assert all(len(incident.finding_ids) < 3 for incident in incidents)
    assert sorted(len(incident.finding_ids) for incident in incidents) == [1, 2]


def test_pattern_matching_survives_rule_id_renames() -> None:
    renamed_rules = [
        rule.model_copy(
            update={
                "id": {
                    "ssh-bruteforce-001": "renamed-auth-pressure",
                    "ssh-success-after-failures-001": "renamed-auth-success",
                }.get(rule.id, rule.id)
            }
        )
        for rule in RULES
    ]
    incidents = correlate_incidents(
        [
            _finding("renamed-auth-pressure", "high", 0),
            _finding("renamed-auth-success", "critical", 2),
        ],
        [
            _event("line:renamed-auth-pressure", 0),
            _event("line:renamed-auth-success", 2),
        ],
        rules=renamed_rules,
        patterns=PATTERNS,
    )

    assert len(incidents) == 1
    assert incidents[0].title == "Possible SSH credential compromise"
    assert incidents[0].score_breakdown["sequence_quality"] == 15
    assert any("ssh-failures-to-success" in item for item in incidents[0].score_rationale)


def test_reverse_stage_order_gets_no_pattern_score() -> None:
    incidents = _correlate(
        [
            _finding("ssh-success-after-failures-001", "critical", 0),
            _finding("ssh-bruteforce-001", "high", 2),
        ],
        [
            _event("line:ssh-success-after-failures-001", 0),
            _event("line:ssh-bruteforce-001", 2),
        ],
    )

    assert len(incidents) == 1
    assert incidents[0].score_breakdown["sequence_quality"] == 0
    assert not any("ssh-failures-to-success" in item for item in incidents[0].score_rationale)


def _finding(rule_id: str, severity: str, minute_offset: int) -> Finding:
    first_seen = BASE_TIME + timedelta(minutes=minute_offset)
    return Finding(
        id=f"finding:{rule_id}",
        rule_id=rule_id,
        title=rule_id,
        severity=severity,  # type: ignore[arg-type]
        confidence="high",
        summary=f"{rule_id} matched.",
        reason="test finding",
        mitre=MitreMapping(),
        first_seen=first_seen,
        last_seen=first_seen,
        event_count=1,
        evidence_line_ids=[f"line:{rule_id}"],
    )


def _event(
    raw_line_id: str,
    minute_offset: int,
    *,
    source_ip: str | None = "10.20.0.25",
    username: str | None = None,
    destination_ip: str | None = None,
) -> ParsedEvent:
    return ParsedEvent(
        id=f"event:{raw_line_id}",
        source_id="source:test",
        raw_line_id=raw_line_id,
        event_time=BASE_TIME + timedelta(minutes=minute_offset),
        event_type="test_event",
        source_ip=source_ip,
        username=username,
        message="test event",
        normalized_fields={"destination_ip": destination_ip} if destination_ip else {},
    )


def _correlate(
    findings: list[Finding],
    events: list[ParsedEvent],
    cross_source_links: list[CrossSourceLink] | None = None,
):
    return correlate_incidents(
        findings,
        events,
        cross_source_links=cross_source_links,
        rules=RULES,
        patterns=PATTERNS,
    )
