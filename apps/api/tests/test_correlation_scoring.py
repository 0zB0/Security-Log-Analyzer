from datetime import UTC, datetime, timedelta

from tracehawk_api.models.domain import Finding, MitreMapping, ParsedEvent
from tracehawk_api.services.analysis import CrossSourceLink
from tracehawk_api.services.correlation import correlate_incidents


BASE_TIME = datetime(2026, 7, 9, 8, 0, tzinfo=UTC)


def test_dns_burst_without_alert_or_c2_gets_no_sequence_score() -> None:
    incidents = correlate_incidents(
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
    incidents = correlate_incidents(
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
    incidents = correlate_incidents(
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
    incidents = correlate_incidents(
        [
            _finding("suricata-dns-burst-001", "medium", 0),
            _finding("suricata-c2-category-001", "high", 120),
        ],
        [
            _event("line:suricata-dns-burst-001", 0),
            _event("line:suricata-c2-category-001", 120),
        ],
    )

    assert len(incidents) == 1
    assert incidents[0].score_breakdown["time_window_proximity"] == 0
    assert incidents[0].score_breakdown["sequence_quality"] == 0


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


def _event(raw_line_id: str, minute_offset: int) -> ParsedEvent:
    return ParsedEvent(
        id=f"event:{raw_line_id}",
        source_id="source:test",
        raw_line_id=raw_line_id,
        event_time=BASE_TIME + timedelta(minutes=minute_offset),
        event_type="test_event",
        source_ip="10.20.0.25",
        message="test event",
        normalized_fields={"destination_ip": "203.0.113.80"},
    )
