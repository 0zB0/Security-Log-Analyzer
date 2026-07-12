from pathlib import Path
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from tracehawk_api.main import app
from tracehawk_api.services.detection import run_detection
from tracehawk_api.services.live import LiveInterfacePacketStreamer, parse_tshark_fields_line
from tracehawk_api.services.rules import load_rules


ROOT = Path(__file__).resolve().parents[3]


def test_tshark_fields_parser_normalizes_wireguard_packet_metadata() -> None:
    line = (
        "1783539718.123456\t10.8.0.2\t\t10.0.0.5\t\t52144\t\t22\t\t"
        "eth:ip:tcp\t74\tTCP\t52144 > 22 [SYN] Seq=0 Len=0"
    )

    event = parse_tshark_fields_line("packet:1", "interface:wg0", line, "wg0")

    assert event is not None
    assert event.event_type == "network_packet"
    assert event.source_ip == "10.8.0.2"
    assert event.service == "interface:wg0"
    assert event.normalized_fields["destination_ip"] == "10.0.0.5"
    assert event.normalized_fields["source_port"] == 52144
    assert event.normalized_fields["destination_port"] == 22
    assert event.normalized_fields["transport_protocol"] == "tcp"
    assert event.normalized_fields["packet_length"] == 74


def test_interface_snapshot_hashes_the_exact_displayed_evidence() -> None:
    line = (
        "1783539718.123456\t10.8.0.2\t\t10.0.0.5\t\t52144\t\t22\t\t"
        "eth:ip:tcp\t74\tTCP\t52144 > 22 [SYN] Seq=0 Len=0"
    )
    streamer = LiveInterfacePacketStreamer("wg0", ROOT / "packages/rules")

    snapshot = streamer._process_tshark_line(1, line)

    assert snapshot is not None
    evidence = snapshot.evidence[0]
    assert evidence.raw_text.startswith("interface=wg0 proto=tcp")
    assert evidence.content_hash == sha256(evidence.raw_text.encode("utf-8")).hexdigest()


def test_wireguard_network_rules_match_admin_service_access() -> None:
    lines = [
        (
            f"1783539718.{index:06d}\t10.8.0.2\t\t10.0.0.5\t\t{52144 + index}\t\t22\t\t"
            "eth:ip:tcp\t74\tTCP\tclient > ssh"
        )
        for index in range(3)
    ]
    events = [
        event
        for index, line in enumerate(lines, start=1)
        if (
            event := parse_tshark_fields_line(
                f"interface:wg0:packet:{index}",
                "interface:wg0",
                line,
                "wg0",
            )
        )
        is not None
    ]

    findings = run_detection(load_rules(ROOT / "packages/rules/network"), events)
    finding_by_rule = {finding.rule_id: finding for finding in findings}

    assert "network-wireguard-admin-service-access-001" in finding_by_rule
    finding = finding_by_rule["network-wireguard-admin-service-access-001"]
    assert finding.event_count == 3
    assert finding.mitre.technique_id == "T1021"
    assert finding.evidence_line_ids == [
        "interface:wg0:packet:1",
        "interface:wg0:packet:2",
        "interface:wg0:packet:3",
    ]


def test_wireguard_admin_service_access_requires_exact_port_match() -> None:
    line = (
        "1783539718.123456\t10.8.0.2\t\t10.0.0.5\t\t52144\t\t33022\t\t"
        "eth:ip:tcp\t74\tTCP\tclient > 33022"
    )
    event = parse_tshark_fields_line("interface:wg0:packet:1", "interface:wg0", line, "wg0")
    assert event is not None

    findings = run_detection(load_rules(ROOT / "packages/rules/network"), [event])

    assert "network-wireguard-admin-service-access-001" not in {
        finding.rule_id for finding in findings
    }


def test_wireguard_network_rules_detect_distinct_port_scan() -> None:
    base_time = datetime(2026, 7, 8, 12, 0, tzinfo=UTC)
    events = []
    for index, destination_port in enumerate(range(30000, 30010), start=1):
        event_time = base_time + timedelta(seconds=index)
        line = (
            f"{event_time.timestamp()}\t10.8.0.2\t\t10.0.0.5\t\t52144\t\t"
            f"{destination_port}\t\teth:ip:tcp\t74\tTCP\tclient > {destination_port}"
        )
        event = parse_tshark_fields_line(
            f"interface:wg0:packet:{index}",
            "interface:wg0",
            line,
            "wg0",
        )
        assert event is not None
        events.append(event)

    findings = run_detection(load_rules(ROOT / "packages/rules/network"), events)
    finding_by_rule = {finding.rule_id: finding for finding in findings}

    assert "network-wireguard-port-scan-001" in finding_by_rule
    finding = finding_by_rule["network-wireguard-port-scan-001"]
    assert finding.event_count == 10
    assert finding.mitre.technique_id == "T1046"
    assert finding.evidence_line_ids[0] == "interface:wg0:packet:1"


def test_wireguard_network_rules_detect_host_sweep() -> None:
    base_time = datetime(2026, 7, 8, 12, 10, tzinfo=UTC)
    events = []
    for index in range(1, 11):
        event_time = base_time + timedelta(seconds=index)
        line = (
            f"{event_time.timestamp()}\t10.8.0.2\t\t10.0.0.{index}\t\t52144\t\t"
            "8443\t\teth:ip:tcp\t74\tTCP\tclient > 8443"
        )
        event = parse_tshark_fields_line(
            f"interface:wg0:packet:{index}",
            "interface:wg0",
            line,
            "wg0",
        )
        assert event is not None
        events.append(event)

    findings = run_detection(load_rules(ROOT / "packages/rules/network"), events)
    finding_by_rule = {finding.rule_id: finding for finding in findings}

    assert "network-wireguard-host-sweep-001" in finding_by_rule
    finding = finding_by_rule["network-wireguard-host-sweep-001"]
    assert finding.event_count == 10
    assert finding.mitre.technique_id == "T1046"


def test_wireguard_network_rules_detect_periodic_beacon() -> None:
    base_time = datetime(2026, 7, 8, 12, 20, tzinfo=UTC)
    events = []
    for index in range(6):
        event_time = base_time + timedelta(seconds=index * 30)
        line = (
            f"{event_time.timestamp()}\t10.8.0.9\t\t198.51.100.10\t\t52144\t\t"
            "443\t\teth:ip:tcp\t90\tTCP\tclient > https"
        )
        event = parse_tshark_fields_line(
            f"interface:wg0:packet:{index + 1}",
            "interface:wg0",
            line,
            "wg0",
        )
        assert event is not None
        events.append(event)

    findings = run_detection(load_rules(ROOT / "packages/rules/network"), events)
    finding_by_rule = {finding.rule_id: finding for finding in findings}

    assert "network-wireguard-periodic-beacon-001" in finding_by_rule
    finding = finding_by_rule["network-wireguard-periodic-beacon-001"]
    assert finding.event_count == 6
    assert finding.mitre.technique_id == "T1071"


def test_live_interface_endpoint_rejects_invalid_interface_name() -> None:
    client = TestClient(app)

    with pytest.raises(WebSocketDisconnect) as caught:
        with client.websocket_connect("/api/live/interface?interface=wg0;cat"):
            pass

    assert caught.value.code == 1008
