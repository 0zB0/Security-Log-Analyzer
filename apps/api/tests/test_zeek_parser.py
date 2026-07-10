from pathlib import Path

from fastapi.testclient import TestClient

from tracehawk_api.main import app
from tracehawk_api.services.detection import run_detection
from tracehawk_api.services.ingest import build_raw_lines
from tracehawk_api.services.rules import load_rules
from tracehawk_api.services.zeek_json_parser import ZeekJsonParser
from tracehawk_api.services.zeek_tsv_parser import ZeekTsvParser


ROOT = Path(__file__).resolve().parents[3]


def test_zeek_tsv_parser_extracts_conn_fields() -> None:
    parser = ZeekTsvParser()
    raw_lines = build_raw_lines(
        ROOT / "packages/sample-data/zeek/conn-port-scan.log",
        "zeek-conn",
    )

    events = [
        event
        for line in raw_lines
        if (event := parser.parse_line(line.id, line.source_id, line.raw_text)) is not None
    ]

    assert len(events) == 10
    assert events[0].event_type == "zeek_conn"
    assert events[0].source_ip == "10.8.0.44"
    assert events[0].normalized_fields["destination_ip"] == "10.0.0.5"
    assert events[0].normalized_fields["source_port"] == 51001
    assert events[0].normalized_fields["destination_port"] == 30000
    assert events[0].normalized_fields["transport_protocol"] == "tcp"
    assert events[0].normalized_fields["conn_state"] == "S0"


def test_zeek_json_parser_extracts_mixed_log_fields() -> None:
    parser = ZeekJsonParser()
    raw_lines = build_raw_lines(
        ROOT / "packages/sample-data/zeek/zeek-mixed.jsonl",
        "zeek-json",
    )

    events = [
        event
        for line in raw_lines
        if (event := parser.parse_line(line.id, line.source_id, line.raw_text)) is not None
    ]

    assert len(events) == 8
    assert events[0].event_type == "zeek_dns"
    assert events[0].normalized_fields["dns_query"] == "a1.beacon-control.example"
    assert events[5].event_type == "zeek_http"
    assert events[5].normalized_fields["url_path"] == "/.env"
    assert events[6].event_type == "zeek_notice"
    assert events[6].normalized_fields["notice_note"] == "Scan::Port_Scan"
    assert events[7].event_type == "zeek_ssl"
    assert events[7].normalized_fields["tls_sni"] == "ops-tunnel.ngrok-free.app"


def test_zeek_rules_detect_tsv_port_scan() -> None:
    parser = ZeekTsvParser()
    raw_lines = build_raw_lines(
        ROOT / "packages/sample-data/zeek/conn-port-scan.log",
        "zeek-conn",
    )
    events = [
        event
        for line in raw_lines
        if (event := parser.parse_line(line.id, line.source_id, line.raw_text)) is not None
    ]

    findings = run_detection(load_rules(ROOT / "packages/rules/zeek"), events)

    assert [finding.rule_id for finding in findings] == ["zeek-conn-port-scan-001"]
    assert findings[0].event_count == 10
    assert findings[0].mitre.technique_id == "T1046"


def test_zeek_rules_detect_json_dns_http_notice_tls() -> None:
    parser = ZeekJsonParser()
    raw_lines = build_raw_lines(
        ROOT / "packages/sample-data/zeek/zeek-mixed.jsonl",
        "zeek-json",
    )
    events = [
        event
        for line in raw_lines
        if (event := parser.parse_line(line.id, line.source_id, line.raw_text)) is not None
    ]

    findings = run_detection(load_rules(ROOT / "packages/rules/zeek"), events)

    assert [finding.rule_id for finding in findings] == [
        "zeek-dns-burst-001",
        "zeek-http-sensitive-path-001",
        "zeek-notice-event-001",
        "zeek-tls-suspicious-name-001",
    ]
    assert findings[0].event_count == 5
    assert findings[-1].mitre.technique_id == "T1071.001"


def test_analyze_upload_supports_zeek_tsv_log() -> None:
    client = TestClient(app)
    sample = ROOT / "packages/sample-data/zeek/conn-port-scan.log"

    with sample.open("rb") as file:
        response = client.post(
            "/api/analyze/upload",
            files={"file": ("conn.log", file, "text/plain")},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["parser"] == "zeek_tsv"
    assert body["raw_line_count"] == 17
    assert body["parsed_event_count"] == 10
    assert body["finding_count"] == 1
    assert body["findings"][0]["rule_id"] == "zeek-conn-port-scan-001"


def test_analyze_upload_supports_zeek_json_log() -> None:
    client = TestClient(app)
    sample = ROOT / "packages/sample-data/zeek/zeek-mixed.jsonl"

    with sample.open("rb") as file:
        response = client.post(
            "/api/analyze/upload",
            files={"file": ("zeek.jsonl", file, "application/jsonl")},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["parser"] == "zeek_json"
    assert body["raw_line_count"] == 8
    assert body["parsed_event_count"] == 8
    assert body["finding_count"] == 4
    assert {finding["rule_id"] for finding in body["findings"]} == {
        "zeek-dns-burst-001",
        "zeek-http-sensitive-path-001",
        "zeek-notice-event-001",
        "zeek-tls-suspicious-name-001",
    }
