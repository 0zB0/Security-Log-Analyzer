from pathlib import Path

from fastapi.testclient import TestClient

from tracehawk_api.main import app
from tracehawk_api.services.detection import run_detection
from tracehawk_api.services.ingest import build_raw_lines
from tracehawk_api.services.rules import load_rules
from tracehawk_api.services.suricata_eve_parser import SuricataEveParser


ROOT = Path(__file__).resolve().parents[3]


def test_suricata_eve_parser_extracts_common_security_fields() -> None:
    parser = SuricataEveParser()
    raw_lines = build_raw_lines(
        ROOT / "packages/sample-data/suricata/eve-c2-dns.jsonl",
        "suricata-sample",
    )

    events = [
        event
        for line in raw_lines
        if (event := parser.parse_line(line.id, line.source_id, line.raw_text)) is not None
    ]

    assert len(events) == 7
    assert events[0].event_type == "suricata_alert"
    assert events[0].source_ip == "10.20.0.25"
    assert events[0].normalized_fields["destination_ip"] == "203.0.113.77"
    assert events[0].normalized_fields["destination_port"] == 443
    assert events[0].normalized_fields["transport_protocol"] == "tcp"
    assert events[0].normalized_fields["signature"] == "ET MALWARE C2 Beacon Observed"
    assert events[0].normalized_fields["category"] == "A Network Trojan was detected"
    assert events[1].event_type == "suricata_http"
    assert events[1].normalized_fields["url_path"] == "/wp-config.php"
    assert events[2].event_type == "suricata_dns"
    assert events[2].normalized_fields["dns_query"] == "a1.beacon-control.example"


def test_suricata_rules_detect_c2_dns_and_sensitive_http() -> None:
    parser = SuricataEveParser()
    raw_lines = build_raw_lines(
        ROOT / "packages/sample-data/suricata/eve-c2-dns.jsonl",
        "suricata-sample",
    )
    events = [
        event
        for line in raw_lines
        if (event := parser.parse_line(line.id, line.source_id, line.raw_text)) is not None
    ]

    findings = run_detection(load_rules(ROOT / "packages/rules/suricata"), events)
    finding_by_rule = {finding.rule_id: finding for finding in findings}

    assert set(finding_by_rule) == {
        "suricata-c2-category-001",
        "suricata-dns-burst-001",
        "suricata-high-severity-alert-001",
        "suricata-http-sensitive-path-001",
    }
    assert finding_by_rule["suricata-c2-category-001"].mitre.technique_id == "T1071"
    assert finding_by_rule["suricata-dns-burst-001"].event_count == 5
    assert finding_by_rule["suricata-http-sensitive-path-001"].evidence_line_ids == [
        "suricata-sample:line:2"
    ]


def test_analyze_upload_supports_suricata_eve_jsonl() -> None:
    client = TestClient(app)
    sample = ROOT / "packages/sample-data/suricata/eve-alerts.jsonl"

    with sample.open("rb") as file:
        response = client.post(
            "/api/analyze/upload",
            files={"file": ("eve.json", file, "application/json")},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["parser"] == "suricata_eve"
    assert body["raw_line_count"] == 5
    assert body["parsed_event_count"] == 5
    assert body["finding_count"] == 3
    assert {finding["rule_id"] for finding in body["findings"]} == {
        "suricata-alert-burst-001",
        "suricata-http-sensitive-path-001",
        "suricata-scan-signature-001",
    }
