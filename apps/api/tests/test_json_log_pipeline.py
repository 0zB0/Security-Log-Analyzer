from pathlib import Path

from fastapi.testclient import TestClient

from tracehawk_api.main import app
from tracehawk_api.services.detection import run_detection
from tracehawk_api.services.ingest import build_raw_lines
from tracehawk_api.services.json_log_parser import JsonLogParser
from tracehawk_api.services.rules import load_rules


ROOT = Path(__file__).resolve().parents[3]


def test_json_log_parser_extracts_common_security_fields() -> None:
    parser = JsonLogParser()
    raw_lines = build_raw_lines(
        ROOT / "packages/sample-data/json/security-events.jsonl",
        "json-sample",
    )

    events = [
        event
        for line in raw_lines
        if (event := parser.parse_line(line.id, line.source_id, line.raw_text)) is not None
    ]

    assert len(events) == 6
    assert events[0].event_type == "authentication_failure"
    assert events[0].source_ip == "198.51.100.44"
    assert events[0].username == "admin"
    assert events[0].host == "api01"
    assert events[0].service == "vpn"
    assert events[-1].normalized_fields["process.command_line"].startswith("bash -c")


def test_json_rules_detect_auth_burst_and_encoded_command() -> None:
    parser = JsonLogParser()
    raw_lines = build_raw_lines(
        ROOT / "packages/sample-data/json/security-events.jsonl",
        "json-sample",
    )
    events = [
        event
        for line in raw_lines
        if (event := parser.parse_line(line.id, line.source_id, line.raw_text)) is not None
    ]
    rules = load_rules(ROOT / "packages/rules/json")

    findings = run_detection(rules, events)
    finding_by_rule = {finding.rule_id: finding for finding in findings}

    assert set(finding_by_rule) == {
        "json-auth-failure-burst-001",
        "json-encoded-command-001",
    }
    assert finding_by_rule["json-auth-failure-burst-001"].event_count == 5
    assert finding_by_rule["json-auth-failure-burst-001"].mitre.technique_id == "T1110"
    assert finding_by_rule["json-encoded-command-001"].evidence_line_ids == [
        "json-sample:line:6"
    ]


def test_analyze_upload_supports_json_lines_log() -> None:
    client = TestClient(app)
    sample = ROOT / "packages/sample-data/json/security-events.jsonl"

    with sample.open("rb") as file:
        response = client.post(
            "/api/analyze/upload",
            files={"file": ("security-events.jsonl", file, "application/jsonl")},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["parser"] == "json_log"
    assert body["raw_line_count"] == 6
    assert body["parsed_event_count"] == 6
    assert body["finding_count"] == 2
    assert {finding["rule_id"] for finding in body["findings"]} == {
        "json-auth-failure-burst-001",
        "json-encoded-command-001",
    }

