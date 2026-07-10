from pathlib import Path

from fastapi.testclient import TestClient

from tracehawk_api.main import app
from tracehawk_api.services.detection import run_detection
from tracehawk_api.services.ingest import build_raw_lines
from tracehawk_api.services.rules import load_rules
from tracehawk_api.services.web_access_parser import WebAccessParser


ROOT = Path(__file__).resolve().parents[3]


def test_web_access_parser_extracts_request_fields() -> None:
    parser = WebAccessParser()
    raw_lines = build_raw_lines(ROOT / "packages/sample-data/nginx/probing.log", "nginx-sample")

    events = [
        event
        for line in raw_lines
        if (event := parser.parse_line(line.id, line.source_id, line.raw_text)) is not None
    ]

    assert len(events) == 4
    assert all(event.event_type == "http_request" for event in events)
    assert events[0].source_ip == "185.34.22.10"
    assert events[0].normalized_fields["http_method"] == "GET"
    assert events[0].normalized_fields["url_path"] == "/.env"
    assert events[0].normalized_fields["status_code"] == 404
    assert events[0].normalized_fields["user_agent"] == "curl/8.1"


def test_web_sensitive_file_rule_matches_nginx_probing() -> None:
    parser = WebAccessParser()
    raw_lines = build_raw_lines(ROOT / "packages/sample-data/nginx/probing.log", "nginx-sample")
    events = [
        event
        for line in raw_lines
        if (event := parser.parse_line(line.id, line.source_id, line.raw_text)) is not None
    ]
    rules = load_rules(ROOT / "packages/rules/web")

    findings = run_detection(rules, events)
    finding_by_rule = {finding.rule_id: finding for finding in findings}

    assert set(finding_by_rule) == {
        "web-path-traversal-001",
        "web-sensitive-file-access-001",
    }
    finding = finding_by_rule["web-sensitive-file-access-001"]
    assert finding.rule_id == "web-sensitive-file-access-001"
    assert finding.severity == "high"
    assert finding.event_count == 4
    assert finding.mitre.technique_id == "T1083"
    assert finding.evidence_line_ids == [
        "nginx-sample:line:1",
        "nginx-sample:line:2",
        "nginx-sample:line:3",
        "nginx-sample:line:4",
    ]
    assert finding_by_rule["web-path-traversal-001"].evidence_line_ids == ["nginx-sample:line:4"]


def test_web_reconnaissance_rules_match_scanner_activity() -> None:
    parser = WebAccessParser()
    raw_lines = build_raw_lines(ROOT / "packages/sample-data/nginx/reconnaissance.log", "recon-sample")
    events = [
        event
        for line in raw_lines
        if (event := parser.parse_line(line.id, line.source_id, line.raw_text)) is not None
    ]
    rules = load_rules(ROOT / "packages/rules/web")

    findings = run_detection(rules, events)
    finding_by_rule = {finding.rule_id: finding for finding in findings}

    assert set(finding_by_rule) == {
        "web-404-burst-001",
        "web-admin-login-probing-001",
        "web-path-traversal-001",
        "web-scanner-user-agent-001",
        "web-sensitive-file-access-001",
        "web-sql-injection-probing-001",
    }
    assert finding_by_rule["web-404-burst-001"].event_count == 6
    assert finding_by_rule["web-admin-login-probing-001"].event_count == 4
    assert finding_by_rule["web-path-traversal-001"].evidence_line_ids == ["recon-sample:line:6"]
    assert finding_by_rule["web-scanner-user-agent-001"].event_count == 7
    assert finding_by_rule["web-sql-injection-probing-001"].evidence_line_ids == [
        "recon-sample:line:7"
    ]
    assert finding_by_rule["web-sensitive-file-access-001"].evidence_line_ids == [
        "recon-sample:line:5"
    ]


def test_analyze_upload_supports_nginx_probing_log() -> None:
    client = TestClient(app)
    sample = ROOT / "packages/sample-data/nginx/probing.log"

    with sample.open("rb") as file:
        response = client.post(
            "/api/analyze/upload",
            files={"file": ("probing.log", file, "text/plain")},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["parser"] == "web_access"
    assert body["raw_line_count"] == 4
    assert body["parsed_event_count"] == 4
    assert body["finding_count"] == 2
    assert body["incident_count"] == 1
    assert {finding["rule_id"] for finding in body["findings"]} == {
        "web-path-traversal-001",
        "web-sensitive-file-access-001",
    }
    assert body["incidents"][0]["title"] == "Web probing against sensitive files"
    assert body["incidents"][0]["entities"] == ["ip:185.34.22.10"]
    assert len(body["evidence"]) == 4
