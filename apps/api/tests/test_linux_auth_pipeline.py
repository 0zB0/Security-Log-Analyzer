from pathlib import Path

from tracehawk_api.services.detection import run_detection
from tracehawk_api.services.correlation import correlate_incidents
from tracehawk_api.services.correlation_patterns import (
    default_correlation_pattern_path,
    load_correlation_patterns,
)
from tracehawk_api.services.ingest import build_raw_lines
from tracehawk_api.services.linux_auth_parser import LinuxAuthParser
from tracehawk_api.services.rules import load_rules


ROOT = Path(__file__).resolve().parents[3]
ALL_RULES = load_rules(ROOT / "packages/rules")
PATTERNS = load_correlation_patterns(
    default_correlation_pattern_path(ROOT / "packages/rules"), ALL_RULES
)


def test_linux_auth_parser_extracts_ssh_events() -> None:
    parser = LinuxAuthParser()
    raw_lines = build_raw_lines(ROOT / "packages/sample-data/auth/ssh-bruteforce.log", "auth-sample")

    events = [
        event
        for line in raw_lines
        if (event := parser.parse_line(line.id, line.source_id, line.raw_text)) is not None
    ]

    assert len(events) == 12
    assert [event.event_type for event in events].count("ssh_failed_login") == 10
    assert [event.event_type for event in events].count("ssh_successful_login") == 1
    assert [event.event_type for event in events].count("sudo_command") == 1
    assert events[0].source_ip == "198.51.100.10"
    assert events[0].username == "admin"
    assert events[-1].normalized_fields["command"] == "/usr/sbin/useradd backupadm"


def test_auth_rules_detect_bruteforce_and_success_after_failures() -> None:
    parser = LinuxAuthParser()
    raw_lines = build_raw_lines(ROOT / "packages/sample-data/auth/ssh-bruteforce.log", "auth-sample")
    events = [
        event
        for line in raw_lines
        if (event := parser.parse_line(line.id, line.source_id, line.raw_text)) is not None
    ]
    rules = load_rules(ROOT / "packages/rules/auth")

    findings = run_detection(rules, events)
    finding_by_rule = {finding.rule_id: finding for finding in findings}

    assert set(finding_by_rule) == {
        "ssh-bruteforce-001",
        "ssh-compromise-sequence-001",
        "ssh-success-after-failures-001",
        "sudo-user-management-001",
    }
    brute_force = finding_by_rule["ssh-bruteforce-001"]
    success_after_failures = finding_by_rule["ssh-success-after-failures-001"]
    compromise_sequence = finding_by_rule["ssh-compromise-sequence-001"]

    assert brute_force.severity == "high"
    assert brute_force.event_count == 10
    assert brute_force.mitre.technique_id == "T1110.001"
    assert len(brute_force.evidence_line_ids) == 10

    assert success_after_failures.severity == "critical"
    assert success_after_failures.event_count == 11
    assert success_after_failures.mitre.technique_id == "T1078"
    assert success_after_failures.evidence_line_ids[-1] == "auth-sample:line:11"
    assert compromise_sequence.event_count == 12
    assert "3 ordered sequence steps" in compromise_sequence.summary

    user_management = finding_by_rule["sudo-user-management-001"]
    assert user_management.severity == "high"
    assert user_management.event_count == 1
    assert user_management.mitre.technique_id == "T1136.001"
    assert user_management.evidence_line_ids == ["auth-sample:line:12"]


def test_sudo_rules_detect_privileged_activity() -> None:
    parser = LinuxAuthParser()
    raw_lines = build_raw_lines(ROOT / "packages/sample-data/auth/sudo-activity.log", "sudo-sample")
    events = [
        event
        for line in raw_lines
        if (event := parser.parse_line(line.id, line.source_id, line.raw_text)) is not None
    ]
    rules = load_rules(ROOT / "packages/rules/auth")

    findings = run_detection(rules, events)
    finding_by_rule = {finding.rule_id: finding for finding in findings}

    assert set(finding_by_rule) == {
        "sudo-burst-001",
        "sudo-sensitive-file-access-001",
        "sudo-user-management-001",
    }
    assert finding_by_rule["sudo-burst-001"].event_count == 3
    assert finding_by_rule["sudo-sensitive-file-access-001"].mitre.technique_id == "T1003.008"
    assert finding_by_rule["sudo-user-management-001"].mitre.technique_id == "T1136.001"


def test_auth_findings_correlate_into_compromise_incident() -> None:
    parser = LinuxAuthParser()
    raw_lines = build_raw_lines(ROOT / "packages/sample-data/auth/ssh-bruteforce.log", "auth-sample")
    events = [
        event
        for line in raw_lines
        if (event := parser.parse_line(line.id, line.source_id, line.raw_text)) is not None
    ]
    rules = load_rules(ROOT / "packages/rules/auth")
    findings = run_detection(rules, events)

    incidents = correlate_incidents(
        findings, events, rules=ALL_RULES, patterns=PATTERNS
    )

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.title == "Possible SSH credential compromise"
    assert incident.severity == "critical"
    assert incident.score == 100
    assert len(incident.finding_ids) == 4
    assert "ip:198.51.100.10" in incident.entities
    assert "user:admin" in incident.entities
    assert incident.mitre_techniques == ["T1078", "T1110.001", "T1136.001"]
    assert len(incident.timeline) == 12
    assert "SSH failures were followed by a successful login" in incident.summary
    assert "successful SSH login was followed by privileged activity" in incident.summary
    assert any("three-step SSH" in reason for reason in incident.score_rationale)


def test_sudo_findings_correlate_by_user() -> None:
    parser = LinuxAuthParser()
    raw_lines = build_raw_lines(ROOT / "packages/sample-data/auth/sudo-activity.log", "sudo-sample")
    events = [
        event
        for line in raw_lines
        if (event := parser.parse_line(line.id, line.source_id, line.raw_text)) is not None
    ]
    rules = load_rules(ROOT / "packages/rules/auth")
    findings = run_detection(rules, events)

    incidents = correlate_incidents(
        findings, events, rules=ALL_RULES, patterns=PATTERNS
    )

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.title == "Privileged sudo activity"
    assert incident.severity == "high"
    assert len(incident.finding_ids) == 3
    assert incident.entities == ["host:labhost", "user:admin"]
    assert incident.mitre_techniques == ["T1003.008", "T1059", "T1136.001"]
