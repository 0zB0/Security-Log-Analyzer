from pathlib import Path

import pytest

from tracehawk_api.services.analysis import analyze_text
from tracehawk_api.services.parser_registry import default_parsers


ROOT = Path(__file__).resolve().parents[3]
RULES = ROOT / "packages/rules"


def test_parser_selection_samples_beyond_first_twenty_lines() -> None:
    auth = (ROOT / "packages/sample-data/auth/ssh-bruteforce.log").read_text()
    text = "\n".join([f"unstructured preamble {index}" for index in range(40)]) + "\n" + auth

    result = analyze_text(text=text, filename="delayed-auth.log", rules_root=RULES)

    assert result.parser == "linux_auth"
    assert result.parsed_event_count == 12
    assert result.finding_count == 4


def test_mixed_auth_and_web_log_uses_parser_scoped_detection() -> None:
    auth = (ROOT / "packages/sample-data/auth/ssh-bruteforce.log").read_text()
    web = (ROOT / "packages/sample-data/nginx/probing.log").read_text()

    result = analyze_text(
        text=f"{auth.rstrip()}\n{web}",
        filename="mixed-auth-web.log",
        rules_root=RULES,
    )

    assert result.parser == "mixed"
    assert result.parsed_event_count == 16
    assert {event.normalized_fields["_tracehawk_parser"] for event in result.events} == {
        "linux_auth",
        "web_access",
    }
    assert {finding.rule_id for finding in result.findings} == {
        "ssh-bruteforce-001",
        "ssh-compromise-sequence-001",
        "ssh-success-after-failures-001",
        "sudo-user-management-001",
        "web-path-traversal-001",
        "web-sensitive-file-access-001",
    }


def test_specific_json_parser_wins_over_generic_json_parser() -> None:
    text = (ROOT / "packages/sample-data/suricata/eve-alerts.jsonl").read_text()

    result = analyze_text(text=text, filename="eve.jsonl", rules_root=RULES)

    assert result.parser == "suricata_eve"
    assert {event.normalized_fields["_tracehawk_parser"] for event in result.events} == {
        "suricata_eve"
    }


def test_mixed_stateful_zeek_section_and_auth_log_preserve_parser_context() -> None:
    zeek = (ROOT / "packages/sample-data/zeek/conn-port-scan.log").read_text()
    auth = (ROOT / "packages/sample-data/auth/ssh-bruteforce.log").read_text()

    result = analyze_text(
        text=f"{zeek.rstrip()}\n{auth}",
        filename="mixed-zeek-auth.log",
        rules_root=RULES,
    )

    assert result.parser == "mixed"
    assert result.parsed_event_count == 22
    assert {finding.rule_id for finding in result.findings} == {
        "zeek-conn-port-scan-001",
        "ssh-bruteforce-001",
        "ssh-compromise-sequence-001",
        "ssh-success-after-failures-001",
        "sudo-user-management-001",
    }


def test_parser_selection_is_independent_of_registry_order() -> None:
    text = (ROOT / "packages/sample-data/auth/ssh-bruteforce.log").read_text()

    normal = analyze_text(
        text=text,
        filename="auth.log",
        rules_root=RULES,
        parsers=default_parsers(),
    )
    reversed_result = analyze_text(
        text=text,
        filename="auth.log",
        rules_root=RULES,
        parsers=list(reversed(default_parsers())),
    )

    assert normal.parser == reversed_result.parser == "linux_auth"
    assert [finding.rule_id for finding in normal.findings] == [
        finding.rule_id for finding in reversed_result.findings
    ]


def test_unrecognized_content_fails_explicitly() -> None:
    with pytest.raises(ValueError, match="No supported parser"):
        analyze_text(
            text="opaque content without a supported log shape",
            filename="unknown.log",
            rules_root=RULES,
        )
