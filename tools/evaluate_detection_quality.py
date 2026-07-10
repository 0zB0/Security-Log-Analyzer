#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
API_ROOT = ROOT / "apps/api"
SCENARIOS_ROOT = ROOT / "packages/test-scenarios"
RULES_ROOT = ROOT / "packages/rules"
NETWORK_CONTRACT = ROOT / "packages/quality-scenarios/network-wireguard-risk.json"
ZEEK_BURST_CONTRACT = ROOT / "packages/quality-scenarios/zeek-connection-attempt-burst.json"
DEFAULT_JSON = ROOT / "docs/proof-pack/current-detection-quality.json"
DEFAULT_MARKDOWN = ROOT / "docs/proof-pack/current-detection-quality.md"

sys.path.insert(0, str(API_ROOT))

from tracehawk_api.services.analysis import analyze_text  # noqa: E402
from tracehawk_api.services.detection import run_detection  # noqa: E402
from tracehawk_api.services.live import parse_tshark_fields_line  # noqa: E402
from tracehawk_api.services.rules import load_rules  # noqa: E402


@dataclass(frozen=True)
class ScenarioQuality:
    scenario: str
    benign: bool
    expected: list[str]
    observed: list[str]
    true_positives: list[str]
    false_positives: list[str]
    false_negatives: list[str]


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate deterministic detection contracts.")
    parser.add_argument("--check", action="store_true", help="Validate without writing artifacts.")
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--markdown-output", type=Path, default=DEFAULT_MARKDOWN)
    args = parser.parse_args()

    report = evaluate_quality()
    assert_quality_gate(report)
    if not args.check:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        args.markdown_output.write_text(render_markdown(report))
    print(
        "detection_quality=ok "
        f"rules={report['summary']['rule_count']} "
        f"positive_coverage={report['summary']['positive_rule_coverage']} "
        f"false_positives={report['summary']['false_positive_count']}"
    )
    return 0


def evaluate_quality() -> dict[str, Any]:
    rules = load_rules(RULES_ROOT)
    rule_ids = {rule.id for rule in rules}
    scenarios = [_evaluate_standard_scenario(path) for path in _scenario_dirs()]
    scenarios.append(_evaluate_network_contract())
    scenarios.append(_evaluate_zeek_burst_contract())

    expected_rule_ids = {
        rule_id for scenario in scenarios for rule_id in scenario.expected
    }
    true_positive_count = sum(len(scenario.true_positives) for scenario in scenarios)
    false_positive_count = sum(len(scenario.false_positives) for scenario in scenarios)
    false_negative_count = sum(len(scenario.false_negatives) for scenario in scenarios)
    precision_denominator = true_positive_count + false_positive_count
    recall_denominator = true_positive_count + false_negative_count
    benign_scenarios = [scenario for scenario in scenarios if scenario.benign]

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "methodology": {
            "unit": "expected rule match per labeled scenario",
            "precision_note": "Precision is TP / (TP + unexpected rule matches).",
            "recall_note": "Recall is TP / (TP + missing expected rule matches).",
            "scope_note": (
                "Contract metrics prove committed labeled scenarios, not population-level "
                "production accuracy. External IoT-23 results are reported separately."
            ),
        },
        "summary": {
            "rule_count": len(rule_ids),
            "rules_with_false_positive_notes": sum(bool(rule.false_positives) for rule in rules),
            "rules_with_recommendations": sum(bool(rule.recommendations) for rule in rules),
            "rules_with_mitre_technique": sum(bool(rule.mitre.technique_id) for rule in rules),
            "positive_rule_coverage": len(rule_ids & expected_rule_ids),
            "missing_positive_rule_ids": sorted(rule_ids - expected_rule_ids),
            "scenario_count": len(scenarios),
            "benign_scenario_count": len(benign_scenarios),
            "benign_scenarios_with_findings": sum(
                bool(scenario.observed) for scenario in benign_scenarios
            ),
            "true_positive_count": true_positive_count,
            "false_positive_count": false_positive_count,
            "false_negative_count": false_negative_count,
            "precision": round(
                true_positive_count / precision_denominator if precision_denominator else 1.0,
                4,
            ),
            "recall": round(
                true_positive_count / recall_denominator if recall_denominator else 1.0,
                4,
            ),
        },
        "scenarios": [asdict(scenario) for scenario in scenarios],
    }


def assert_quality_gate(report: dict[str, Any]) -> None:
    summary = report["summary"]
    assert summary["positive_rule_coverage"] == summary["rule_count"], (
        "Rules missing positive contracts: "
        f"{', '.join(summary['missing_positive_rule_ids'])}"
    )
    assert summary["false_positive_count"] == 0, "Unexpected rule matches were observed."
    assert summary["false_negative_count"] == 0, "Expected rule matches were missing."
    assert summary["benign_scenarios_with_findings"] == 0, (
        "A committed benign scenario produced a finding."
    )
    assert summary["rules_with_false_positive_notes"] == summary["rule_count"]
    assert summary["rules_with_recommendations"] == summary["rule_count"]
    assert summary["rules_with_mitre_technique"] == summary["rule_count"]


def _evaluate_standard_scenario(path: Path) -> ScenarioQuality:
    expected_data = json.loads((path / "expected.json").read_text())
    input_path = _scenario_input(path)
    result = analyze_text(
        text=input_path.read_text(),
        filename=input_path.name,
        rules_root=RULES_ROOT,
    )
    expected = list(expected_data["expected_findings"])
    observed = [finding.rule_id for finding in result.findings]
    return _quality_result(path.name, expected, observed)


def _evaluate_network_contract() -> ScenarioQuality:
    contract = json.loads(NETWORK_CONTRACT.read_text())
    events = _network_contract_events()
    findings = run_detection(load_rules(RULES_ROOT / "network"), events)
    return _quality_result(
        contract["scenario"],
        list(contract["expected_findings"]),
        [finding.rule_id for finding in findings],
    )


def _evaluate_zeek_burst_contract() -> ScenarioQuality:
    contract = json.loads(ZEEK_BURST_CONTRACT.read_text())
    base_timestamp = datetime(2026, 7, 9, 12, 0, tzinfo=UTC).timestamp()
    lines = [
        json.dumps(
            {
                "_path": "conn",
                "ts": base_timestamp + index * 0.2,
                "id.orig_h": "10.8.0.20",
                "id.orig_p": 50000 + index,
                "id.resp_h": "10.0.0.20",
                "id.resp_p": 63798,
                "proto": "tcp",
                "conn_state": "S0",
            }
        )
        for index in range(100)
    ]
    result = analyze_text(
        text="\n".join(lines),
        filename="zeek-connection-attempt-burst.jsonl",
        rules_root=RULES_ROOT,
    )
    expected = list(contract["expected_findings"])
    observed = [finding.rule_id for finding in result.findings]
    return _quality_result(contract["scenario"], expected, observed)


def _quality_result(
    scenario: str,
    expected: list[str],
    observed: list[str],
) -> ScenarioQuality:
    expected_set = set(expected)
    observed_set = set(observed)
    return ScenarioQuality(
        scenario=scenario,
        benign=not expected,
        expected=expected,
        observed=observed,
        true_positives=sorted(expected_set & observed_set),
        false_positives=sorted(observed_set - expected_set),
        false_negatives=sorted(expected_set - observed_set),
    )


def _network_contract_events() -> list:
    base = datetime(2026, 7, 9, 12, 0, tzinfo=UTC)
    specs: list[tuple[datetime, str, str, int, int]] = []
    specs.append((base, "10.8.0.2", "10.0.0.5", 51000, 22))
    specs.append((base, "10.8.0.3", "10.0.0.6", 51001, 3389))
    specs.extend(
        (base + timedelta(milliseconds=index * 100), "10.8.0.4", "10.0.0.53", 52000 + index, 53)
        for index in range(20)
    )
    specs.extend(
        (base + timedelta(seconds=index), "10.8.0.5", "10.0.0.7", 53000 + index, 30000 + index)
        for index in range(10)
    )
    specs.extend(
        (base + timedelta(seconds=index), "10.8.0.6", f"10.0.1.{index + 1}", 54000 + index, 8443)
        for index in range(10)
    )
    specs.extend(
        (base + timedelta(seconds=index * 30), "10.8.0.7", "198.51.100.10", 55000 + index, 443)
        for index in range(6)
    )
    specs.extend(
        (base + timedelta(milliseconds=index * 400), "10.8.0.8", "10.0.0.8", 56000 + index, 443)
        for index in range(100)
    )

    events = []
    for index, (event_time, source, destination, source_port, destination_port) in enumerate(
        specs,
        start=1,
    ):
        line = (
            f"{event_time.timestamp()}\t{source}\t\t{destination}\t\t{source_port}\t\t"
            f"{destination_port}\t\teth:ip:tcp\t74\tTCP\tcontract packet"
        )
        event = parse_tshark_fields_line(
            f"quality:network:line:{index}",
            "quality:network",
            line,
            "wg0",
        )
        assert event is not None
        events.append(event)
    return events


def _scenario_dirs() -> list[Path]:
    return sorted(path for path in SCENARIOS_ROOT.iterdir() if path.is_dir())


def _scenario_input(path: Path) -> Path:
    matches = sorted(
        item
        for item in path.iterdir()
        if item.name.startswith("input.")
        and item.suffix in {".csv", ".log", ".txt", ".jsonl"}
    )
    if len(matches) != 1:
        raise ValueError(f"{path} must have exactly one supported input file.")
    return matches[0]


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    rows = [
        "# Current Detection Quality",
        "",
        f"Generated: `{report['generated_at']}`",
        "",
        "## Contract Summary",
        "",
        "| Measure | Result |",
        "| --- | ---: |",
        f"| Detection rules | {summary['rule_count']} |",
        f"| Rules with a positive contract | {summary['positive_rule_coverage']} |",
        f"| Labeled scenarios | {summary['scenario_count']} |",
        f"| Benign negative-control scenarios | {summary['benign_scenario_count']} |",
        f"| True-positive rule matches | {summary['true_positive_count']} |",
        f"| Unexpected rule matches | {summary['false_positive_count']} |",
        f"| Missing expected matches | {summary['false_negative_count']} |",
        f"| Contract precision | {summary['precision']:.4f} |",
        f"| Contract recall | {summary['recall']:.4f} |",
        "",
        "## Interpretation",
        "",
        report["methodology"]["scope_note"],
        "The external IoT-23 evaluation is maintained as a separate proof because a committed",
        "contract suite cannot establish real-world prevalence or population-level false-positive rates.",
        "",
        "## Negative Controls",
        "",
    ]
    benign_names = [
        scenario["scenario"] for scenario in report["scenarios"] if scenario["benign"]
    ]
    rows.extend(f"- `{name}`" for name in benign_names)
    rows.extend(
        [
            "",
            "All committed negative controls produced zero findings. Exact-port controls include",
            "Zeek destination port `33022`, which must not match SSH port `22`.",
            "",
        ]
    )
    return "\n".join(rows)


if __name__ == "__main__":
    raise SystemExit(main())
