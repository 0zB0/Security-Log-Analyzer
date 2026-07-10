import json
from pathlib import Path

import pytest

from tracehawk_api.services.analysis import analyze_text


ROOT = Path(__file__).resolve().parents[3]
SCENARIOS_ROOT = ROOT / "packages/test-scenarios"
RULES_ROOT = ROOT / "packages/rules"


def _scenario_dirs() -> list[Path]:
    return sorted(path for path in SCENARIOS_ROOT.iterdir() if path.is_dir())


@pytest.mark.parametrize("scenario_dir", _scenario_dirs(), ids=lambda path: path.name)
def test_detection_scenario_contract(scenario_dir: Path) -> None:
    input_path = _scenario_input(scenario_dir)
    expected = json.loads((scenario_dir / "expected.json").read_text())

    result = analyze_text(
        text=input_path.read_text(),
        filename=input_path.name,
        rules_root=RULES_ROOT,
    )

    assert result.parser == expected["parser"]
    assert result.raw_line_count == expected["raw_line_count"]
    assert result.parsed_event_count == expected["parsed_event_count"]
    assert result.finding_count == expected["finding_count"]
    assert result.incident_count == expected["incident_count"]

    assert [finding.rule_id for finding in result.findings] == expected["expected_findings"]
    assert sorted({
        technique
        for finding in result.findings
        if (technique := finding.mitre.technique_id)
    }) == sorted(expected["expected_mitre"])
    assert sorted(line.line_number for line in result.evidence) == sorted(
        expected["expected_evidence_lines"]
    )

    if result.findings:
        assert result.evidence, "Findings must always carry line-level evidence."
    for finding in result.findings:
        assert finding.evidence_line_ids, f"{finding.rule_id} has no evidence lines."


def _scenario_input(scenario_dir: Path) -> Path:
    matches = sorted(
        path
        for path in scenario_dir.iterdir()
        if path.name.startswith("input.") and path.suffix in {".csv", ".log", ".txt", ".jsonl"}
    )
    assert len(matches) == 1, f"{scenario_dir} must have exactly one input file."
    return matches[0]
