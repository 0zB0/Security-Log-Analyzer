import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/evaluate_detection_quality.py"


def test_detection_quality_contract_covers_every_rule_without_unexpected_matches() -> None:
    spec = importlib.util.spec_from_file_location("evaluate_detection_quality", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    report = module.evaluate_quality()
    module.assert_quality_gate(report)

    summary = report["summary"]
    assert summary["rule_count"] == 65
    assert summary["positive_rule_coverage"] == 65
    assert summary["false_positive_count"] == 0
    assert summary["false_negative_count"] == 0
    assert summary["benign_scenario_count"] >= 11
