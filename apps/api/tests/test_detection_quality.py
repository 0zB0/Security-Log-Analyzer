import importlib.util
import re
import sys
from pathlib import Path

from tracehawk_api.services.rules import load_rules


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
    assert summary["rule_count"] == 66
    assert summary["positive_rule_coverage"] == 66
    assert summary["false_positive_count"] == 0
    assert summary["false_negative_count"] == 0
    assert summary["benign_scenario_count"] >= 11


def test_current_rule_documentation_lists_the_complete_library() -> None:
    rule_ids = {rule.id for rule in load_rules(ROOT / "packages" / "rules")}
    documented_pattern = re.compile(r"^- `([a-z0-9-]+)`$", re.MULTILINE)

    for relative_path in ("docs/rules.md", "docs/rule-authoring.md"):
        documented_ids = set(
            documented_pattern.findall((ROOT / relative_path).read_text(encoding="utf-8"))
        )
        assert documented_ids == rule_ids
