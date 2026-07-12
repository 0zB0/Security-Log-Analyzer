from pathlib import Path

import pytest

from tracehawk_api.services.correlation_patterns import load_correlation_patterns
from tracehawk_api.services.rules import load_rules


ROOT = Path(__file__).resolve().parents[3]
RULES = load_rules(ROOT / "packages/rules")


def test_correlation_pattern_library_loads_declared_behaviors() -> None:
    patterns = load_correlation_patterns(
        ROOT / "packages/correlation/patterns.yml",
        RULES,
    )

    assert len(patterns) == 5
    assert {pattern.id for pattern in patterns} == {
        "alert-burst-to-high-severity",
        "dns-burst-to-c2-alert",
        "scan-to-sensitive-http",
        "ssh-failures-to-success",
        "ssh-success-to-privileged-action",
    }


def test_correlation_pattern_ids_must_be_unique(tmp_path: Path) -> None:
    path = tmp_path / "patterns.yml"
    path.write_text(
        _pattern_document("duplicate") + _pattern_item("duplicate", "ssh_success"),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="IDs must be unique"):
        load_correlation_patterns(path, RULES)


def test_correlation_patterns_reject_unknown_behaviors(tmp_path: Path) -> None:
    path = tmp_path / "patterns.yml"
    path.write_text(_pattern_document("unknown-behavior"), encoding="utf-8")

    with pytest.raises(ValueError, match="unknown behaviors: behavior_not_declared"):
        load_correlation_patterns(path, RULES)


def test_correlation_patterns_require_at_least_two_stages(tmp_path: Path) -> None:
    path = tmp_path / "patterns.yml"
    path.write_text(
        """schema_version: 1
patterns:
  - id: one-stage
    title: Invalid one-stage pattern
    stages:
      - any_behaviors: [ssh_failures]
    max_gap_minutes: 15
    score: 5
    rationale: Missing a follow-up stage.
    summary: Invalid pattern.
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="at least 2 items"):
        load_correlation_patterns(path, RULES)


def _pattern_document(pattern_id: str) -> str:
    return "schema_version: 1\npatterns:\n" + _pattern_item(
        pattern_id,
        "behavior_not_declared" if pattern_id == "unknown-behavior" else "ssh_failures",
    )


def _pattern_item(pattern_id: str, first_behavior: str) -> str:
    return f"""  - id: {pattern_id}
    title: Test pattern
    stages:
      - any_behaviors: [{first_behavior}]
      - any_behaviors: [ssh_success]
    max_gap_minutes: 15
    score: 5
    rationale: Test rationale.
    summary: Test summary.
"""
