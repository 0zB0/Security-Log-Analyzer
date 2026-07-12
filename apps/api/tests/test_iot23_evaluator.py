import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/evaluate_iot23.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("evaluate_iot23_test_target", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_iot23_label_parser_supports_separate_and_combined_formats() -> None:
    module = _load_module()
    separate = ["value"] * 21 + ["Malicious", "PartOfAHorizontalPortScan"]
    combined = ["value"] * 20 + ["-   Malicious   C&C-Torii"]
    benign_combined = ["value"] * 20 + ["(empty)   Benign   -"]
    lowercase_benign = ["value"] * 20 + ["-   benign   -"]

    assert module._extract_detailed_label(separate) == (
        "PartOfAHorizontalPortScan",
        "separate_columns",
    )
    assert module._extract_detailed_label(combined) == (
        "C&C-Torii",
        "combined_column",
    )
    assert module._extract_detailed_label(benign_combined) == (
        "Benign",
        "combined_column",
    )
    assert module._extract_detailed_label(lowercase_benign) == (
        "Benign",
        "combined_column",
    )


def test_iot23_capture_catalog_does_not_confuse_44_with_benign_4() -> None:
    module = _load_module()

    final = module._capture_definition(
        Path("iot23-44-1-conn.log.labeled"), force_benign=False
    )
    benign = module._capture_definition(
        Path("iot23-benign-4-1-conn.log.labeled"), force_benign=True
    )

    assert final["capture_id"] == "44-1"
    assert final["role"] == "final_evaluation"
    assert final["objectives"] == ["command_and_control"]
    assert benign["capture_id"] == "4-1"
    assert benign["role"] == "negative_control"
    assert set(benign["objectives"]) == {"network_scan", "command_and_control"}


def test_final_metrics_exclude_development_and_validation_captures() -> None:
    module = _load_module()
    datasets = [
        _dataset("20-1", "development", _metrics(tp=50, fn=1)),
        _dataset("21-1", "validation", _metrics(tp=0, fn=5)),
        _dataset("42-1", "final_evaluation", _metrics(tp=2, fn=3)),
        _dataset("4-1", "negative_control", _metrics(tn=10)),
    ]

    report = module._objective_report("command_and_control", datasets)

    assert report["metrics_by_role"]["development"]["true_positive_windows"] == 50
    assert report["metrics_by_role"]["validation"]["false_negative_windows"] == 5
    assert report["final_metrics"]["true_positive_windows"] == 2
    assert report["final_metrics"]["false_negative_windows"] == 3
    assert report["final_metrics"]["true_negative_windows"] == 10
    assert report["final_capture_ids"] == ["42-1"]
    assert report["negative_control_capture_ids"] == ["4-1"]


def test_c2_label_family_is_narrow_and_explicit() -> None:
    module = _load_module()

    assert module._is_positive_label("command_and_control", "C&C")
    assert module._is_positive_label("command_and_control", "C&C-FileDownload")
    assert not module._is_positive_label("command_and_control", "FileDownload")
    assert not module._is_positive_label("command_and_control", "DDoS")


def test_committed_iot23_report_retains_holdout_roles_and_errors() -> None:
    report = json.loads(
        (ROOT / "docs/proof-pack/current-iot23-evaluation.json").read_text()
    )

    assert report["schema_version"] == 2
    assert report["methodology"]["rule_freeze_commit"] == (
        "df5811a6f98e48ea046247fcbb770fa9ecbd32ed"
    )
    roles = {dataset["capture_id"]: dataset["role"] for dataset in report["datasets"]}
    assert roles == {
        "34-1": "final_evaluation",
        "20-1": "development",
        "21-1": "validation",
        "8-1": "validation",
        "42-1": "final_evaluation",
        "44-1": "final_evaluation",
        "4-1": "negative_control",
    }
    scan = report["objectives"]["network_scan"]["final_metrics"]
    c2 = report["objectives"]["command_and_control"]["final_metrics"]
    assert _matrix(scan) == (1, 1, 1, 877)
    assert _matrix(c2) == (2, 21, 1, 246)
    assert c2["precision"] == 0.087
    assert c2["recall"] == 0.6667
    assert all(
        "Unknown" not in dataset["label_counts"] for dataset in report["datasets"]
    )


def _dataset(capture_id: str, role: str, metrics: dict) -> dict:
    return {
        "capture_id": capture_id,
        "role": role,
        "objective_metrics": {"command_and_control": metrics},
    }


def _metrics(*, tp: int = 0, fp: int = 0, fn: int = 0, tn: int = 0) -> dict:
    return {
        "window_count": tp + fp + fn + tn,
        "true_positive_windows": tp,
        "false_positive_windows": fp,
        "false_negative_windows": fn,
        "true_negative_windows": tn,
        "detected_rule_windows": {},
        "false_positive_examples": [],
        "false_negative_examples": [],
    }


def _matrix(metrics: dict) -> tuple[int, int, int, int]:
    return (
        metrics["true_positive_windows"],
        metrics["false_positive_windows"],
        metrics["false_negative_windows"],
        metrics["true_negative_windows"],
    )
