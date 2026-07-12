import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "tools/evaluation_metrics.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("evaluation_metrics_test_target", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_confusion_metrics_retain_counts_and_expose_small_sample_uncertainty() -> None:
    metrics = _load_module().confusion_metrics(1, 1, 1, 877)

    assert metrics["sample_count"] == 880
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1"] == 0.5
    assert metrics["specificity"] == 0.9989
    assert metrics["balanced_accuracy"] == 0.7494
    assert metrics["precision_wilson_95"] == [0.0945, 0.9055]
    assert metrics["recall_wilson_95"] == [0.0945, 0.9055]


def test_confusion_metrics_handle_zero_denominators_without_claiming_certainty() -> None:
    metrics = _load_module().confusion_metrics(0, 0, 0, 0)

    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["specificity"] == 0.0
    assert metrics["precision_wilson_95"] == [0.0, 0.0]
    assert metrics["sample_count"] == 0
