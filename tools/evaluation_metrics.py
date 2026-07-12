from __future__ import annotations

from math import sqrt
from typing import TypedDict


class ConfusionMetrics(TypedDict):
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    sample_count: int
    positive_prevalence: float
    precision: float
    recall: float
    specificity: float
    false_positive_rate: float
    f1: float
    balanced_accuracy: float
    precision_wilson_95: list[float]
    recall_wilson_95: list[float]
    specificity_wilson_95: list[float]


def safe_ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def wilson_interval(successes: int, total: int, *, z: float = 1.959963984540054) -> list[float]:
    """Return a bounded 95% Wilson score interval for a binomial proportion."""
    if total == 0:
        return [0.0, 0.0]
    proportion = successes / total
    denominator = 1 + z**2 / total
    centre = proportion + z**2 / (2 * total)
    margin = z * sqrt((proportion * (1 - proportion) + z**2 / (4 * total)) / total)
    return [round(max(0.0, (centre - margin) / denominator), 4), round(min(1.0, (centre + margin) / denominator), 4)]


def confusion_metrics(tp: int, fp: int, fn: int, tn: int) -> ConfusionMetrics:
    sample_count = tp + fp + fn + tn
    precision = safe_ratio(tp, tp + fp)
    recall = safe_ratio(tp, tp + fn)
    specificity = safe_ratio(tn, tn + fp)
    return {
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "sample_count": sample_count,
        "positive_prevalence": round(safe_ratio(tp + fn, sample_count), 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "specificity": round(specificity, 4),
        "false_positive_rate": round(1 - specificity if tn + fp else 0.0, 4),
        "f1": round(safe_ratio(2 * precision * recall, precision + recall), 4),
        "balanced_accuracy": round((recall + specificity) / 2, 4),
        "precision_wilson_95": wilson_interval(tp, tp + fp),
        "recall_wilson_95": wilson_interval(tp, tp + fn),
        "specificity_wilson_95": wilson_interval(tn, tn + fp),
    }
