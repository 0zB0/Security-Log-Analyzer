#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
API_ROOT = ROOT / "apps/api"
TOOLS_ROOT = ROOT / "tools"
RULES_ROOT = ROOT / "packages/rules"
DEFAULT_JSON = ROOT / "docs/proof-pack/current-iot23-evaluation.json"
DEFAULT_MARKDOWN = ROOT / "docs/proof-pack/current-iot23-evaluation.md"
MALICIOUS_URL = (
    "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/"
    "CTU-IoT-Malware-Capture-34-1/bro/conn.log.labeled"
)
BENIGN_URL = (
    "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/"
    "CTU-Honeypot-Capture-4-1/bro/conn.log.labeled"
)
SCAN_LABEL = "PartOfAHorizontalPortScan"
SCAN_RULE_IDS = {
    "zeek-conn-attempt-burst-001",
    "zeek-conn-host-sweep-001",
    "zeek-conn-port-scan-001",
}

sys.path.insert(0, str(API_ROOT))
sys.path.insert(0, str(TOOLS_ROOT))

from tracehawk_api.models.domain import ParsedEvent  # noqa: E402
from tracehawk_api.services.detection import run_detection  # noqa: E402
from tracehawk_api.services.rules import load_rules  # noqa: E402
from tracehawk_api.services.zeek_tsv_parser import ZeekTsvParser  # noqa: E402
from evaluation_metrics import confusion_metrics  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate TraceHawk on IoT-23 labeled Zeek logs.")
    parser.add_argument("--input", required=True, action="append", type=Path, help="IoT-23 malicious conn.log.labeled; repeat for more captures")
    parser.add_argument(
        "--benign-input",
        required=True,
        action="append",
        type=Path,
        help="IoT-23 benign-device conn.log.labeled; repeat for more captures",
    )
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--markdown-output", type=Path, default=DEFAULT_MARKDOWN)
    args = parser.parse_args()

    report = evaluate_iot23(args.input, args.benign_input)
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    args.markdown_output.write_text(render_markdown(report))
    metrics = report["aggregate_scan_window_metrics"]
    print(
        "iot23_evaluation=ok "
        f"rows={sum(dataset['parsed_rows'] for dataset in report['datasets'])} "
        f"tp={metrics['true_positive_windows']} fp={metrics['false_positive_windows']} "
        f"fn={metrics['false_negative_windows']} tn={metrics['true_negative_windows']}"
    )
    return 0


def evaluate_iot23(
    malicious_paths: Path | list[Path], benign_paths: Path | list[Path]
) -> dict[str, Any]:
    malicious_paths = [malicious_paths] if isinstance(malicious_paths, Path) else malicious_paths
    benign_paths = [benign_paths] if isinstance(benign_paths, Path) else benign_paths
    rules = [rule for rule in load_rules(RULES_ROOT / "zeek") if rule.id in SCAN_RULE_IDS]
    datasets: list[dict[str, Any]] = []
    capture_metrics: list[dict[str, Any]] = []
    for path, force_benign in [
        *((path, False) for path in malicious_paths),
        *((path, True) for path in benign_paths),
    ]:
        events, labels = _parse_labeled_zeek(path, force_benign=force_benign)
        metrics = _evaluate_windows(events, labels, rules)
        capture_metrics.append(metrics)
        datasets.append(
            _dataset_metadata(path, _source_url(path, force_benign), events, labels, metrics)
        )
    aggregate = _combine_metrics(*capture_metrics)

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "dataset": "IoT-23",
        "citation": (
            "Stratosphere Laboratory. A labeled dataset with malicious and benign IoT "
            "network traffic. Agustin Parmisano, Sebastian Garcia, Maria Jose Erquiaga."
        ),
        "license": "CC-BY; source citation required.",
        "methodology": {
            "objective": (
                "Evaluate deterministic Zeek connection-attempt, host-sweep, and port-scan "
                "findings against the IoT-23 PartOfAHorizontalPortScan label."
            ),
            "window_seconds": 120,
            "ground_truth_positive": f"A window contains at least one `{SCAN_LABEL}` flow.",
            "prediction_positive": (
                "A window produces a Zeek connection-attempt burst, host-sweep, or port-scan finding."
            ),
            "limitations": [
                "Fixed windows can split activity across a boundary.",
                "Only scan rules are scored; C&C and DDoS labels are outside this evaluation.",
                "IoT-23 is a controlled research dataset and is not current production traffic.",
                "Metrics are window-level, not packet-level or host-level prevalence estimates.",
            ],
        },
        "datasets": datasets,
        "aggregate_scan_window_metrics": aggregate,
    }


def _parse_labeled_zeek(
    path: Path,
    *,
    force_benign: bool = False,
) -> tuple[list[ParsedEvent], dict[str, str]]:
    parser = ZeekTsvParser()
    events: list[ParsedEvent] = []
    labels: dict[str, str] = {}
    source_id = f"iot23:{path.stem}"
    for line_number, raw_line in enumerate(path.read_text().splitlines(), start=1):
        raw_line_id = f"{source_id}:line:{line_number}"
        event = parser.parse_line(raw_line_id, source_id, raw_line)
        if event is None:
            continue
        parts = raw_line.split("\t")
        label = "Benign" if force_benign else _detailed_label(parts)
        events.append(event)
        labels[event.id] = label
    if not events:
        raise ValueError(f"No Zeek events were parsed from {path}.")
    return events, labels


def _detailed_label(parts: list[str]) -> str:
    if len(parts) < 23:
        return "Unknown"
    broad_label, detailed_label = parts[-2], parts[-1]
    return detailed_label if detailed_label not in {"", "-"} else broad_label


def _evaluate_windows(
    events: list[ParsedEvent],
    labels: dict[str, str],
    rules: list,
) -> dict[str, Any]:
    windows: dict[int, list[ParsedEvent]] = defaultdict(list)
    for event in events:
        if event.event_time is None:
            continue
        windows[int(event.event_time.timestamp() // 120)].append(event)

    tp = fp = fn = tn = 0
    detected_rules: Counter[str] = Counter()
    false_positive_examples: list[dict[str, Any]] = []
    false_negative_examples: list[dict[str, Any]] = []
    for window_key, window_events in windows.items():
        ground_positive = any(labels.get(event.id) == SCAN_LABEL for event in window_events)
        findings = run_detection(rules, window_events)
        observed_ids = {finding.rule_id for finding in findings}
        predicted_positive = bool(observed_ids)
        detected_rules.update(observed_ids)
        if ground_positive and predicted_positive:
            tp += 1
        elif not ground_positive and predicted_positive:
            fp += 1
            if len(false_positive_examples) < 5:
                false_positive_examples.append(
                    _window_example(window_key, window_events, labels, observed_ids)
                )
        elif ground_positive:
            fn += 1
            if len(false_negative_examples) < 5:
                false_negative_examples.append(
                    _window_example(window_key, window_events, labels, observed_ids)
                )
        else:
            tn += 1

    return {
        "window_count": len(windows),
        "true_positive_windows": tp,
        "false_positive_windows": fp,
        "false_negative_windows": fn,
        "true_negative_windows": tn,
        "detected_rule_windows": dict(sorted(detected_rules.items())),
        "false_positive_examples": false_positive_examples,
        "false_negative_examples": false_negative_examples,
    }


def _window_example(
    window_key: int,
    events: list[ParsedEvent],
    labels: dict[str, str],
    observed_rule_ids: set[str],
) -> dict[str, Any]:
    endpoints = sorted(
        {
            (
                event.source_ip or "?",
                str(event.normalized_fields.get("destination_ip") or "?"),
                str(event.normalized_fields.get("destination_port") or "?"),
            )
            for event in events
        }
    )
    return {
        "window_start": datetime.fromtimestamp(window_key * 120, tz=UTC).isoformat(),
        "event_count": len(events),
        "label_counts": dict(sorted(Counter(labels.get(event.id, "Unknown") for event in events).items())),
        "observed_rule_ids": sorted(observed_rule_ids),
        "sample_endpoints": [" -> ".join(endpoint) for endpoint in endpoints[:5]],
    }


def _combine_metrics(*metrics: dict[str, Any]) -> dict[str, Any]:
    combined = {
        key: sum(int(metric[key]) for metric in metrics)
        for key in (
            "window_count",
            "true_positive_windows",
            "false_positive_windows",
            "false_negative_windows",
            "true_negative_windows",
        )
    }
    tp = combined["true_positive_windows"]
    fp = combined["false_positive_windows"]
    fn = combined["false_negative_windows"]
    tn = combined["true_negative_windows"]
    derived = confusion_metrics(tp, fp, fn, tn)
    combined.update({key: value for key, value in derived.items() if key not in {
        "true_positive", "false_positive", "false_negative", "true_negative", "sample_count"
    }})
    return combined


def _source_url(path: Path, force_benign: bool) -> str:
    if "34-1" in path.name:
        return MALICIOUS_URL
    if "benign-4-1" in path.name.lower() or "honeypot-4-1" in path.name.lower():
        return BENIGN_URL
    capture_kind = "benign" if force_benign else "malicious"
    return f"IoT-23 local {capture_kind} capture; source URL must be recorded in the evaluation manifest"


def _dataset_metadata(
    path: Path,
    source_url: str,
    events: list[ParsedEvent],
    labels: dict[str, str],
    metrics: dict[str, Any],
) -> dict[str, Any]:
    content = path.read_bytes()
    return {
        "filename": path.name,
        "source_url": source_url,
        "sha256": sha256(content).hexdigest(),
        "bytes": len(content),
        "parsed_rows": len(events),
        "label_counts": dict(sorted(Counter(labels.values()).items())),
        "scan_window_metrics": metrics,
    }


def render_markdown(report: dict[str, Any]) -> str:
    metrics = report["aggregate_scan_window_metrics"]
    rows = [
        "# Current IoT-23 Detection Evaluation",
        "",
        f"Generated: `{report['generated_at']}`",
        "",
        "## Dataset And Scope",
        "",
        report["citation"],
        "",
        report["methodology"]["objective"],
        "",
        "| Capture | Parsed rows | SHA-256 |",
        "| --- | ---: | --- |",
    ]
    for dataset in report["datasets"]:
        rows.append(
            f"| [{dataset['filename']}]({dataset['source_url']}) | "
            f"{dataset['parsed_rows']} | `{dataset['sha256']}` |"
        )
    rows.extend(
        [
            "",
            "## Scan Window Metrics",
            "",
            "| Measure | Result |",
            "| --- | ---: |",
            f"| Two-minute windows | {metrics['window_count']} |",
            f"| True-positive windows | {metrics['true_positive_windows']} |",
            f"| False-positive windows | {metrics['false_positive_windows']} |",
            f"| False-negative windows | {metrics['false_negative_windows']} |",
            f"| True-negative windows | {metrics['true_negative_windows']} |",
            f"| Precision | {metrics['precision']:.4f} |",
            f"| Precision 95% Wilson interval | {metrics['precision_wilson_95'][0]:.4f}–{metrics['precision_wilson_95'][1]:.4f} |",
            f"| Recall | {metrics['recall']:.4f} |",
            f"| Recall 95% Wilson interval | {metrics['recall_wilson_95'][0]:.4f}–{metrics['recall_wilson_95'][1]:.4f} |",
            f"| F1 | {metrics['f1']:.4f} |",
            f"| Specificity | {metrics['specificity']:.4f} |",
            f"| Balanced accuracy | {metrics['balanced_accuracy']:.4f} |",
            f"| Positive prevalence | {metrics['positive_prevalence']:.4f} |",
            f"| False-positive rate | {metrics['false_positive_rate']:.4f} |",
            "",
            "The wide precision and recall intervals are material: only two predicted-positive and",
            "two ground-truth-positive windows are present. Point estimates must not be presented as",
            "stable detection-quality estimates for the complete product.",
            "",
            "## Per-Capture And Per-Rule Results",
            "",
            "| Capture | Windows | TP | FP | FN | TN | Detected rule windows |",
            "| --- | ---: | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for dataset in report["datasets"]:
        capture = dataset["scan_window_metrics"]
        detected = ", ".join(
            f"{rule_id}: {count}"
            for rule_id, count in capture["detected_rule_windows"].items()
        ) or "none"
        rows.append(
            f"| {dataset['filename']} | {capture['window_count']} | "
            f"{capture['true_positive_windows']} | {capture['false_positive_windows']} | "
            f"{capture['false_negative_windows']} | {capture['true_negative_windows']} | {detected} |"
        )
    rows.extend(
        [
            "",
            "## Limitations",
            "",
        ]
    )
    rows.extend(f"- {item}" for item in report["methodology"]["limitations"])
    false_positive_examples = [
        example
        for dataset in report["datasets"]
        for example in dataset["scan_window_metrics"]["false_positive_examples"]
    ]
    false_negative_examples = [
        example
        for dataset in report["datasets"]
        for example in dataset["scan_window_metrics"]["false_negative_examples"]
    ]
    rows.extend(["", "## Error Analysis", ""])
    if false_positive_examples:
        example = false_positive_examples[0]
        rows.extend(
            [
                "The observed false-positive window is labeled as DDoS rather than horizontal scan,",
                "but it contains the same repeated unsuccessful connection-attempt shape detected by",
                f"`{', '.join(example['observed_rule_ids'])}`. Under this narrow label objective it is",
                "counted as a false positive; operationally it remains suspicious behavior requiring",
                "classification rather than suppression.",
                "",
                f"- Window: `{example['window_start']}`",
                f"- Events: {example['event_count']}",
                f"- Labels: `{json.dumps(example['label_counts'], sort_keys=True)}`",
            ]
        )
    if false_negative_examples:
        example = false_negative_examples[0]
        rows.extend(
            [
                "",
                "The false-negative window contains an isolated scan-labeled flow below the 100-event",
                "burst threshold. Lowering the threshold solely to capture this point would weaken the",
                "benign and DDoS separation and is not justified by this dataset alone.",
                "",
                f"- Window: `{example['window_start']}`",
                f"- Events: {example['event_count']}",
                f"- Labels: `{json.dumps(example['label_counts'], sort_keys=True)}`",
            ]
        )
    rows.append("")
    return "\n".join(rows)


if __name__ == "__main__":
    raise SystemExit(main())
