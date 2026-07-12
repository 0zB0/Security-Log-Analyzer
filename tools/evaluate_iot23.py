#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
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
EVALUATION_MANIFEST = ROOT / "docs/evaluation-manifest.json"

SCAN_LABEL = "PartOfAHorizontalPortScan"
C2_LABEL_DESCRIPTION = "C&C or a detailed label beginning with C&C-"
OBJECTIVES: dict[str, dict[str, Any]] = {
    "network_scan": {
        "title": "Horizontal network-scan windows",
        "window_seconds": 120,
        "rule_ids": {
            "zeek-conn-attempt-burst-001",
            "zeek-conn-host-sweep-001",
            "zeek-conn-port-scan-001",
        },
        "ground_truth": f"A window contains at least one `{SCAN_LABEL}` flow.",
        "prediction": (
            "A window produces a Zeek connection-attempt burst, host-sweep, or port-scan finding."
        ),
    },
    "command_and_control": {
        "title": "Stable-endpoint C2-indicator windows",
        "window_seconds": 300,
        "rule_ids": {"zeek-stable-endpoint-retry-001"},
        "ground_truth": f"A window contains at least one label in the {C2_LABEL_DESCRIPTION} family.",
        "prediction": (
            "A window produces the low-confidence repeated failed stable-endpoint finding."
        ),
    },
}

CAPTURE_CATALOG: dict[str, dict[str, Any]] = {
    "34-1": {
        "scenario": "CTU-IoT-Malware-Capture-34-1",
        "role": "final_evaluation",
        "objectives": ["network_scan"],
    },
    "20-1": {
        "scenario": "CTU-IoT-Malware-Capture-20-1",
        "role": "development",
        "objectives": ["command_and_control"],
    },
    "21-1": {
        "scenario": "CTU-IoT-Malware-Capture-21-1",
        "role": "validation",
        "objectives": ["command_and_control"],
    },
    "8-1": {
        "scenario": "CTU-IoT-Malware-Capture-8-1",
        "role": "validation",
        "objectives": ["command_and_control"],
    },
    "42-1": {
        "scenario": "CTU-IoT-Malware-Capture-42-1",
        "role": "final_evaluation",
        "objectives": ["command_and_control"],
    },
    "44-1": {
        "scenario": "CTU-IoT-Malware-Capture-44-1",
        "role": "final_evaluation",
        "objectives": ["command_and_control"],
    },
    "4-1": {
        "scenario": "CTU-Honeypot-Capture-4-1",
        "role": "negative_control",
        "objectives": ["network_scan", "command_and_control"],
    },
}

sys.path.insert(0, str(API_ROOT))
sys.path.insert(0, str(TOOLS_ROOT))

from evaluation_metrics import confusion_metrics  # noqa: E402
from tracehawk_api.models.domain import ParsedEvent  # noqa: E402
from tracehawk_api.services.detection import run_detection  # noqa: E402
from tracehawk_api.services.rules import load_rules  # noqa: E402
from tracehawk_api.services.zeek_tsv_parser import ZeekTsvParser  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate selected TraceHawk Zeek objectives on official IoT-23 labeled captures."
        )
    )
    parser.add_argument(
        "--input",
        required=True,
        action="append",
        type=Path,
        help=(
            "IoT-23 malicious conn.log.labeled; repeat for development, validation, and final "
            "captures. Known capture IDs receive frozen roles."
        ),
    )
    parser.add_argument(
        "--benign-input",
        required=True,
        action="append",
        type=Path,
        help="IoT-23 benign conn.log.labeled negative control; repeat when needed.",
    )
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--markdown-output", type=Path, default=DEFAULT_MARKDOWN)
    args = parser.parse_args()

    report = evaluate_iot23(args.input, args.benign_input)
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    args.markdown_output.write_text(render_markdown(report))
    scan = report["objectives"]["network_scan"]["final_metrics"]
    c2 = report["objectives"]["command_and_control"]["final_metrics"]
    print(
        "iot23_evaluation=ok "
        f"rows={sum(dataset['parsed_rows'] for dataset in report['datasets'])} "
        f"scan_tp={scan['true_positive_windows']} scan_fp={scan['false_positive_windows']} "
        f"scan_fn={scan['false_negative_windows']} "
        f"c2_tp={c2['true_positive_windows']} c2_fp={c2['false_positive_windows']} "
        f"c2_fn={c2['false_negative_windows']}"
    )
    return 0


def evaluate_iot23(
    malicious_paths: Path | list[Path],
    benign_paths: Path | list[Path],
) -> dict[str, Any]:
    malicious = [malicious_paths] if isinstance(malicious_paths, Path) else malicious_paths
    benign = [benign_paths] if isinstance(benign_paths, Path) else benign_paths
    paths = [*malicious, *benign]
    if len(paths) != len({path.resolve() for path in paths}):
        raise ValueError("Each IoT-23 capture path must be unique.")

    relevant_rule_ids = {
        rule_id
        for objective in OBJECTIVES.values()
        for rule_id in objective["rule_ids"]
    }
    rules_by_id = {
        rule.id: rule
        for rule in load_rules(RULES_ROOT / "zeek")
        if rule.id in relevant_rule_ids
    }
    if set(rules_by_id) != relevant_rule_ids:
        missing = ", ".join(sorted(relevant_rule_ids - set(rules_by_id)))
        raise ValueError(f"IoT-23 evaluation rules are missing: {missing}")

    datasets: list[dict[str, Any]] = []
    for path, force_benign in [
        *((path, False) for path in malicious),
        *((path, True) for path in benign),
    ]:
        definition = _capture_definition(path, force_benign=force_benign)
        events, labels, label_formats = _parse_labeled_zeek(
            path,
            force_benign=force_benign,
        )
        objective_metrics: dict[str, dict[str, Any]] = {}
        for objective_id in definition["objectives"]:
            objective = OBJECTIVES[objective_id]
            objective_rules = [
                rules_by_id[rule_id] for rule_id in sorted(objective["rule_ids"])
            ]
            objective_metrics[objective_id] = _evaluate_windows(
                events,
                labels,
                objective_rules,
                objective_id=objective_id,
                window_seconds=int(objective["window_seconds"]),
            )
        datasets.append(
            _dataset_metadata(
                path,
                definition,
                events,
                labels,
                label_formats,
                objective_metrics,
            )
        )

    objective_reports = {
        objective_id: _objective_report(objective_id, datasets)
        for objective_id in OBJECTIVES
    }
    evaluation_manifest = json.loads(EVALUATION_MANIFEST.read_text(encoding="utf-8"))
    c2_manifest = next(
        item
        for item in evaluation_manifest["evaluations"]
        if item["behavior_family"] == "command_and_control"
    )
    return {
        "schema_version": 2,
        "generated_at": datetime.now(UTC).isoformat(),
        "dataset": "IoT-23",
        "citation": (
            "Stratosphere Laboratory. A labeled dataset with malicious and benign IoT "
            "network traffic. Agustin Parmisano, Sebastian Garcia, Maria Jose Erquiaga."
        ),
        "license": "CC-BY; source citation required.",
        "methodology": {
            "rule_freeze_commit": c2_manifest["rule_freeze_commit"],
            "frozen_rule": c2_manifest["frozen_rule"],
            "role_policy": {
                "development": "May guide the rule shape and threshold.",
                "validation": "May expose instability but is not counted as final holdout evidence.",
                "final_evaluation": "Scored only after the rule and threshold are frozen.",
                "negative_control": "Contributes final negative windows to each assigned objective.",
                "supplemental": "Reported but excluded from final metrics until explicitly classified.",
            },
            "label_formats": [
                "separate label and detailed-label TSV columns",
                "legacy combined tunnel_parents/label/detailed-label column",
            ],
            "limitations": [
                "Fixed windows can split activity across a boundary.",
                "The C2 objective measures one low-confidence retry indicator, not all C2 behavior.",
                "IoT-23 is a controlled, historical research dataset, not current production traffic.",
                "Metrics are window-level and do not estimate packet-, flow-, host-, or tenant prevalence.",
                "Capture heterogeneity makes per-capture errors more informative than one pooled score.",
            ],
        },
        "datasets": datasets,
        "objectives": objective_reports,
        "aggregate_scan_window_metrics": objective_reports["network_scan"]["final_metrics"],
    }


def _parse_labeled_zeek(
    path: Path,
    *,
    force_benign: bool = False,
) -> tuple[list[ParsedEvent], dict[str, str], Counter[str]]:
    parser = ZeekTsvParser()
    events: list[ParsedEvent] = []
    labels: dict[str, str] = {}
    label_formats: Counter[str] = Counter()
    source_id = f"iot23:{path.stem}"
    for line_number, raw_line in enumerate(path.read_text().splitlines(), start=1):
        raw_line_id = f"{source_id}:line:{line_number}"
        event = parser.parse_line(raw_line_id, source_id, raw_line)
        if event is None:
            continue
        parsed_label, label_format = _extract_detailed_label(raw_line.split("\t"))
        label = "Benign" if force_benign else parsed_label
        events.append(event)
        labels[event.id] = label
        label_formats[label_format] += 1
    if not events:
        raise ValueError(f"No Zeek events were parsed from {path}.")
    if not force_benign and set(labels.values()) == {"Unknown"}:
        raise ValueError(f"No supported IoT-23 labels were parsed from {path}.")
    return events, labels, label_formats


def _detailed_label(parts: list[str]) -> str:
    return _extract_detailed_label(parts)[0]


def _extract_detailed_label(parts: list[str]) -> tuple[str, str]:
    if len(parts) >= 23:
        broad_label = parts[-2].strip()
        detailed_label = parts[-1].strip()
        return (
            detailed_label if detailed_label not in {"", "-"} else broad_label,
            "separate_columns",
        )

    if not parts:
        return "Unknown", "unknown"
    combined = parts[-1].strip()
    tokens = re.split(r"\s{2,}", combined)
    if len(tokens) >= 3 and tokens[-2].lower() in {"benign", "malicious"}:
        broad_label, detailed_label = tokens[-2].title(), tokens[-1]
        return (
            detailed_label if detailed_label not in {"", "-"} else broad_label,
            "combined_column",
        )
    match = re.match(
        r"^.*?\s+(Benign|Malicious)\s+(\S+)$",
        combined,
        flags=re.IGNORECASE,
    )
    if match:
        broad_label, detailed_label = match.groups()
        broad_label = broad_label.title()
        return (
            detailed_label if detailed_label not in {"", "-"} else broad_label,
            "combined_column",
        )
    return "Unknown", "unknown"


def _evaluate_windows(
    events: list[ParsedEvent],
    labels: dict[str, str],
    rules: list[Any],
    *,
    objective_id: str,
    window_seconds: int,
) -> dict[str, Any]:
    windows: dict[int, list[ParsedEvent]] = defaultdict(list)
    for event in events:
        if event.event_time is None:
            continue
        windows[int(event.event_time.timestamp() // window_seconds)].append(event)

    tp = fp = fn = tn = 0
    detected_rules: Counter[str] = Counter()
    false_positive_examples: list[dict[str, Any]] = []
    false_negative_examples: list[dict[str, Any]] = []
    for window_key, window_events in sorted(windows.items()):
        ground_positive = any(
            _is_positive_label(objective_id, labels.get(event.id, "Unknown"))
            for event in window_events
        )
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
                    _window_example(
                        window_key,
                        window_seconds,
                        window_events,
                        labels,
                        observed_ids,
                    )
                )
        elif ground_positive:
            fn += 1
            if len(false_negative_examples) < 5:
                false_negative_examples.append(
                    _window_example(
                        window_key,
                        window_seconds,
                        window_events,
                        labels,
                        observed_ids,
                    )
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


def _is_positive_label(objective_id: str, label: str) -> bool:
    if objective_id == "network_scan":
        return label == SCAN_LABEL
    if objective_id == "command_and_control":
        return label == "C&C" or label.startswith("C&C-")
    raise ValueError(f"Unknown evaluation objective: {objective_id}")


def _window_example(
    window_key: int,
    window_seconds: int,
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
        "window_start": datetime.fromtimestamp(
            window_key * window_seconds, tz=UTC
        ).isoformat(),
        "event_count": len(events),
        "label_counts": dict(
            sorted(Counter(labels.get(event.id, "Unknown") for event in events).items())
        ),
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
    detected_rules: Counter[str] = Counter()
    for metric in metrics:
        detected_rules.update(metric.get("detected_rule_windows", {}))
    combined["detected_rule_windows"] = dict(sorted(detected_rules.items()))
    combined["false_positive_examples"] = [
        example
        for metric in metrics
        for example in metric.get("false_positive_examples", [])
    ][:5]
    combined["false_negative_examples"] = [
        example
        for metric in metrics
        for example in metric.get("false_negative_examples", [])
    ][:5]
    derived = confusion_metrics(
        combined["true_positive_windows"],
        combined["false_positive_windows"],
        combined["false_negative_windows"],
        combined["true_negative_windows"],
    )
    combined.update(
        {
            key: value
            for key, value in derived.items()
            if key
            not in {
                "true_positive",
                "false_positive",
                "false_negative",
                "true_negative",
                "sample_count",
            }
        }
    )
    return combined


def _objective_report(
    objective_id: str,
    datasets: list[dict[str, Any]],
) -> dict[str, Any]:
    objective = OBJECTIVES[objective_id]
    applicable = [
        dataset
        for dataset in datasets
        if objective_id in dataset["objective_metrics"]
    ]
    metrics_by_role = {
        role: _combine_metrics(
            *[
                dataset["objective_metrics"][objective_id]
                for dataset in applicable
                if dataset["role"] == role
            ]
        )
        for role in (
            "development",
            "validation",
            "final_evaluation",
            "negative_control",
            "supplemental",
        )
    }
    final_metrics = _combine_metrics(
        *[
            dataset["objective_metrics"][objective_id]
            for dataset in applicable
            if dataset["role"] in {"final_evaluation", "negative_control"}
        ]
    )
    return {
        "title": objective["title"],
        "window_seconds": objective["window_seconds"],
        "rule_ids": sorted(objective["rule_ids"]),
        "ground_truth_positive": objective["ground_truth"],
        "prediction_positive": objective["prediction"],
        "final_capture_ids": [
            dataset["capture_id"]
            for dataset in applicable
            if dataset["role"] == "final_evaluation"
        ],
        "negative_control_capture_ids": [
            dataset["capture_id"]
            for dataset in applicable
            if dataset["role"] == "negative_control"
        ],
        "metrics_by_role": metrics_by_role,
        "final_metrics": final_metrics,
    }


def _capture_definition(path: Path, *, force_benign: bool) -> dict[str, Any]:
    capture_id = _capture_id(path)
    catalog = CAPTURE_CATALOG.get(capture_id)
    if catalog is None:
        return {
            "capture_id": capture_id,
            "role": "negative_control" if force_benign else "supplemental",
            "objectives": list(OBJECTIVES),
            "source_url": "IoT-23 local capture; record the official URL before final use",
        }
    scenario = str(catalog["scenario"])
    return {
        "capture_id": capture_id,
        "role": "negative_control" if force_benign else catalog["role"],
        "objectives": list(catalog["objectives"]),
        "source_url": (
            "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/"
            f"IndividualScenarios/{scenario}/bro/conn.log.labeled"
        ),
    }


def _capture_id(path: Path) -> str:
    lowered = path.name.lower()
    match = re.search(r"(?:iot23-(?:benign-)?|capture-)(\d+-\d+)", lowered)
    return match.group(1) if match else f"unknown:{path.stem}"


def _dataset_metadata(
    path: Path,
    definition: dict[str, Any],
    events: list[ParsedEvent],
    labels: dict[str, str],
    label_formats: Counter[str],
    objective_metrics: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    content = path.read_bytes()
    return {
        "capture_id": definition["capture_id"],
        "filename": path.name,
        "source_url": definition["source_url"],
        "license": "CC-BY; source citation required.",
        "sha256": sha256(content).hexdigest(),
        "bytes": len(content),
        "parsed_rows": len(events),
        "role": definition["role"],
        "objectives": definition["objectives"],
        "label_format_counts": dict(sorted(label_formats.items())),
        "label_counts": dict(sorted(Counter(labels.values()).items())),
        "objective_metrics": objective_metrics,
    }


def render_markdown(report: dict[str, Any]) -> str:
    rows = [
        "# Current IoT-23 Detection Evaluation",
        "",
        f"Generated: `{report['generated_at']}`",
        "",
        "## Dataset And Role Separation",
        "",
        report["citation"],
        "",
        "Development and validation captures are reported but excluded from final metrics. Final",
        "metrics combine only frozen holdout captures and the assigned benign negative control.",
        f"C2-indicator rule freeze commit: `{report['methodology']['rule_freeze_commit']}`.",
        "",
        "| Capture | Role | Objectives | Rows | Label format | SHA-256 |",
        "| --- | --- | --- | ---: | --- | --- |",
    ]
    for dataset in report["datasets"]:
        formats = ", ".join(dataset["label_format_counts"]) or "unknown"
        rows.append(
            f"| [{dataset['capture_id']}]({dataset['source_url']}) | {dataset['role']} | "
            f"{', '.join(dataset['objectives'])} | {dataset['parsed_rows']} | {formats} | "
            f"`{dataset['sha256']}` |"
        )

    for objective_id, objective in report["objectives"].items():
        metrics = objective["final_metrics"]
        rows.extend(
            [
                "",
                f"## {objective['title']}",
                "",
                f"Objective ID: `{objective_id}`",
                "",
                f"- Window: {objective['window_seconds']} seconds",
                f"- Rules: `{', '.join(objective['rule_ids'])}`",
                f"- Ground truth: {objective['ground_truth_positive']}",
                f"- Prediction: {objective['prediction_positive']}",
                f"- Frozen final captures: `{', '.join(objective['final_capture_ids'])}`",
                f"- Negative controls: `{', '.join(objective['negative_control_capture_ids'])}`",
                "",
                "### Final Metrics",
                "",
                "| Measure | Result |",
                "| --- | ---: |",
                f"| Windows | {metrics['window_count']} |",
                f"| TP | {metrics['true_positive_windows']} |",
                f"| FP | {metrics['false_positive_windows']} |",
                f"| FN | {metrics['false_negative_windows']} |",
                f"| TN | {metrics['true_negative_windows']} |",
                f"| Precision | {metrics['precision']:.4f} |",
                f"| Precision 95% Wilson interval | {_interval(metrics['precision_wilson_95'])} |",
                f"| Recall | {metrics['recall']:.4f} |",
                f"| Recall 95% Wilson interval | {_interval(metrics['recall_wilson_95'])} |",
                f"| F1 | {metrics['f1']:.4f} |",
                f"| Specificity | {metrics['specificity']:.4f} |",
                f"| Balanced accuracy | {metrics['balanced_accuracy']:.4f} |",
                f"| Positive prevalence | {metrics['positive_prevalence']:.4f} |",
                "",
                "### Per-Capture Results",
                "",
                "| Capture | Role | Windows | TP | FP | FN | TN | Detected rules |",
                "| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
            ]
        )
        for dataset in report["datasets"]:
            capture = dataset["objective_metrics"].get(objective_id)
            if capture is None:
                continue
            detected = ", ".join(
                f"{rule_id}: {count}"
                for rule_id, count in capture["detected_rule_windows"].items()
            ) or "none"
            rows.append(
                f"| {dataset['capture_id']} | {dataset['role']} | {capture['window_count']} | "
                f"{capture['true_positive_windows']} | {capture['false_positive_windows']} | "
                f"{capture['false_negative_windows']} | {capture['true_negative_windows']} | "
                f"{detected} |"
            )
        rows.extend(_error_analysis_rows(objective_id, report["datasets"]))

    rows.extend(["", "## Limitations", ""])
    rows.extend(f"- {item}" for item in report["methodology"]["limitations"])
    rows.append("")
    return "\n".join(rows)


def _error_analysis_rows(
    objective_id: str,
    datasets: list[dict[str, Any]],
) -> list[str]:
    rows = ["", "### Final Error Analysis", ""]
    examples: list[tuple[str, str, dict[str, Any]]] = []
    for dataset in datasets:
        if dataset["role"] not in {"final_evaluation", "negative_control"}:
            continue
        metrics = dataset["objective_metrics"].get(objective_id)
        if metrics is None:
            continue
        examples.extend(
            (dataset["capture_id"], "FP", example)
            for example in metrics["false_positive_examples"]
        )
        examples.extend(
            (dataset["capture_id"], "FN", example)
            for example in metrics["false_negative_examples"]
        )
    if not examples:
        return [*rows, "No final false-positive or false-negative example was observed."]
    for capture_id, error_type, example in examples[:6]:
        rows.extend(
            [
                f"- `{error_type}` capture `{capture_id}`, window `{example['window_start']}`: "
                f"{example['event_count']} events, labels "
                f"`{json.dumps(example['label_counts'], sort_keys=True)}`, rules "
                f"`{', '.join(example['observed_rule_ids']) or 'none'}`.",
            ]
        )
    return rows


def _interval(values: list[float]) -> str:
    return f"{values[0]:.4f}–{values[1]:.4f}"


if __name__ == "__main__":
    raise SystemExit(main())
