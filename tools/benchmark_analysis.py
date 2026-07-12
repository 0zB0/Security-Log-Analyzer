#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import resource
import statistics
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
API_ROOT = ROOT / "apps/api"
RULES_ROOT = ROOT / "packages/rules"
DEFAULT_JSON = ROOT / "docs/proof-pack/current-performance.json"
DEFAULT_MARKDOWN = ROOT / "docs/proof-pack/current-performance.md"
DEFAULT_SCALE_JSON = ROOT / "docs/proof-pack/current-scale-performance.json"
DEFAULT_SCALE_MARKDOWN = ROOT / "docs/proof-pack/current-scale-performance.md"

SCENARIOS = {
    "core-auth-100kb": {"kind": "core", "bytes": 100_000},
    "core-auth-1mb": {"kind": "core", "bytes": 1_000_000},
    "core-auth-near-limit": {"kind": "core", "bytes": 1_900_000},
    "core-mixed-100kb": {"kind": "mixed", "bytes": 100_000},
    "core-mixed-1mb": {"kind": "mixed", "bytes": 1_000_000},
    "case-bundle-eight-sources": {"kind": "bundle", "bytes_per_source": 900_000},
    "api-upload-pdf-report": {"kind": "api-report"},
    "live-retention-2k-lines": {
        "kind": "live",
        "line_count": 2000,
        "raw_capacity": 200,
        "event_capacity": 150,
    },
    "offline-auth-10mb": {"kind": "core", "bytes": 10_000_000},
    "offline-auth-50mb": {"kind": "core", "bytes": 50_000_000},
    "offline-auth-100mb": {"kind": "core", "bytes": 100_000_000},
}

SMOKE_SCENARIOS = [
    "core-auth-100kb",
    "core-mixed-100kb",
    "api-upload-pdf-report",
    "live-retention-2k-lines",
]
FULL_SCENARIOS = [
    "core-auth-100kb",
    "core-auth-1mb",
    "core-auth-near-limit",
    "core-mixed-100kb",
    "core-mixed-1mb",
    "case-bundle-eight-sources",
    "api-upload-pdf-report",
    "live-retention-2k-lines",
]
SCALE_SCENARIOS = ["offline-auth-10mb", "offline-auth-50mb", "offline-auth-100mb"]

BUDGETS = {
    "core-auth-100kb": {"p95_seconds": 2.0, "max_rss_mb": 256.0},
    "core-auth-1mb": {"p95_seconds": 10.0, "max_rss_mb": 512.0},
    "core-auth-near-limit": {"p95_seconds": 20.0, "max_rss_mb": 768.0},
    "core-mixed-100kb": {"p95_seconds": 3.0, "max_rss_mb": 256.0},
    "core-mixed-1mb": {"p95_seconds": 20.0, "max_rss_mb": 768.0},
    "case-bundle-eight-sources": {"p95_seconds": 30.0, "max_rss_mb": 1024.0},
    "api-upload-pdf-report": {"p95_seconds": 5.0, "max_rss_mb": 384.0},
    "live-retention-2k-lines": {"p95_seconds": 10.0, "max_rss_mb": 256.0},
    "offline-auth-10mb": {"p95_seconds": 30.0, "max_rss_mb": 1536.0},
    "offline-auth-50mb": {"p95_seconds": 150.0, "max_rss_mb": 6144.0},
    "offline-auth-100mb": {"p95_seconds": 300.0, "max_rss_mb": 12288.0},
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run isolated TraceHawk performance benchmarks.")
    parser.add_argument("--profile", choices=("smoke", "full", "scale"), default="full")
    parser.add_argument("--repeats", type=int)
    parser.add_argument("--check", action="store_true", help="Do not write proof artifacts.")
    parser.add_argument(
        "--calibrate",
        action="store_true",
        help="Record results without enforcing budgets.",
    )
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--markdown-output", type=Path)
    parser.add_argument("--worker", choices=SCENARIOS)
    args = parser.parse_args()

    if args.worker:
        print(json.dumps(run_worker(args.worker), sort_keys=True))
        return 0

    repeats = args.repeats or (1 if args.profile in {"smoke", "scale"} else 3)
    scenario_names = {
        "smoke": SMOKE_SCENARIOS,
        "full": FULL_SCENARIOS,
        "scale": SCALE_SCENARIOS,
    }[args.profile]
    report = run_benchmarks(scenario_names, repeats)
    if not args.calibrate:
        assert_budgets(report)
    if not args.check:
        json_output = args.json_output or (
            DEFAULT_SCALE_JSON if args.profile == "scale" else DEFAULT_JSON
        )
        markdown_output = args.markdown_output or (
            DEFAULT_SCALE_MARKDOWN if args.profile == "scale" else DEFAULT_MARKDOWN
        )
        json_output.parent.mkdir(parents=True, exist_ok=True)
        json_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        markdown_output.write_text(render_markdown(report))
    print(
        f"benchmark_{args.profile}=ok scenarios={len(scenario_names)} "
        f"repeats={repeats} budgets={'calibration' if args.calibrate else 'passed'}"
    )
    return 0


def run_benchmarks(scenario_names: list[str], repeats: int) -> dict[str, Any]:
    results = []
    for scenario_name in scenario_names:
        samples = [_run_isolated_worker(scenario_name) for _ in range(repeats)]
        elapsed = [float(sample["elapsed_seconds"]) for sample in samples]
        rss = [float(sample["max_rss_mb"]) for sample in samples]
        throughput = [float(sample["lines_per_second"]) for sample in samples]
        budget = BUDGETS[scenario_name]
        p95_seconds = _percentile(elapsed, 0.95)
        max_rss_mb = max(rss)
        result_summary = {
                "scenario": scenario_name,
                "description": SCENARIOS[scenario_name],
                "repeats": repeats,
                "payload_bytes": max(int(sample["payload_bytes"]) for sample in samples),
                "line_count": max(int(sample["line_count"]) for sample in samples),
                "parsed_event_count": max(
                    int(sample["parsed_event_count"]) for sample in samples
                ),
                "p50_seconds": round(statistics.median(elapsed), 4),
                "p95_seconds": round(p95_seconds, 4),
                "max_rss_mb": round(max_rss_mb, 2),
                "p50_lines_per_second": round(statistics.median(throughput), 2),
                "budget": budget,
                "budget_passed": (
                    p95_seconds <= budget["p95_seconds"]
                    and max_rss_mb <= budget["max_rss_mb"]
                ),
                "samples": samples,
            }
        if live_retention := samples[-1].get("live_retention"):
            result_summary["live_retention"] = live_retention
        results.append(result_summary)
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "base_commit": _git_commit(),
        "working_tree_dirty": _working_tree_dirty(),
        "environment": _environment_metadata(),
        "methodology": {
            "process_isolation": True,
            "p95_method": "nearest-rank over isolated worker runs",
            "rss_note": "Linux ru_maxrss peak for the complete worker process.",
            "ci_note": "CI runs the smoke profile; full results use three repetitions locally.",
        },
        "results": results,
    }


def assert_budgets(report: dict[str, Any]) -> None:
    failed = [result["scenario"] for result in report["results"] if not result["budget_passed"]]
    if failed:
        raise AssertionError(f"Performance budget failed: {', '.join(failed)}")


def _run_isolated_worker(scenario_name: str) -> dict[str, Any]:
    process = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--worker", scenario_name],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=360 if scenario_name in SCALE_SCENARIOS else 120,
    )
    lines = [line for line in process.stdout.splitlines() if line.strip()]
    return json.loads(lines[-1])


def run_worker(scenario_name: str) -> dict[str, Any]:
    scenario = SCENARIOS[scenario_name]
    with tempfile.TemporaryDirectory(prefix="tracehawk-benchmark-") as temp_dir:
        os.environ["TRACEHAWK_DB_PATH"] = str(Path(temp_dir) / "benchmark.db")
        sys.path.insert(0, str(API_ROOT))
        started = perf_counter()
        if scenario["kind"] == "core":
            result, payload_bytes, line_count = _run_core(int(scenario["bytes"]), mixed=False)
        elif scenario["kind"] == "mixed":
            result, payload_bytes, line_count = _run_core(int(scenario["bytes"]), mixed=True)
        elif scenario["kind"] == "bundle":
            result, payload_bytes, line_count = _run_bundle(int(scenario["bytes_per_source"]))
        elif scenario["kind"] == "live":
            result, payload_bytes, line_count = _run_live_retention(
                int(scenario["line_count"]),
                int(scenario["raw_capacity"]),
                int(scenario["event_capacity"]),
            )
        else:
            result, payload_bytes, line_count = _run_api_report()
        elapsed = perf_counter() - started
        rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        worker_result = {
            "scenario": scenario_name,
            "elapsed_seconds": round(elapsed, 6),
            "max_rss_mb": round(rss_mb, 2),
            "payload_bytes": payload_bytes,
            "line_count": line_count,
            "parsed_event_count": int(result["parsed_event_count"]),
            "finding_count": int(result["finding_count"]),
            "incident_count": int(result["incident_count"]),
            "lines_per_second": round(line_count / elapsed if elapsed else 0.0, 2),
        }
        if live_retention := result.get("live_retention"):
            worker_result["live_retention"] = live_retention
        return worker_result


def _run_core(target_bytes: int, *, mixed: bool) -> tuple[dict[str, int], int, int]:
    from tracehawk_api.services.analysis import analyze_text

    auth = (ROOT / "packages/sample-data/auth/ssh-bruteforce.log").read_text()
    web = (ROOT / "packages/sample-data/nginx/probing.log").read_text()
    unit = f"{auth.rstrip()}\n{web}" if mixed else auth
    text = _repeat_complete_lines(unit, target_bytes)
    result = analyze_text(
        text=text,
        filename="benchmark-mixed.log" if mixed else "benchmark-auth.log",
        rules_root=RULES_ROOT,
    )
    return _result_counts(result), len(text.encode()), len(text.splitlines())


def _run_bundle(bytes_per_source: int) -> tuple[dict[str, int], int, int]:
    from tracehawk_api.services.case_bundle import CaseBundleInput, analyze_case_bundle

    auth = (ROOT / "packages/sample-data/auth/ssh-bruteforce.log").read_text()
    inputs = [
        CaseBundleInput(
            filename=f"benchmark-source-{index}.log",
            text=_repeat_complete_lines(auth, bytes_per_source),
        )
        for index in range(8)
    ]
    case = analyze_case_bundle(inputs, rules_root=RULES_ROOT, case_name="benchmark-bundle")
    total_bytes = sum(len(item.text.encode()) for item in inputs)
    total_lines = sum(len(item.text.splitlines()) for item in inputs)
    return _result_counts(case.result), total_bytes, total_lines


def _run_api_report() -> tuple[dict[str, int], int, int]:
    from fastapi.testclient import TestClient
    from tracehawk_api.main import app

    payload = (ROOT / "packages/sample-data/auth/ssh-bruteforce.log").read_bytes()
    client = TestClient(app)
    analysis_response = client.post(
        "/api/analyze/upload",
        files={"file": ("benchmark-auth.log", payload, "text/plain")},
    )
    analysis_response.raise_for_status()
    analysis = analysis_response.json()
    report_response = client.post(
        "/api/reports/incident?format=pdf",
        json={
            "incident": analysis["incidents"][0],
            "findings": analysis["findings"],
            "evidence": analysis["evidence"],
            "assistant_summary": "Benchmark summary.",
        },
    )
    report_response.raise_for_status()
    report = report_response.json()
    if report["format"] != "pdf" or not report["content"]:
        raise AssertionError("PDF report benchmark did not produce content.")
    return {
        "parsed_event_count": analysis["parsed_event_count"],
        "finding_count": analysis["finding_count"],
        "incident_count": analysis["incident_count"],
    }, len(payload), len(payload.splitlines())


def _run_live_retention(
    line_count: int,
    raw_capacity: int,
    event_capacity: int,
) -> tuple[dict[str, Any], int, int]:
    from tracehawk_api.services.live import LiveFileTailer

    line = "Jul 08 09:10:00 bench01 systemd[1]: started bounded benchmark service"
    tailer = LiveFileTailer(
        Path("benchmark-live.log"),
        RULES_ROOT,
        max_raw_lines=raw_capacity,
        max_events=event_capacity,
    )
    snapshot = None
    for line_number in range(1, line_count + 1):
        snapshot = tailer._process_line(line_number, line)
    if snapshot is None:
        raise AssertionError("Live-retention benchmark produced no snapshot.")
    if snapshot.live_retention.retained_raw_lines != raw_capacity:
        raise AssertionError("Live raw-line capacity was not enforced.")
    if snapshot.live_retention.retained_parsed_events != event_capacity:
        raise AssertionError("Live event capacity was not enforced.")

    result: dict[str, Any] = _result_counts(snapshot)
    result["live_retention"] = snapshot.live_retention.model_dump(mode="json")
    payload_bytes = len(line.encode()) * line_count
    return result, payload_bytes, line_count


def _repeat_complete_lines(unit: str, target_bytes: int) -> str:
    unit = unit.rstrip("\n") + "\n"
    repeats = max(1, math.ceil(target_bytes / len(unit.encode())))
    text = unit * repeats
    encoded = text.encode()
    if len(encoded) <= target_bytes:
        return text
    truncated = encoded[:target_bytes].decode("utf-8", errors="ignore")
    last_newline = truncated.rfind("\n")
    return truncated[: last_newline + 1]


def _result_counts(result: Any) -> dict[str, int]:
    return {
        "parsed_event_count": result.parsed_event_count,
        "finding_count": result.finding_count,
        "incident_count": result.incident_count,
    }


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def _git_commit() -> str:
    ci_commit = os.getenv("CI_COMMIT_SHA")
    if ci_commit:
        return ci_commit
    try:
        process = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return "unknown"
    return process.stdout.strip()


def _working_tree_dirty() -> bool:
    try:
        process = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False
    return bool(process.stdout.strip())


def _environment_metadata() -> dict[str, Any]:
    memory_kb = None
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        first_line = meminfo.read_text().splitlines()[0]
        memory_kb = int(first_line.split()[1])
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
        "logical_cpu_count": os.cpu_count(),
        "memory_total_mb": round(memory_kb / 1024, 2) if memory_kb else None,
    }


def render_markdown(report: dict[str, Any]) -> str:
    rows = [
        "# Current Performance Benchmark",
        "",
        f"Generated: `{report['generated_at']}`",
        f"Base commit: `{report['base_commit']}`",
        f"Working tree dirty during capture: `{str(report['working_tree_dirty']).lower()}`",
        f"Python: `{report['environment']['python']}`",
        f"Platform: `{report['environment']['platform']}`",
        "",
        "## Results",
        "",
        "| Scenario | Payload | Lines | Events | p50 | p95 | Peak RSS | Throughput | Budget |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for result in report["results"]:
        rows.append(
            f"| `{result['scenario']}` | {result['payload_bytes'] / 1_000_000:.2f} MB | "
            f"{result['line_count']} | {result['parsed_event_count']} | "
            f"{result['p50_seconds']:.4f}s | {result['p95_seconds']:.4f}s | "
            f"{result['max_rss_mb']:.2f} MB | {result['p50_lines_per_second']:.0f} lines/s | "
            f"{'PASS' if result['budget_passed'] else 'FAIL'} |"
        )
    rows.extend(
        [
            "",
            "## Method",
            "",
            "Each sample runs in a fresh process. Peak RSS therefore includes the Python runtime,",
            "dependencies, application import, generated events, findings, and reports. CI uses the",
            "smoke profile; the committed full proof uses three isolated repetitions per scenario.",
            "Budgets are regression ceilings for this portfolio workload, not universal production SLOs.",
            "",
        ]
    )
    return "\n".join(rows)


if __name__ == "__main__":
    raise SystemExit(main())
