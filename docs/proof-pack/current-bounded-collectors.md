# Bounded Live And Syslog Collector Proof

Date: 2026-07-12

## Scope

This proof covers two local ingestion boundaries:

1. rolling retention for file, folder, Docker, and interface live sources;
2. the opt-in loopback-default TCP/UDP syslog collector.

It does not claim durable message delivery, distributed ingestion, or an Azure collector.

## Live Retention Invariants

- Rules and correlation patterns load once when a live source is created.
- Retained raw lines never exceed `TRACEHAWK_LIVE_MAX_RAW_LINES`.
- Retained parsed events never exceed `TRACEHAWK_LIVE_MAX_EVENTS`.
- Evicting raw evidence also removes any retained event that references it.
- Findings and incidents are rebuilt from the retained event graph only.
- `LiveRetentionSummary` reports capacities, totals, retained counts, and dropped counts.
- The summary is included in the process-local HMAC and persisted inside evidence-integrity
  provenance when a snapshot is saved.

The focused benchmark processes 2,000 incremental syslog lines with capacities of 200 raw lines and
150 events. The calibrated run on the reference workstation reported:

```json
{
  "elapsed_seconds": 0.562594,
  "max_rss_mb": 173.03,
  "retained_raw_lines": 200,
  "retained_parsed_events": 150,
  "dropped_raw_lines": 1800,
  "dropped_parsed_events": 1850
}
```

The CI ceilings are 10 seconds and 256 MB peak RSS. They are regression budgets for this workload,
not a production SLA.

## Collector Boundaries

| Boundary | Executable evidence |
| --- | --- |
| Loopback default | non-loopback config fails without explicit override |
| UDP and TCP success | real loopback sockets create isolated persisted analyses |
| Evidence integrity | restored analyses report `verified` and origin `syslog` |
| Line cap | oversized input increments `dropped_oversize` |
| Encoding and shape | invalid UTF-8, empty, and NUL input increment `dropped_malformed` |
| Queue cap | non-blocking overflow increments `dropped_queue_full` |
| TCP connection cap | excess connection is closed and counted |
| Idle timeout | inactive TCP client is closed and counted |
| Failed analysis | failed batch is counted; a later valid batch persists |
| Shutdown | queued input is drained before worker exit |
| Deployment | collector has an opt-in profile and host-loopback TCP/UDP publications |

Collector processing uses `analyze_text`, `persist_analysis`, the shared rule/pattern assets, and the
same pre-commit hash and graph verifier as uploads. Rules and patterns are cached once per collector
process rather than reloaded for every line or batch.

## Public-Cloud Boundary

The default Compose profiles expose only HTTP ports. Port `5514` exists only under the
`collectors` profile and is published as `127.0.0.1:5514`. Azure deploy tooling configures only the
HTTP application on target port `8000`; no collector process or TCP/UDP ingress is deployed.

## Reproduction

```bash
.venv/bin/python -m pytest \
  apps/api/tests/test_live_file.py \
  apps/api/tests/test_live_interface.py \
  apps/api/tests/test_syslog_collector.py \
  apps/api/tests/test_analyze_api.py -q
.venv/bin/python tools/benchmark_analysis.py --worker live-retention-2k-lines
make compose-check
```

The socket tests use loopback and the test suite's isolated temporary SQLite database. No external
host, production log, or public listener is required.
