# TraceHawk API Reference

## Authentication And Roles

Local development defaults to `TRACEHAWK_AUTH_MODE=disabled`, binds to loopback, and runs as a local
admin. Optional trusted-proxy mode adds application RBAC. Viewer covers read-only investigation,
analyst covers analysis/report/note operations, and admin covers host live sources, settings,
retention deletion, and audit access. See `docs/auth-rbac.md` for the exact matrix.

Every protected HTTP response includes `X-Request-ID`. Clients may supply that header to correlate
an operation with its audit event.

## Generated Browser Contract

FastAPI Pydantic component schemas are exported to committed OpenAPI and TypeScript artifacts.
`make api-contract-check` fails when backend models and browser declarations drift. The generation
workflow, frontend consumption rules, and runtime boundary are documented in the
[generated API contract guide](api-contract.md).

## Health

```text
GET /api/health
```

Returns local API status.

```text
GET /api/health/live
GET /api/health/ready
```

Liveness proves the process is serving. Readiness executes a SQLite query and validates the full
YAML rule library plus the correlation-pattern library; it returns `503` when a dependency fails.
In `public_demo`, readiness reports the database as `disabled` and validates only the rule and
correlation libraries because that runtime never initializes SQLite.

## Session-Only Public Demo

These endpoints exist only when `TRACEHAWK_DEPLOYMENT_PROFILE=public_demo`. They are anonymous,
stateless, non-cacheable, and deliberately separate from the persistent private API.

```text
GET /api/public-demo/status
POST /api/public-demo/analyze
POST /api/public-demo/analyze/sample/{sample_id}
POST /api/public-demo/report/incident
POST /api/public-demo/report/case
```

`POST /api/public-demo/analyze` accepts JSON with `filename` and `text`. It allows one bounded UTF-8
`.log`, `.txt`, `.csv`, `.json`, or `.jsonl` payload and returns the deterministic analysis inside
an envelope with `ephemeral=true`, `stored=false`, `external_ai=false`, and lifecycle metadata.
The response has no public `analysis_id`. Public reports are Markdown returned in the response and
are not written to disk or SQLite. See [Session-only public demo](public-demo.md) for limits and the
complete capability boundary.

## Metrics

```text
GET /metrics
Required role: admin
```

Returns Prometheus text-format request counts, route-template latency histograms, in-flight gauge,
process start time, and build metadata. Query strings, bodies, filenames, and evidence are excluded.

## Database Backup

```text
POST /api/operations/backup
Required role: admin
```

Downloads a consistent SQLite backup. Verify the `X-TraceHawk-SHA256` response header before
storing it outside the application volume. Restore remains an offline CLI operation.

## Audit Events

```text
GET /api/audit/events?limit=100
Required role: admin
```

Returns newest-first authorization and action records. Payload bodies and evidence are excluded.

## Analyze Uploaded Log

```text
POST /api/analyze/upload
Content-Type: multipart/form-data
field: file
```

The endpoint:

1. accepts a UTF-8 log file;
2. confidence-ranks specific parsers over generic fallbacks across a stratified file sample;
3. parses raw log lines into normalized events;
4. loads local YAML rules from `packages/rules`;
5. runs deterministic detection;
6. correlates findings into incidents;
7. persists the analysis to local SQLite;
8. returns an `analysis_id`, events, findings, incidents, MITRE mapping, and evidence lines.

If the representative sample contains more than one supported format, the response parser is
`mixed`. Each parsed event then carries `_tracehawk_parser` in `normalized_fields`, and detection
rules run only against events produced by a compatible parser. Stateful CSV and Zeek TSV sections
retain their header context until another recognizable format begins.

Example:

```bash
curl -F "file=@packages/sample-data/auth/ssh-bruteforce.log" \
  http://localhost:8000/api/analyze/upload
```

Current parser coverage:

- Linux auth / SSH / sudo logs.
- Nginx/Apache combined web access logs.
- JSON Lines security events with common fields such as `@timestamp`, `event.action`,
  `source.ip`, `user.name`, `host.name`, `service.name`, and arbitrary nested fields exposed as
  dotted `normalized_fields`.
- Headered CSV security event exports with common fields such as `timestamp`, `action`,
  `source_ip`, `username`, `host`, `service`, and `message`.
- Generic syslog service messages that are not SSH/sudo-specific.
- Suricata EVE JSON / JSON Lines records with `event_type`, `src_ip`, `dest_ip`, alert, DNS,
  HTTP, TLS, and flow metadata.
- Zeek JSON Lines records for `conn`, `dns`, `http`, `ssl`, and `notice` logs.
- Zeek default TSV logs with `#separator`, `#path`, and `#fields` metadata.

Current detection coverage:

- threshold rules;
- distinct-count rules for cardinality patterns;
- periodic timing rules for regular interval patterns;
- ordered sequence rules with two to eight typed steps;
- path contains rules for sensitive web file probing;
- exact field matching with `field_equals`;
- exact list membership matching with `field_in`;
- normalized field substring matching with `field_contains_any`.

## Built-In Sample Analysis

```text
GET /api/analyze/sample/{sample_id}
```

Runs one allowlisted local sample through the same analysis and persistence path as uploads. This
is for reproducible demos and screenshots, not arbitrary file reads.

Current sample IDs:

- `auth-ssh-compromise`
- `suricata-alert-burst`
- `suricata-c2-http-dns`
- `zeek-port-scan`
- `zeek-dns-http-notice`

Example:

```bash
curl http://localhost:8000/api/analyze/sample/zeek-port-scan
```

## Recent Analysis Runs

```text
GET /api/analyze/runs
```

Returns the latest locally persisted analysis runs with parser, raw line count, parsed event
count, finding count, incident count, and creation time.

## Analysis Run Detail

```text
GET /api/analyze/runs/{analysis_id}
```

Returns a persisted analysis result, including parsed events, findings, incidents, and raw
evidence lines for the run.

## Recent Incidents

```text
GET /api/analyze/incidents
```

Returns recent locally persisted incidents ordered by score and last seen time.
Pass `analysis_id` to scope the result to one persisted analysis run.

## Live File Tail

All `/api/live/*` WebSocket endpoints require the `admin` role. This is intentionally stricter than
ordinary analysis because the connection selects filesystem, Docker, or network-interface resources
on the API host. Local `disabled` auth mode runs as the trusted local admin.

```text
WS /api/live/file?path=/absolute/or/relative/file.log&start_at_end=true
```

Streams analysis snapshots for a local file. Query parameters:

- `path`: local log file path readable by the API process.
- `start_at_end`: when `true`, only new appended lines are processed; when `false`, the stream
  starts from the beginning of the existing file.

Each message is a `snapshot` containing:

- source ID and parser;
- live source status: `active` or `paused`;
- retained raw line, parsed event, finding, and incident counts;
- configured capacities plus total, retained, and dropped raw/event counters in `live_retention`;
- latest parsed event;
- current findings and incidents;
- evidence lines retained in the current rolling window.

`TRACEHAWK_LIVE_MAX_RAW_LINES` and `TRACEHAWK_LIVE_MAX_EVENTS` default to `5000`. Findings and
incidents are rebuilt only from retained events whose raw references remain in the window. The
retention summary is covered by the live HMAC and persisted inside evidence-integrity provenance
when a snapshot is saved.

The client can send control messages over the same socket:

```json
{"action": "pause"}
{"action": "resume"}
{"action": "ping"}
```

## Live Folder Watch

```text
WS /api/live/folder?path=/absolute/or/relative/folder&pattern=*.log&start_at_end=true
```

Streams snapshots for all matching files in a local folder. Query parameters:

- `path`: local folder readable by the API process.
- `pattern`: glob pattern for files in the folder, default `*.log`.
- `start_at_end`: when `true`, only new appended lines are processed; when `false`, existing file
  content is processed first.

The socket uses the same snapshot format and `pause` / `resume` / `ping` control messages as
`/api/live/file`.

## Live Docker Logs

```text
WS /api/live/docker?container=my-container&tail=0
```

Streams `docker logs --follow` output through the same parser, rule, and correlation pipeline.
Query parameters:

- `container`: Docker container name or ID visible to the API process.
- `tail`: number of existing log lines to include before following, default `0`.

This endpoint requires Docker CLI access from the API runtime. In local development that usually
means running the API on the host or mounting Docker access intentionally.

## Live Interface Capture

```text
WS /api/live/interface?interface=wg0&capture_filter=ip%20or%20ip6
```

Streams packet metadata from a local network interface through `tshark`. For WireGuard tunnel
monitoring, capturing on `wg0` observes decrypted inner tunnel traffic as packet metadata, while
capturing on the physical interface generally observes encrypted WireGuard UDP transport.

Query parameters:

- `interface`: local interface name, for example `lo`, `wg0`, or `CloudflareWARP`, readable by
  `tshark`.
- `capture_filter`: optional BPF capture filter, default `ip or ip6`.

Runtime requirements:

- `tshark` installed on the API host.
- Permission to capture on the interface, usually root or packet-capture capabilities.
- Written authorization for the monitored environment.

Snapshot messages use the same shape as file/folder/docker live sources. `parser` is
`network_packet`. The snapshot includes accumulated events, findings, incidents, and evidence.
Evidence lines are metadata summaries with content hashes. Payload content is not shown by default.

Current interface metadata rules include:

- SSH/admin service access.
- RDP service access.
- DNS burst.
- Packet-rate burst.
- Port scan pattern.
- Host sweep pattern.
- Periodic beacon pattern.

## Zeek And Suricata Upload Examples

```bash
curl -F "file=@packages/sample-data/suricata/eve-alerts.jsonl" \
  http://localhost:8000/api/analyze/upload

curl -F "file=@packages/sample-data/suricata/eve-c2-dns.jsonl" \
  http://localhost:8000/api/analyze/upload

curl -F "file=@packages/sample-data/zeek/conn-port-scan.log" \
  http://localhost:8000/api/analyze/upload

curl -F "file=@packages/sample-data/zeek/zeek-mixed.jsonl" \
  http://localhost:8000/api/analyze/upload
```

The parser response will show `suricata_eve`, `zeek_tsv`, or `zeek_json`. If these inputs return
`json_log`, parser precedence is broken and must be fixed before treating the ingest as valid.

## Persist Live Snapshot

```text
POST /api/analyze/live-snapshot
Content-Type: application/json
```

Accepts the current live snapshot converted to an `AnalysisResult` shape and persists it as a
normal local analysis run. The payload must retain the `live_snapshot_attestation` emitted by the
WebSocket. Missing, expired-process, or modified snapshots return `422` before any write. This is
intended for live interface or file-tail findings that need to be kept for later incident review
and report export.

The endpoint namespaces raw line, event, finding, and incident IDs under the generated
`analysis_id`, so repeated saves from the same live source do not overwrite earlier evidence rows.
The persistence boundary also recomputes SHA-256 values and validates counters and graph references.

## Assistant Status

```text
GET /api/assistant/status
```

Returns the active local assistant provider, configured model, Ollama availability, installed
model names, and any local connection or model-selection error. The first release supports
`ollama`, `mock`, and `disabled` provider modes.

## Assistant Incident Explanation

```text
POST /api/assistant/explain
Content-Type: application/json
```

Accepts an incident, linked findings, bounded evidence lines, and an optional analyst question.
The request may include `model` to override the configured local Ollama model for that explanation.
Returns a local explanation with summary, key points, next steps, validated evidence references,
guardrails, and the prompt preview. Ollama output is schema-validated. If Ollama is unavailable or
returns unusable JSON, the endpoint falls back to the deterministic local mock provider.

## Incident Report

```text
POST /api/reports/incident?format=markdown
POST /api/reports/incident?format=html
POST /api/reports/incident?format=pdf
Content-Type: application/json
```

Accepts an incident, linked findings, evidence lines, an optional assistant summary, and optional
`redaction` settings. Returns a report filename, creation time, and report content. Supported
formats are Markdown, HTML, and PDF.
Markdown and HTML content is returned as text. PDF content is returned as base64. The report includes
incident metadata, entities, MITRE techniques, findings, timeline, evidence blocks with hashes, and
integrity notes.

Redaction example:

```json
{
  "redaction": {
    "enabled": true,
    "mask_ips": true,
    "mask_users": true,
    "mask_hosts": true
  }
}
```
