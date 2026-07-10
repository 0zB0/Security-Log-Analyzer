# Case Investigation Workflow

## Purpose

Case investigation combines multiple exported security logs into one local analysis. The first
supported case path is Zeek plus Suricata:

- Zeek `conn.log`
- Zeek `dns.log`
- Zeek `http.log`
- Suricata `eve.json`

## Workflow

1. Export logs from a controlled lab or approved customer environment.
2. Import them together through `POST /api/analyze/case-bundle` or the UI Case import.
3. Review source summaries to confirm parser, line count, event count, finding count, and SHA-256.
4. Review cross-source links.
5. Click a link to inspect both engine events and both raw evidence lines.
6. Export a case report with source hashes, correlation method, findings, incidents, and evidence by
   source.

## Correlation Methods

- `http_path_match`: Suricata and Zeek observed the same HTTP path within five minutes.
- `dns_query_match`: Suricata and Zeek observed the same DNS query within five minutes.
- `flow_match`: Suricata and Zeek shared source IP, destination IP, destination port, and timestamp
  window.

Each cross-source link preserves:

- Suricata event ID;
- Zeek event ID;
- Suricata raw line ID;
- Zeek raw line ID;
- source file labels;
- match value;
- confidence.

## Evidence Rules

- Evidence lines are preserved with SHA-256 hashes.
- Case evidence includes both finding evidence and cross-source link evidence.
- Case reports group evidence by source file.
- Redacted case reports mask IPs, users, and hosts while preserving hashes.

## Local Reproduction

```bash
make real-lab-proof
.venv/bin/python -m pytest apps/api/tests/test_case_bundle_api.py -q
```

The committed real-lab sample endpoint is:

```text
GET /api/analyze/case-sample/real-lab
```

Expected current local real-lab result:

- parser: `case_bundle`
- sources: `4`
- events: `67`
- findings: `13`
- incidents: `2`
- cross-source links: `71`
