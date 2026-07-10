# Zeek And Suricata Ingest

## Scope

This ingest layer accepts exported Zeek and Suricata text logs through the existing upload, live
file, folder watch, and Docker log paths. It does not run Zeek, Suricata, or PCAP processing inside
TraceHawk.

## Supported Inputs

Suricata:

- EVE JSON / JSON Lines records.
- Event types: `alert`, `dns`, `http`, `tls`, `flow`, `anomaly`, `fileinfo`, `ssh`.
- Parser name: `suricata_eve`.

Zeek:

- JSON Lines records for `conn`, `dns`, `http`, `ssl`, and `notice`.
- Default TSV logs with `#separator`, `#path`, and `#fields` metadata.
- Parser names: `zeek_json`, `zeek_tsv`.

## Normalized Fields

Suricata fields:

- `source_ip`
- `destination_ip`
- `source_port`
- `destination_port`
- `transport_protocol`
- `signature`
- `category`
- `dns_query`
- `http_hostname`
- `url_path`
- `tls_sni`

Zeek fields:

- `source_ip`
- `destination_ip`
- `source_port`
- `destination_port`
- `transport_protocol`
- `conn_state`
- `dns_query`
- `http_hostname`
- `url_path`
- `tls_sni`
- `notice_note`

## Detection Coverage

Suricata:

- alert burst;
- command-and-control alert category;
- DNS burst;
- high severity alert;
- sensitive HTTP path;
- scan signature.

Zeek:

- administrative service access;
- host sweep;
- port scan;
- DNS burst;
- sensitive HTTP path;
- notice event;
- suspicious TLS SNI.

## Reproducible Local Checks

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

Multi-source case bundle:

```bash
curl \
  -F "files=@docs/proof-pack/v0.4.1-real-lab/engine-output/zeek/conn.log" \
  -F "files=@docs/proof-pack/v0.4.1-real-lab/engine-output/zeek/dns.log" \
  -F "files=@docs/proof-pack/v0.4.1-real-lab/engine-output/zeek/http.log" \
  -F "files=@docs/proof-pack/v0.4.1-real-lab/engine-output/suricata/eve.json" \
  http://localhost:8000/api/analyze/case-bundle
```

Reproducible committed real-lab case:

```bash
curl http://localhost:8000/api/analyze/case-sample/real-lab
```

Expected parser values:

- `suricata_eve`
- `zeek_tsv`
- `zeek_json`
- `case_bundle`

Case bundle responses include source summaries and cross-source links. Cross-source links are built
from matching Zeek and Suricata flow metadata, DNS queries, HTTP paths, and timestamps. Each link
keeps both event IDs and both raw line IDs so the UI and case report can show the exact Suricata
and Zeek evidence lines.

Case workflow documentation:

- `docs/case-investigation-workflow.md`

Expected scenario checks:

```bash
.venv/bin/pytest apps/api/tests/test_suricata_eve_parser.py apps/api/tests/test_zeek_parser.py apps/api/tests/test_case_bundle_api.py apps/api/tests/test_scenarios.py
```

## Parser Precedence Requirement

Suricata EVE and Zeek JSON must be tested before the generic JSON parser. If a Suricata or Zeek
fixture returns `json_log`, parser precedence is broken.

## UI Sample Selector

The investigation intake includes allowlisted sample scenarios for reproducible demos:

- `Suricata alert burst`
- `Suricata C2 DNS`
- `Zeek port scan`
- `Zeek DNS HTTP notice`

## Sources

- Zeek documentation describes the default TSV log structure and `#fields` metadata:
  https://docs.zeek.org/en/master/tutorial/logs.html
- Suricata documentation describes EVE JSON as the JSON firehose for alerts and protocol records:
  https://docs.suricata.io/en/latest/output/eve/eve-json-output.html
- Suricata EVE JSON format documents protocol-specific fields including HTTP and DNS:
  https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
