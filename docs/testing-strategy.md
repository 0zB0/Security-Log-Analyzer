# Testing Strategy

## Parser Tests

Parser tests verify timestamp parsing, field extraction, invalid-line handling, and event type classification.
Current covered parsers are Linux auth, web access, JSON Lines security events, Suricata EVE,
Zeek JSON, and Zeek TSV. CSV and generic syslog coverage is handled through end-to-end scenario
contracts because CSV parsing depends on header state and syslog value comes from fallback parser
selection.

## Rule Tests

Every rule should have sample input and expected findings.
The generated detection-quality report enforces positive contract coverage for every rule and zero
unexpected findings across committed benign controls. This is contract coverage, not a claim of
production prevalence or universal false-positive rate.
Network behavior rules are covered with synthetic packet metadata generated in
the same `tshark -T fields` shape used by the live interface monitor. This keeps
tests deterministic while still exercising normalization, cardinality, periodic
timing, findings, MITRE mappings, and evidence IDs.
Zeek and Suricata rules are covered with realistic text fixtures instead of requiring the tools to
run locally. This keeps CI deterministic while testing the same upload parser and rule path used by
real exported logs.

## Correlation Tests

Correlation tests verify that related findings are grouped into incidents by source IP, username, host, time window, and sequence.

## LLM Tests

LLM unit tests should use a mock provider. Optional integration tests can run when Ollama is available.

## End-to-End Demo Test

The final demo test should import sample logs, create parsed events, trigger findings, correlate incidents, and generate a report.

Current smoke coverage includes upload analysis, live file tail, live folder watch, assistant mock
responses, model selector wiring, redaction control wiring, and Markdown/HTML/PDF report generation.

## External Dataset Evaluation

IoT-23 evaluation scores selected Zeek scan rules in fixed two-minute windows against the
`PartOfAHorizontalPortScan` label and a separate benign-device capture. Dataset hashes, method,
limitations, false positives, and false negatives are committed in the proof pack; raw external
captures and malware binaries are not committed.
