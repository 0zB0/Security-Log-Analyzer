# ADR 0001: Confidence-ranked parser routing

- Status: accepted
- Decision date: 2026-07-10
- Code: `apps/api/tracehawk_api/services/analysis.py`,
  `apps/api/tracehawk_api/services/parser_registry.py`

## Context

TraceHawk accepts heterogeneous logs. Several formats overlap: a CloudTrail, Kubernetes, Windows,
Zeek, or Suricata record is also valid JSON; an auth line can resemble generic syslog. Selecting
the first parser that returns true would make registry order an undocumented detection decision.
Selecting one parser from only the first line would also fail mixed files and files with headers.

## Decision

Route through a deterministic parser registry with explicit specificity scores. Sample non-empty
lines across the complete input, select the most specific parser per sampled line, suppress weak
generic fallback hits, and label significant multi-parser inputs as `mixed`. Stateful formats such
as CSV and Zeek TSV retain their dedicated parse path. Unsupported content fails explicitly rather
than being coerced into findings.

## Rejected alternatives

- File extension only: extensions are weak and frequently wrong for exported security data.
- First matching parser: makes registry order override semantic specificity.
- LLM format classification: not deterministic, not auditable, and unnecessary for known formats.
- Parse every line with every parser: increases duplicate events and cost.

## Consequences

Parser selection is explainable and reproducible. New specific parsers must receive a specificity
entry and overlap tests against generic JSON/syslog fallbacks. The registry remains a controlled
ordering surface rather than a plugin free-for-all.

## Verification

```bash
.venv/bin/python -m pytest apps/api/tests/test_parser_selection.py \
  apps/api/tests/test_json_log_pipeline.py apps/api/tests/test_scenarios.py -q
```
