# ADR 0002: Transparent additive correlation scoring

- Status: accepted
- Decision date: 2026-07-10
- Code: `apps/api/tracehawk_api/services/correlation.py`

## Context

A single severity label does not express why related findings form a stronger incident. Analysts
need to distinguish raw finding volume from ordered behavior, temporal proximity, independent
source agreement, and rule-family diversity. A hidden score would be difficult to test and would
turn ranking into an unexplained product claim.

## Decision

Group findings through shared normalized entities, then calculate an additive score with explicit
components: base severity, finding volume, sequence quality, time-window proximity, cross-source
corroboration, and rule-family diversity. Cap the final score at 100. Return both
`score_breakdown` and human-readable `score_rationale` with every incident.

## Rejected alternatives

- Severity-only ordering: loses corroboration and sequence information.
- Opaque weighted machine-learning score: lacks an appropriate training population and weakens
  auditability.
- Finding-count score: rewards noisy rules and duplicated evidence.
- Cross-source link count alone: unrelated links can inflate an incident.

## Consequences

Every ranking decision is visible in API responses, the UI, and reports. Adding a score component
requires a negative guardrail test as well as a positive test. The current weights are policy,
not statistical probability, and documentation must not describe them as breach likelihood.

## Verification

```bash
.venv/bin/python -m pytest apps/api/tests/test_correlation_scoring.py \
  apps/api/tests/test_case_bundle_api.py apps/api/tests/test_reports_api.py -q
```
