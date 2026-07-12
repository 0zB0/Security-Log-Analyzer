# Declarative Correlation Migration Proof

Date: 2026-07-12

## Claim

TraceHawk correlation behavior is configured through validated rule metadata and a versioned
pattern library. Incident grouping requires one stable entity common to every finding in a bounded
time span.

## Implementation Evidence

| Invariant | Source |
| --- | --- |
| Rule behavior, family, entity, and gap metadata | `apps/api/tracehawk_api/models/domain.py` |
| Versioned pattern schema and cross-library validation | `apps/api/tracehawk_api/services/correlation_patterns.py` |
| Pattern declarations | `packages/correlation/patterns.yml` |
| Common-entity intersection and time-span bound | `apps/api/tracehawk_api/services/correlation.py` |
| Startup/readiness failure on invalid assets | `apps/api/tracehawk_api/observability.py` |
| Analyst-visible rule metadata | `GET /api/rules/library` and Detection Library UI |

## Negative Evidence

`test_transitive_entity_bridge_does_not_merge_unrelated_endpoints` uses this graph:

```text
A: user:alice
B: user:alice + ip:10.20.0.25
C: ip:10.20.0.25
```

The result contains one two-finding incident and one singleton, never one three-finding incident.
The test protects against connected-component bridge expansion.

`test_far_apart_findings_get_no_time_window_or_ordered_sequence_score` proves that two findings 120
minutes apart become separate incidents under the participating rules' declared bounds.

Pattern-library tests reject duplicate IDs and undeclared behavior tags. Scoring tests reject
missing follow-up stages and unrelated corroboration links.

## Extensibility Evidence

`test_pattern_matching_survives_rule_id_renames` replaces the SSH rule IDs with
`renamed-auth-pressure` and `renamed-auth-success`. The unchanged
`ssh-failures-to-success` pattern still matches through behavior tags and produces the declared
title and score. No correlation Python branch changes.

## Boundary

These controls reduce accidental grouping and hidden naming conventions. They do not establish
that two observations have the same human operator, that the sequence was malicious, or that the
source telemetry is authentic.
