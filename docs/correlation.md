# Incident Correlation

TraceHawk converts deterministic findings into bounded, explainable incidents. Correlation is
declarative: Python does not recognize product behavior from concrete rule IDs, titles, or filename
fragments.

## Correlation Inputs

Every detection rule may declare a `correlation` block:

```yaml
correlation:
  family: credential_access
  behaviors:
    - ssh_failures
  entity_fields:
    - source_ip
    - username
  max_gap_minutes: 15
```

- `family` contributes to rule-family diversity. When omitted, the MITRE tactic is the fallback.
- `incident_title` optionally supplies a shared analyst-facing title for an unmatched multi-finding
  group.
- `behaviors` are stable semantic tags consumed by correlation patterns.
- `entity_fields` selects allowed stable keys from `source_ip`, `destination_ip`, `username`, and
  `host`.
- `max_gap_minutes` limits the total temporal span of a group containing that rule.
- `intrinsic_sequence_score`, rationale, and summary may describe a sequence already proven inside
  one detection rule.

The rule library rejects duplicate or malformed behaviors, duplicate entity fields, invalid
maximum gaps, and unexplained intrinsic scores during startup/readiness validation.

## Declarative Multi-Rule Patterns

Ordered patterns live in `packages/correlation/patterns.yml`. The document has an explicit schema
version. Each pattern declares two to four stages, accepted behavior tags per stage, maximum gap,
score, title, rationale, and summary:

```yaml
schema_version: 1
patterns:
  - id: ssh-failures-to-success
    title: Possible SSH credential compromise
    stages:
      - any_behaviors: [ssh_failures]
      - any_behaviors: [ssh_success]
    max_gap_minutes: 15
    score: 15
    rationale: SSH failures are followed by a successful login.
    summary: SSH failures were followed by a successful login.
```

Pattern loading fails on duplicate IDs, empty or malformed stages, out-of-range values, extra
fields, or behavior tags not declared by any rule. A tagged rule can replace or extend an existing
rule without changing `correlation.py`.

Current patterns cover:

- SSH failures followed by successful login;
- successful SSH login followed by privileged activity;
- network scan followed by sensitive HTTP access;
- DNS burst followed by C2 or high-severity alert evidence;
- Suricata alert burst containing high-severity evidence.

## Bounded Grouping Invariant

For each finding, TraceHawk derives the configured entities from its evidence events. Source IP,
destination IP, and username are preferred; host is used only when no enabled stronger entity is
available.

A finding can join a group only when both conditions hold:

1. it shares at least one entity with the entity intersection common to every existing group
   member;
2. the resulting first-to-last span is no longer than the strictest member's `max_gap_minutes`.

After a join, the common entity set is intersected again. This blocks transitive expansion:

```text
finding A: user:alice
finding B: user:alice + ip:10.20.0.25
finding C: ip:10.20.0.25

A + B may group through user:alice.
C cannot join because no entity is common to A, B, and C.
```

Groups and incidents are sorted deterministically. Findings outside the configured temporal span
become separate incidents even when an entity repeats later.

## Incident Fields

Each incident exposes:

- analyst-facing title and summary;
- maximum severity and deterministic score;
- `score_breakdown` and `score_rationale`;
- linked finding IDs and display entities;
- MITRE techniques;
- evidence-derived timeline.

Matched pattern IDs appear in rationale such as
`Sequence quality: pattern scan-to-sensitive-http: ...`. A matched pattern supplies the preferred
incident title. A single finding keeps its rule title. An unmatched multi-finding group uses the
highest-priority declared `incident_title`, then falls back to the highest-severity finding title
plus `and related activity`.

## Scoring

The additive score is capped at 100 and exposes these components:

- base severity;
- finding volume;
- sequence quality from declared intrinsic sequences and matched patterns;
- time-window proximity;
- evidence-linked cross-source corroboration;
- declared family diversity, with MITRE tactic fallback.

Cross-source points are awarded only when a link references evidence belonging to a finding in the
incident. A link elsewhere in the case cannot raise the score.

## Case Quality Summary

Case bundle analysis exposes the strongest incident, strongest score, count of sequence-backed
incidents, count of cross-source-corroborated incidents, total cross-source links, and the top
scoring reason. This summary is derived from the same visible breakdown rather than a second hidden
ranking system.

## Verification

```bash
.venv/bin/python -m pytest \
  apps/api/tests/test_correlation_patterns.py \
  apps/api/tests/test_correlation_scoring.py \
  apps/api/tests/test_case_bundle_api.py \
  apps/api/tests/test_linux_auth_pipeline.py \
  apps/api/tests/test_scenarios.py -q
```

The negative contracts cover unknown behaviors, duplicate pattern IDs, missing stages, unrelated
links, missing follow-up behavior, findings outside the grouping window, and the
A-user-B-IP-C bridge case.
