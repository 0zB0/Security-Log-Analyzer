# Current Correlation Quality Proof

Date: 2026-07-12

## Scope

This proof covers the deterministic incident layer after the declarative-correlation migration. It
checks pattern-driven scoring, bounded grouping, evidence-linked corroboration, and real-lab rank
ordering. It does not claim that correlation establishes attacker identity or causality.

## Real-Lab Case

- API: `GET /api/analyze/case-sample/real-lab`
- Parser: `case_bundle`
- Sources: `conn.log`, `dns.log`, `http.log`, `eve.json`
- Findings in strongest incident: `12`
- Cross-source links in case: `71`
- Incidents: `2`

### Incident 1: Reconnaissance followed by sensitive HTTP access

Score: `100`

```json
{
  "base_severity": 95,
  "finding_volume": 20,
  "sequence_quality": 25,
  "time_window_proximity": 10,
  "cross_source_corroboration": 18,
  "rule_family_diversity": 10
}
```

Matched declarative patterns:

- `scan-to-sensitive-http`;
- `dns-burst-to-c2-alert`;
- `alert-burst-to-high-severity`.

The related finding evidence falls within five minutes. Twenty evidence-linked DNS or HTTP pairs
contribute the capped cross-source score. Six declared families contribute the capped diversity
score.

### Incident 2: Zeek port scan pattern

Score: `93`

```json
{
  "base_severity": 75,
  "finding_volume": 0,
  "sequence_quality": 0,
  "time_window_proximity": 0,
  "cross_source_corroboration": 18,
  "rule_family_diversity": 0
}
```

The singleton remains below the multi-step incident. Its related flow evidence can contribute
cross-source corroboration, but no absent follow-up behavior is invented.

## Declarative And Grouping Guardrails

Automated contracts prove that:

- pattern IDs are unique and every referenced behavior exists in the rule library;
- malformed pattern documents fail closed;
- renamed rule IDs retain pattern behavior without a Python change;
- DNS activity without a C2/high-alert follow-up receives no sequence points;
- scan activity without sensitive HTTP follow-up receives no sequence points;
- unrelated cross-source links do not increase a score;
- findings beyond the configured maximum gap form separate incidents;
- A-user-B-IP-C produces two groups because no entity is common to all three findings.

The implementation contains no concrete rule-ID or name-fragment behavior branches. Pattern IDs
are included in `score_rationale`, so the explanation is traceable to
`packages/correlation/patterns.yml`.

## Case Quality Summary

The current real-lab response reports:

- strongest title: `Reconnaissance followed by sensitive HTTP access`;
- strongest score: `100`;
- sequence-backed incidents: `1`;
- cross-source-corroborated incidents: `2`;
- total cross-source links: `71`;
- top reason: `Sequence quality: pattern scan-to-sensitive-http: Scan activity is followed by
  sensitive HTTP access.`

## Analyst Surfaces

- Incident detail renders score components and rationale.
- Case overview renders the case-quality summary.
- Markdown, HTML, and PDF reports retain scoring rationale.
- The rule-library API and UI expose family, behavior tags, entity fields, and maximum gap.

## Reproduction

```bash
.venv/bin/python -m pytest \
  apps/api/tests/test_correlation_patterns.py \
  apps/api/tests/test_correlation_scoring.py \
  apps/api/tests/test_case_bundle_api.py \
  apps/api/tests/test_linux_auth_pipeline.py \
  apps/api/tests/test_rule_library_api.py \
  apps/api/tests/test_scenarios.py -q
.venv/bin/python -m ruff check apps/api/tracehawk_api apps/api/tests
npm --prefix apps/web test -- --run src/features/workspace/KnowledgePanels.test.tsx
npm --prefix apps/web run build
```

The result is reproducible proof of the checked fixtures and code revision, not a production-wide
precision or recall claim.
