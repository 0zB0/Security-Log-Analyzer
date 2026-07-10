# ADR 0003: LLM explanation is outside the detection authority boundary

- Status: accepted
- Decision date: 2026-07-10
- Code: `apps/api/tracehawk_api/services/llm.py`, `docs/threat-model.md`

## Context

Security logs are untrusted input and can contain prompt-injection text. Generated explanations
can also invent evidence or cite lines that were never supplied. Letting a model create or mutate
findings would remove deterministic provenance from the core product.

## Decision

Parsing, rules, findings, evidence, incidents, and scoring remain deterministic and authoritative.
The optional assistant receives bounded structured incident context and a capped evidence subset.
Only a configured local Ollama endpoint is supported. Model output must validate against a strict
schema; evidence references are filtered against the supplied line numbers. Invalid or unavailable
output falls back to a deterministic local explanation. Assistant output cannot create, delete, or
change findings.

## Rejected alternatives

- Send raw uploads to a cloud model: violates the local-first privacy boundary.
- Let the model perform detection: findings become non-reproducible and prompt-injectable.
- Accept arbitrary model evidence references: permits unsupported claims.
- Fail the investigation when Ollama fails: explanation availability must not affect evidence.

## Consequences

The assistant is useful for explanation, not an analyst-of-record. New providers must preserve the
local-only boundary, schema validation, evidence-reference filtering, and deterministic fallback.
Product copy must not imply that LLM output is a detection.

## Verification

```bash
.venv/bin/python -m pytest apps/api/tests/test_assistant_api.py -q
make smoke-ollama
```
