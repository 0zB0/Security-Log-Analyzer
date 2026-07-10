# TraceHawk Technical Walkthrough

This walkthrough demonstrates system understanding through a reproducible code change. It is not
an authorship claim. Run it on a temporary branch and discard the example change afterward.

## 1. Establish the verified baseline

```bash
make lock-check
make verify-all
```

Explain the execution path while the gate runs:

1. `analysis.analyze_text` creates stable raw-line evidence and selects parsers.
2. `parser_registry.default_parsers` supplies the supported deterministic parser set.
3. YAML rules create findings with evidence-line identifiers.
4. `correlation.correlate_incidents` groups findings and exposes score components.
5. the report package renders the same incident model as Markdown, HTML, or PDF.
6. the optional LLM layer only explains already-created deterministic evidence.

## 2. Inspect one complete rule contract

Use `packages/rules/auth/ssh-bruteforce.yml` and
`packages/test-scenarios/auth-ssh-compromise/expected.json`. Identify the log type, threshold or
sequence condition, MITRE mapping, evidence source, analyst guidance, and benign-control coverage.

```bash
.venv/bin/python -m pytest apps/api/tests/test_scenarios.py -q
```

## 3. Prove that the test can fail

Temporarily change the expected SSH brute-force rule identifier in the scenario contract to an
invalid value. Run the targeted test and capture the assertion that shows the missing and
unexpected rule identifiers.

```bash
.venv/bin/python -m pytest apps/api/tests/test_scenarios.py -q
```

Restore the expected identifier and rerun the same command. The value of this step is the visible
red/green transition, not a screenshot of an already-green pipeline.

## 4. Make a bounded rule change

Create a new sanitized positive scenario and a benign control before changing detection logic.
Then change one threshold or match condition in a single YAML rule. Do not edit generated proof
artifacts by hand.

```bash
.venv/bin/python -m pytest apps/api/tests/test_scenarios.py \
  apps/api/tests/test_detection_quality.py -q
.venv/bin/python tools/evaluate_detection_quality.py --check
```

Explain why the change does not broaden unrelated parser families and which false positive it may
introduce. If the answer is unknown, the rule is not ready.

## 5. Verify downstream evidence

```bash
.venv/bin/python -m pytest apps/api/tests/test_correlation_scoring.py \
  apps/api/tests/test_reports_api.py -q
npm --prefix apps/web run test:coverage
make smoke-ui
```

Show the rule identifier in the finding, the evidence-line hash, the incident score rationale, and
the rendered report. The assistant summary is not accepted as proof.

## 6. Close with the complete gate

```bash
make verify-all
make security-scan
docker build -t tracehawk:walkthrough .
```

Record the problem, behavioral change, failed test, passing test, and exact commands in the merge
request. Keep deployment and public publication as separate explicit decisions.
