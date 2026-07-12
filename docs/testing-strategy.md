# Testing And Evaluation Strategy

> Audience: engineers, security reviewers, and academic evaluators
> Canonical for: verification layers and the claims each layer can support
> Verified against: TraceHawk v0.7.1

TraceHawk uses multiple verification layers because no single test type proves parser correctness,
detection quality, UI behavior, operational safety, and production readiness at once.

## Verification Model

```text
Static and unit checks
├── Python lint and type-aware model validation
├── parser and detection primitives
└── pure frontend selectors and selected components

Deterministic contracts
├── positive rule scenarios
├── benign negative controls
└── rule schema and semantic checks

Integration tests
├── API and persistence
├── reports and redaction
├── auth, RBAC, audit, and WebSockets
└── case correlation and entities

System smoke tests
├── Docker/local API
├── live sources
├── optional Ollama boundary
├── report rendering
└── browser UI

External and operational evidence
├── IoT-23 error analysis
├── performance/resource budgets
├── real Zeek/Suricata export proof
└── exact-commit deployment verification
```

## Static Checks

Ruff covers maintained Python code and tests. TypeScript compilation and Vite production build check
the frontend contract and bundle. CI additionally runs dependency audits, Semgrep, Gitleaks, and
CycloneDX SBOM generation.

Static checks can detect classes of mistakes and policy violations. They do not prove runtime
behavior or absence of vulnerabilities.

## Unit Tests

### Parsers

Parser tests verify recognition, timestamp parsing, common-field extraction, normalized fields,
invalid-line handling, provenance, and event classification. Format-specific tests cover Linux
auth, web, JSON, Windows, Suricata, Zeek, and other registered source paths; scenario contracts add
stateful CSV and generic fallback coverage.

### Detection primitives

Tests exercise threshold windows, distinct counts, periodic timing, field matching, grouping, and
two-to-eight-step sequences. They verify deterministic semantics independently from the UI.

### Correlation

Correlation tests verify grouping, additive score components, rationale, guardrails, time
proximity, sequences, source corroboration, and rule-family diversity.

### Frontend

Vitest and React Testing Library cover pure workspace selectors and selected rendered states.
Accessibility assertions use axe where configured.

The current coverage report is dominated by files imported by the existing tests, especially
`workspaceSelectors.ts`. It is not whole-application coverage and must not be presented as such.

## Detection Contracts

Each YAML rule must have a positive labeled scenario. The detection-quality evaluator also runs
committed benign controls and rejects unexpected matches.

Contract metrics answer:

> Does the current rule library produce exactly the declared output on the committed scenarios?

They do not answer:

> What precision or recall will this rule have on production traffic?

Network behavior fixtures use deterministic `tshark -T fields`-shaped metadata. Zeek and Suricata
fixtures reproduce exported text shapes without requiring both engines in every CI job.

## API And Persistence Integration

Integration tests use FastAPI's test client and isolated application state to cover:

- upload and sample analysis;
- saved run listing and reopen;
- entities and notes;
- retention preview, export, and apply;
- report formats and redaction parity;
- assistant mock behavior and evidence references;
- rule library exposure;
- liveness/readiness and metrics dependencies.

These tests prove component cooperation in one process. They do not prove distributed behavior or a
long-running production database lifecycle.

## Security Integration

Allowed and denied tests cover explicit local/Azure auth modes, viewer/analyst/admin boundaries,
server-side note attribution, audit events, upload validation, malformed input, and HTTP/WebSocket
authorization.

Security tests must include both successful and denied behavior. A test that only proves an admin
can perform an action does not prove a viewer cannot.

## Robustness And Recovery

Robustness coverage includes concurrent independent analyses, unsupported control-heavy input,
malformed JSON, newline-heavy payloads, limit enforcement, and successful recovery after a rejected
upload. Backup tests exercise online SQLite backup and integrity verification.

The opt-in scale benchmark measures direct offline analysis at larger sizes without weakening the
bounded HTTP upload contract.

## System Smoke Tests

Smoke tools verify real process boundaries that unit tests do not:

| Gate | Purpose |
| --- | --- |
| `make smoke-live` | live file/folder analysis path |
| `make smoke-ollama` | configured local assistant boundary |
| `make smoke-reports` | rendered report path |
| `make smoke-ui` | browser-facing application workflow |
| `make smoke-azure-public` | deployed public/auth posture |
| `make real-lab-proof` | real Zeek/Suricata replay/export path |

Smoke tests are narrower than full E2E product tests. They prove a chosen critical path, not every
interaction or browser state.

## Performance And Resource Budgets

Benchmarks run isolated repetitions and record latency, throughput, and peak RSS for bounded upload,
mixed parsing, case bundle, scale, and report flows. CI uses regression ceilings, not universal
production SLOs.

Benchmark proof must record the code revision, environment, input size, repetitions, and dirty-tree
state. A measurement from a dirty tree remains evidence with a limitation, not a release baseline.

## External Dataset Evaluation

IoT-23 evaluation scores selected Zeek scan rules in fixed windows against an external label and a
separate benign capture. It records hashes, method, false positives, false negatives, and scope.

The current evaluation is intentionally narrow. It cannot validate all parser families, rule
families, modern enterprise traffic, or production prevalence.

## Real-Engine Proof

The real-lab runner creates a controlled PCAP, replays it through containerized Zeek and Suricata,
uploads their exports through the normal API path, and creates reports and a manifest. This closes
the gap between hand-written text fixtures and real engine output while remaining a seeded lab.

## Deployment Verification

The delivery pipeline builds an immutable commit-tagged image, deploys it, and checks that the
running revision reports the expected commit. A 200 response alone is insufficient because it can
come from a previous healthy deployment.

## Primary Commands

```bash
ruff check apps/api/tracehawk_api apps/api/tests tools
pytest apps/api/tests -W error -q
npm --prefix apps/web run test:coverage
npm --prefix apps/web run build
make detection-quality-check
make benchmark-smoke
make docs-check
make verify-all
```

## Claim Matrix

| Claim | Minimum supporting evidence | What remains unproven |
| --- | --- | --- |
| Parser extracts declared fields | parser unit test and realistic fixture | all vendor versions and malformed variants |
| Rule matches its contract | positive and benign scenarios | population-level precision/recall |
| Correlation score is stable | scoring unit/integration tests | causal correctness |
| Analysis can be reopened | persistence integration test | multi-version migration history |
| UI builds and critical path renders | build, component test, UI smoke | all interactions, browsers, and accessibility states |
| Public revision is current | exact-commit deployment check | long-term reliability and SLOs |
| Backup is readable | online backup and integrity test | full disaster-recovery objective |

## Known Gaps And Priorities

1. Include all maintained frontend files in coverage and add component tests for primary workflows.
2. Add browser E2E coverage for demo, real-lab case, report export, and auth boundaries.
3. Expand external datasets across rule families and current traffic shapes.
4. Run longer-lived collector and persistence soak tests.
5. Add schema migration and upgrade/rollback tests before evolving persisted deployments.
6. Add independent-user reproduction evidence rather than relying only on maintainer-generated proof.
