# Engineering Portfolio Guide

> Audience: employers, engineering managers, technical interviewers, academic reviewers, and contributors
> Canonical for: mapping TraceHawk capabilities to engineering disciplines and review evidence
> Verified against: TraceHawk v0.10.0

TraceHawk is best evaluated as a compact, full-stack security product rather than as a small script
or an attempted enterprise SIEM. This guide maps each engineering area to its implementation,
verification, canonical documentation, honest limitation, and oral-review questions.

Use the [documentation hub](README.md) for task-oriented navigation and the
[product specification](product-spec.md) for the current product contract.

## Product Engineering

TraceHawk turns a broad “analyze security logs” idea into a bounded local workflow: ingest,
normalize, detect, correlate, investigate, persist, explain, and report.

| Review dimension | Evidence |
| --- | --- |
| Product scope | `docs/product-spec.md`, `docs/limitations.md` |
| User workflow | `docs/case-investigation-workflow.md`, demo assets |
| Current versus planned work | `ROADMAP.md`, `docs/plans/active/` |
| Success criteria | reproducible demo, tests, reports, and proof pack |

Strong signal: the project explicitly rejects QRadar/SIEM replacement claims and separates product
AI from deterministic evidence.

Current limitation: the repository has portfolio proof, not independent market adoption or a
multi-user production history.

Be prepared to explain:

- Why is a local SOC assistant a better scope than a SIEM replacement?
- Which user problem is solved without long-term centralized log search?
- Which feature would be removed first if it weakened evidence traceability?

## Security And SOC Domain

The domain model follows an analyst path from raw evidence to normalized events, findings,
incidents, entities, timelines, ATT&CK context, notes, and reports.

| Implementation | Verification | Canonical documentation |
| --- | --- | --- |
| `models/domain.py` | API and scenario tests | [Architecture](architecture.md) |
| Case and incident panels | real-lab UI proof | [Case workflow](case-investigation-workflow.md) |
| MITRE mapping service and UI | rule contracts and API tests | [Rules](rules.md) |
| Report renderers | Markdown/HTML/PDF tests | [API reference](api.md) |

Strong signal: observed evidence, interpretation, and recommended next action remain separate.

Current limitation: TraceHawk cannot prove compromise without endpoint, identity, and network
corroboration beyond the supplied evidence.

Be prepared to explain the difference between an event, finding, alert-like result, and correlated
incident.

## Log Parsing And Normalization

The parser layer recognizes specific security formats before generic fallbacks and preserves parser
provenance for mixed input.

| Implementation | Verification | Canonical documentation |
| --- | --- | --- |
| `services/parser_registry.py` | `test_parser_selection.py` | [Event pipeline](event-processing-pipeline.md) |
| `services/*_parser.py` | parser-specific tests | source ingest guides |
| `models/domain.py::ParsedEvent` | end-to-end scenario tests | [Architecture](architecture.md) |

Strong signal: selection uses stratified content samples and specificity ranking rather than file
extension alone.

Current limitation: this is a curated parser set, not an enterprise schema/connector ecosystem;
stateful formats still require headers.

Be prepared to explain:

- Why must Suricata outrank generic JSON?
- How is a mixed text file routed?
- Why can raw line count differ from parsed event count?

## Detection Engineering

Versioned YAML contracts express transparent thresholds, cardinality, periodic timing, field
matching, and multi-step sequences. The engine evaluates them without an LLM.

| Implementation | Verification | Canonical documentation |
| --- | --- | --- |
| `services/rules.py` | `test_detection_quality.py` | [Rules](rules.md) |
| `services/detection.py` | `test_sequence_engine.py` | [Rule authoring](rule-authoring.md) |
| `packages/rules/` | `packages/test-scenarios/` | [Detection quality](detection-quality.md) |

Strong signal: every rule has a positive contract, while committed benign controls reject
unexpected matches.

Current limitation: contract precision/recall describes declared fixtures. The role-separated
IoT-23 scan and stable-endpoint C2-indicator objectives report real false positives and false
negatives, including poor C2-indicator precision, and are not production accuracy.

Be prepared to explain threshold windows, grouping keys, sequence ordering, false-positive notes,
and why lowering a threshold to fit one dataset can reduce generality.

## Incident Correlation

Correlation groups findings through entities, time, behavior sequences, rule-family diversity, and
independent-source links. Scores are additive and include visible rationale.

| Implementation | Verification | Canonical documentation |
| --- | --- | --- |
| `services/correlation.py` | `test_correlation_scoring.py` | [Correlation](correlation.md) |
| `services/case_bundle.py` | `test_case_bundle_api.py` | [Case workflow](case-investigation-workflow.md) |
| Case panels/selectors | selector tests and UI proof | [Frontend architecture](frontend-architecture.md) |

Strong signal: the UI and reports expose why an incident received its score.

Current limitation: this is deterministic heuristic grouping, not graph-scale historical analytics
or probabilistic causal inference.

Be prepared to explain why two findings should or should not form one incident and which scoring
guardrails prevent volume alone from dominating.

## Backend And API Engineering

FastAPI routers define bounded HTTP and WebSocket interfaces; services keep parsing, detection,
correlation, persistence, reporting, and assistant concerns separate.

| Implementation | Verification | Canonical documentation |
| --- | --- | --- |
| `main.py`, `routers/` | API and health tests | [API reference](api.md) |
| `services/analysis.py` | analysis and robustness tests | [Event pipeline](event-processing-pipeline.md) |
| Pydantic domain models | validation through unit/API tests | [Architecture](architecture.md) |

Strong signal: the code distinguishes transport, domain, and persistence responsibilities without
introducing unnecessary infrastructure.

Current limitation: API versioning and browser runtime schema validation are not present. The
compile-time frontend contract is generated and drift-enforced.

Be prepared to trace one upload from router through service calls to the returned `AnalysisResult`.

## Persistence And Evidence Governance

SQLite stores bounded investigation state, raw evidence text, events, findings, incidents, entities,
notes, settings, and body-free audit metadata. Original uploaded files are not copied into durable
file storage.

| Implementation | Verification | Canonical documentation |
| --- | --- | --- |
| `database.py` | health and API tests | [Persistence lifecycle](persistence-evidence-lifecycle.md) |
| `services/persistence.py` | reopen/list tests | same canonical guide |
| retention and backup services | retention and backup tests | runbooks |

Strong signal: the documentation explicitly distinguishes “file not retained” from “raw evidence
text persisted.”

Current limitation: Alembic now manages schema evolution, but no immutable evidence ledger,
encryption design, or horizontal-write model is present.

Be prepared to explain what remains after raw-evidence purge and why a hash cannot reconstruct
deleted text or establish chain of custody.

## Frontend And Investigation UX

React presents one coordinated investigation workspace with incident, evidence, case, entity,
MITRE, library, live, assistant, and report projections.

| Implementation | Verification | Canonical documentation |
| --- | --- | --- |
| `app/main.tsx` | production build, component tests, and Playwright E2E | [Frontend architecture](frontend-architecture.md) |
| `WorkspaceBody.tsx` | component test | same canonical guide |
| `workspaceSelectors.ts` | selector tests | same canonical guide |
| specialized workspace panels | backend integration proof and screenshots | case workflow/proof |

Strong signal: evidence is selected by backend evidence IDs rather than reconstructed with fuzzy
text matching in the browser.

Current limitation: the enforced whole-source component and Chromium critical-path coverage does
not yet provide a cross-browser, exhaustive responsive, or complete screen-reader matrix.

Be prepared to explain top-level versus panel-local state and what should move into URL routing or a
state reducer as workflows grow.

## Testing And Evaluation

The verification model combines unit behavior, rule contracts, integration tests, smoke tests,
performance budgets, security scans, external evaluation, and deployment proof.

| Layer | Examples | Canonical documentation |
| --- | --- | --- |
| Unit | parser, sequence, selector behavior | [Testing strategy](testing-strategy.md) |
| Contract | rule scenarios and benign controls | [Detection quality](detection-quality.md) |
| Integration | API, persistence, reports, auth | [Testing strategy](testing-strategy.md) |
| System | Docker, UI, live, Ollama, reports | Make targets and proof pack |
| External | IoT-23 scan and stable-endpoint C2-indicator windows | current IoT-23 proof |

Strong signal: external errors remain documented instead of being hidden behind fixture-perfect
metrics.

Current limitation: external dataset scope and real long-running operational evidence remain narrow.

Be prepared to explain what each test layer proves and, more importantly, what it cannot prove.

## Application Security

Security controls cover untrusted uploads, bounded resources, explicit auth modes, RBAC, WebSocket
authorization, audit metadata, report redaction, dependency scanning, static analysis, and secret
scanning.

| Implementation | Verification | Canonical documentation |
| --- | --- | --- |
| `security.py`, `services/uploads.py` | upload/security tests | [Security notes](security.md) |
| `auth.py` and middleware | auth gate tests | [Auth and RBAC](auth-rbac.md) |
| audit service | auth/audit tests | [Threat model](threat-model.md) |
| CI security jobs | pipeline proof | current CI/security proof |

Strong signal: local and trusted-proxy modes are explicit; deployment headers are not trusted in
local mode.

Current limitation: the single-instance audit sink, local rate limiter, and SQLite boundary are not
enterprise multi-tenant controls.

Be prepared to describe the most valuable asset, most likely abuse case, and which control fails
first if the app is horizontally scaled.

## DevSecOps And Operations

The GitHub delivery path validates code, dependencies, secrets, static findings, SBOM inputs,
browser behavior, digest-pinned images, and container vulnerabilities.

| Implementation | Verification | Canonical documentation |
| --- | --- | --- |
| `Dockerfile`, `docker-compose.yml` | compose and smoke gates | [Self-hosted deployment](deployment-selfhost.md) |
| `.github/workflows/ci.yml` | scheduled and change-triggered pipeline evidence | [Testing strategy](testing-strategy.md) |
| health/metrics/observability | health tests and operational proof | [Operations](operations.md) |
| backup/rollback tools | tool tests and runbooks | `docs/runbooks/` |

Strong signal: deployment verification checks the exact expected commit rather than only a 200
response.

Current limitation: a passing portfolio pipeline is not an SRE history, capacity model, or recovery
time guarantee.

Be prepared to explain the image promotion path, secret boundary, readiness dependencies, and
rollback evidence.

## Responsible Product AI

Optional Ollama output is advisory and grounded in selected structured evidence. Prompt limits and
guardrails prevent the model from becoming a hidden detector.

| Implementation | Verification | Canonical documentation |
| --- | --- | --- |
| `services/llm.py` | `test_assistant_api.py` | [LLM privacy model](llm-privacy-model.md) |
| assistant router and panels | mock smoke and UI flow | ADR 0003 |

Strong signal: deterministic findings work without a model and AI cannot change them.

Current limitation: grounded input reduces hallucination risk but cannot make generated narrative
authoritative or correct.

Be prepared to explain which exact data enters a prompt and why generated recommendations remain
separate from observed evidence.

## AI-Assisted Development And Accountability

The repository openly records extensive GPT-5.5 and GPT-5.6 assistance across ideation,
architecture, implementation, tests, review, and documentation. The maintainer remains responsible
for understanding, verification, and accepted output.

Canonical documentation: [AI-assisted development disclosure](ai-assisted-development.md).

Strong signal: the disclosure is specific about models, extent, missing prompt-history provenance,
human verification, and institutional-policy precedence.

Current limitation: complete prompt histories were not retained, so the estimated generated-code
share is not independently auditable line by line.

Be prepared to explain and modify any material subsystem without delegating the explanation back to
an AI tool.

## Technical Communication

The repository contains product scope, architecture, ADRs, rule contracts, a threat model,
runbooks, case studies, performance methods, proof artifacts, and an executable walkthrough.

Strong signal: canonical ownership separates explanation, decision rationale, operational procedure,
and measurement.

Current limitation: documentation must remain synchronized with fast-moving code and should be
judged by navigability and accuracy, not volume.

## Recommended Live Review

A strong 30-minute review is:

1. Run the real-lab sample and select the highest-scored incident.
2. Trace one finding to its YAML rule and raw evidence.
3. Explain one correlation score component.
4. Reopen the saved analysis and export a redacted report.
5. Change a bounded rule threshold and make its contract test fail, then pass.
6. Identify one external-evaluation error and one production architecture gap.

The [technical walkthrough](technical-walkthrough.md) provides the executable rule-change path.
