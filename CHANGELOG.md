# Changelog

All notable public TraceHawk releases are documented here.

## [Unreleased]

No unreleased changes.

## [0.9.0] - 2026-07-12

### Added

- server-verified evidence hashes, graph validation, persisted provenance, and live snapshot
  attestation;
- declarative correlation behavior/pattern metadata and bounded common-entity grouping;
- bounded live windows and an opt-in loopback TCP/UDP syslog collector;
- frozen role-separated IoT-23 scan and C2-indicator evaluation;
- deterministic OpenAPI-to-TypeScript generation with drift gates;
- broader interaction, axe, recovery, and Chromium workflow verification.

### Changed

- correlation no longer depends on rule names or IDs for behavior semantics;
- retained and dropped live counters are visible and persisted;
- frontend coverage floors now enforce 70% lines/statements, 65% functions, and 50% branches;
- CI retains coverage and browser evidence artifacts.

### Security

- modified or stale-process live snapshots fail before persistence;
- collector resource limits and loopback defaults reduce accidental exposure;
- known external-evaluation errors remain published.

### Known Limitations

- the frozen stable-endpoint C2-indicator slice records 0.0870 precision and is not a production
  detector claim;
- live HMAC attestation is not sensor identity or legal chain of custody;
- syslog UDP and in-memory queues cannot guarantee delivery or replay.

## [0.8.0] - 2026-07-12

### Added

- frontend tests, accessibility assertions, and coverage enforcement;
- reproducible Python and npm dependency locks;
- 10, 50, and 100 MB offline scale evidence and robustness tests;
- architecture decision records and an executable technical walkthrough;
- Alembic case-integrity migration with strict legacy-schema recognition;
- complete case and scoring round-trip persistence tests;
- rendered Playwright investigation and report E2E;
- Dependabot and scheduled GitHub security verification.

### Changed

- the workspace frontend and report service are split into focused modules;
- public CI validates frontend tests before build;
- repeated analysis replaces stale child records;
- release exports require a clean tree and identify dirty previews explicitly;
- production containers use digest-pinned bases and wheel installation;
- release reports use a fixed release clock and invariant PDF output.

### Security

- SQLite foreign keys are enabled for every application connection;
- local rate limiting cannot be bypassed with spoofed deployment identity headers;
- host live sources and assistant settings follow role-aware frontend/backend boundaries;
- Actions are SHA-pinned and Trivy rejects fixed HIGH or CRITICAL image vulnerabilities.

## [0.7.1] - 2026-07-10

### Changed

- local Docker ports bind to loopback and self-host instructions use the required Compose profile;
- synthetic SSH and web fixtures use RFC 5737 TEST-NET addressing;
- screenshots and release proof assets were regenerated from the corrected fixtures;
- public CI publishes Semgrep SARIF to GitHub code scanning;
- issue forms, pull request guidance, and a code of conduct complete the public contribution surface.

### Security

- the unauthenticated local admin surface is no longer published to the surrounding LAN by default;
- the clean-room export rejects the previously used routable synthetic address;
- GitHub secret scanning and push protection are enabled for the public mirror.

## [0.7.0] - 2026-07-09

### Added

- confidence-ranked parser selection and per-line mixed-log routing;
- typed two-to-eight-step sequence detection;
- complete 65-rule positive contract coverage and benign controls;
- external IoT-23 evaluation with explicit error analysis;
- bounded upload, case bundle, persistence, and report performance budgets;
- viewer/analyst/admin RBAC, WebSocket authorization, and audit trail;
- structured logs, Prometheus metrics, readiness, and container healthcheck;
- SQLite backup tooling and documented recovery boundaries;
- UI demo, screenshots, multi-source case study, and HTML/PDF report proof;
- Gitleaks, Semgrep, dependency audit, coverage, and Docker CI gates.

### Security

- deployed identity headers are trusted only in explicit deployed-auth mode;
- local mode ignores spoofed deployment identity headers;
- request and report logs exclude uploaded bodies and evidence payloads;
- uploads are bounded by request, file, line, file-count, and total case size.

### Known Limitations

- single-replica SQLite architecture;
- instance-local rate limiting and metrics;
- no multi-tenant isolation or autonomous response;
- the documented IoT-23 slice is deliberately small and not a production accuracy claim.

[Unreleased]: https://github.com/0zB0/Security-Log-Analyzer/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/0zB0/Security-Log-Analyzer/releases/tag/v0.9.0
[0.8.0]: https://github.com/0zB0/Security-Log-Analyzer/releases/tag/v0.8.0
[0.7.1]: https://github.com/0zB0/Security-Log-Analyzer/releases/tag/v0.7.1
[0.7.0]: https://github.com/0zB0/Security-Log-Analyzer/releases/tag/v0.7.0
