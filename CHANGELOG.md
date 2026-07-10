# Changelog

All notable public TraceHawk releases are documented here.

## [Unreleased]

### Added

- frontend tests, accessibility assertions, and coverage enforcement;
- reproducible Python and npm dependency locks;
- 10, 50, and 100 MB offline scale evidence and robustness tests;
- architecture decision records and an executable technical walkthrough.

### Changed

- the workspace frontend and report service are split into focused modules;
- public CI validates frontend tests before build.

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

[Unreleased]: https://github.com/0zB0/Security-Log-Analyzer/compare/v0.7.1...HEAD
[0.7.1]: https://github.com/0zB0/Security-Log-Analyzer/releases/tag/v0.7.1
[0.7.0]: https://github.com/0zB0/Security-Log-Analyzer/releases/tag/v0.7.0
