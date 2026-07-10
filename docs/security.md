# Security Notes

## Data Boundary

TraceHawk is designed for sanitized portfolio demonstrations. Do not upload production logs,
credentials, tokens, cookies, private keys, client data, personal data, confidential hostnames, or
internal topology.

## Current Controls

- upload extensions, request bytes, file bytes, line count, case file count, and total case bytes
  are bounded independently;
- uploaded file objects are not retained, while bounded analysis evidence is stored in SQLite;
- only UTF-8 text is accepted; compressed archives and binary captures are rejected;
- the Docker image runs as a non-root user and has a healthcheck;
- request logs omit bodies, query strings, and evidence;
- local mode ignores deployment identity headers;
- committed local Docker profiles publish ports on loopback only because local mode has no external
  authentication;
- deployed-auth mode fails closed and enforces viewer/analyst/admin RBAC;
- report rendering escapes interpolated values and supports evidence redaction;
- CI runs Gitleaks, Semgrep, Python and npm audits, tests, and Docker build verification.

## Remaining Boundaries

- rate limiting and metrics are process-local;
- SQLite is single-writer storage and no tenant isolation is provided;
- malware scanning and encrypted evidence object storage are not implemented;
- no centralized immutable audit export or external paging integration is included;
- deterministic rules require analyst validation and can produce false positives.

See [threat model](threat-model.md), [limitations](limitations.md), and
[authentication matrix](auth-rbac.md). Report vulnerabilities through the private process in the
repository root `SECURITY.md`.
