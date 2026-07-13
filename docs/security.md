# Security Notes

## Data Boundary

TraceHawk is designed for sanitized portfolio demonstrations. Do not upload production logs,
credentials, tokens, cookies, private keys, client data, personal data, confidential hostnames, or
internal topology.

## Current Controls

- upload extensions, request bytes, file bytes, line count, case file count, and total case bytes
  are bounded independently;
- uploaded file objects are not retained, while bounded analysis evidence is stored in SQLite;
- unpurged evidence hashes, counters, ownership, and graph references are verified before write;
- browser-returned live snapshots require a current-process HMAC before persistence;
- only UTF-8 text is accepted; compressed archives and binary captures are rejected;
- the Docker image uses digest-pinned bases, installs the API wheel as a non-root user, and has a
  healthcheck;
- request logs omit bodies, query strings, and evidence;
- local mode ignores deployment identity headers;
- committed local Docker profiles publish ports on loopback only because local mode has no external
  authentication;
- deployed-auth mode fails closed and enforces viewer/analyst/admin RBAC;
- the anonymous `public_demo` runtime has no SQLite lifecycle, no external AI, no private API or
  WebSocket access, no public analysis IDs, and non-cacheable responses;
- public analysis has independent byte, line, rate, concurrency, and execution-time limits and is
  supported only at one replica while those controls remain process-local; Azure mode keys the
  limiter only from the platform-supplied rightmost forwarded address;
- live sources use fixed raw/event windows with retained/dropped counters; the optional TCP/UDP
  syslog collector is loopback-default and queue/line/connection/batch bounded;
- report rendering escapes interpolated values and supports evidence redaction;
- CI runs Gitleaks, Semgrep, Python and npm audits, component and Playwright tests, a Docker build,
  and a Trivy HIGH/CRITICAL image gate;
- GitHub Actions are SHA-pinned, scheduled weekly, and covered by Dependabot together with Python,
  npm, and Docker dependencies.
- FastAPI/TypeScript contract artifacts are deterministic and drift-checked in CI.

## Remaining Boundaries

- rate limiting and metrics are process-local;
- the public demo processes bounded visitor text in memory during a request even though it does not
  retain the result;
- SQLite is single-writer storage and no tenant isolation is provided;
- malware scanning and encrypted evidence object storage are not implemented;
- no centralized immutable audit export or external paging integration is included;
- deterministic rules require analyst validation and can produce false positives.

See [threat model](threat-model.md), [limitations](limitations.md), and
[authentication matrix](auth-rbac.md). Report vulnerabilities through the private process in the
repository root `SECURITY.md`.
