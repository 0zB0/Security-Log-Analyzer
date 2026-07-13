# Operations And Observability

TraceHawk is a single-replica portfolio service. These controls provide observable local and
self-hosted operation; they do not provide multi-region or multi-tenant SIEM guarantees.

## Runtime Signals

| Signal | Endpoint or source | Access | Purpose |
| --- | --- | --- | --- |
| Liveness | `GET /api/health/live` | public | process is serving HTTP |
| Readiness | `GET /api/health/ready` | public | private: SQLite plus rules/patterns; public demo: database disabled plus rules/patterns |
| Health | `GET /api/health` | public | client and smoke compatibility |
| Metrics | `GET /metrics` | admin | request count, status, in-flight gauge, latency, build metadata |
| Structured logs | stdout JSON | operator | request ID, route template, status, duration, role, build |
| Audit events | `GET /api/audit/events` | admin | mutations, denied access, and live connection attempts |
| Syslog collector stats | structured JSON stdout | local operator | accepted, dropped, queued, failed, and persisted work |

Request logs use route templates, omit query strings and bodies, and never log uploaded evidence.
`X-Request-ID` correlates responses, structured logs, and audit events.

## Operational Boundaries

- readiness must be `200` before and after deployment;
- protected API access without identity must remain `401` or `403` in deployed-auth mode;
- public-demo private routes must remain `404`, results must expose no public analysis ID, and
  response headers must remain non-cacheable;
- repeated readiness, SQLite, or restart failures require rollback or restore assessment;
- upload latency and memory must remain inside `docs/performance.md` budgets;
- rate limits, metrics, and SQLite writes are instance-local;
- horizontal write scaling requires external shared state and is not supported by this release.
- the optional syslog collector is loopback-default, in-memory-queue bounded, and has no delivery
  acknowledgement or replay guarantee.

The container runs as a non-root user and exposes a Docker healthcheck. Backup export is available
to administrators; restore is an explicit offline CLI operation. Review `docs/deployment-selfhost.md`,
`docs/threat-model.md`, and `docs/limitations.md` before deployment.

The anonymous demo must run as a separate single-replica instance with
`TRACEHAWK_DEPLOYMENT_PROFILE=public_demo`, no persistent volume, and external AI disabled. Its
runtime contract is documented in `docs/public-demo.md`.
