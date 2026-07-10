# Operations And Observability

TraceHawk is a single-replica portfolio service. These controls provide observable local and
self-hosted operation; they do not provide multi-region or multi-tenant SIEM guarantees.

## Runtime Signals

| Signal | Endpoint or source | Access | Purpose |
| --- | --- | --- | --- |
| Liveness | `GET /api/health/live` | public | process is serving HTTP |
| Readiness | `GET /api/health/ready` | public | SQLite query and YAML rules load successfully |
| Health | `GET /api/health` | public | client and smoke compatibility |
| Metrics | `GET /metrics` | admin | request count, status, in-flight gauge, latency, build metadata |
| Structured logs | stdout JSON | operator | request ID, route template, status, duration, role, build |
| Audit events | `GET /api/audit/events` | admin | mutations, denied access, and live connection attempts |

Request logs use route templates, omit query strings and bodies, and never log uploaded evidence.
`X-Request-ID` correlates responses, structured logs, and audit events.

## Operational Boundaries

- readiness must be `200` before and after deployment;
- protected API access without identity must remain `401` or `403` in deployed-auth mode;
- repeated readiness, SQLite, or restart failures require rollback or restore assessment;
- upload latency and memory must remain inside `docs/performance.md` budgets;
- rate limits, metrics, and SQLite writes are instance-local;
- horizontal write scaling requires external shared state and is not supported by this release.

The container runs as a non-root user and exposes a Docker healthcheck. Backup export is available
to administrators; restore is an explicit offline CLI operation. Review `docs/deployment-selfhost.md`,
`docs/threat-model.md`, and `docs/limitations.md` before deployment.
