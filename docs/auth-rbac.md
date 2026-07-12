# Authentication, RBAC, And Audit Trail

TraceHawk has two explicit authentication modes. There is no automatic trust of identity headers.

| Mode | Intended boundary | Effective local role |
| --- | --- | --- |
| `disabled` | loopback-bound local workstation or private development environment | local `admin`; deployment identity headers are ignored |
| `azure_easy_auth` | trusted header-sanitizing identity proxy in front of the application | role derived from the allowlist and role bindings |

The public GitHub quick start uses `TRACEHAWK_AUTH_MODE=disabled` and binds to loopback. The
`azure_easy_auth` compatibility mode is optional; starting it without an allowlist fails
configuration validation. `x-ms-client-principal-name` and `x-ms-client-principal` are trusted only
in that mode and only behind a proxy that removes client-supplied identity headers before injecting
an authenticated principal.

## Role Matrix

| Capability | Viewer | Analyst | Admin |
| --- | :---: | :---: | :---: |
| View runs, incidents, entities, rules, MITRE, notes, status, and settings | yes | yes | yes |
| Start upload, sample, or case analysis | no | yes | yes |
| Open host file, folder, Docker, or interface live sources | no | no | yes |
| Generate incident or case reports and assistant previews | no | yes | yes |
| Create, update, or delete analyst notes | no | yes | yes |
| Preview retention | no | yes | yes |
| Change assistant or retention settings | no | no | yes |
| Apply retention deletion | no | no | yes |
| Read the audit trail | no | no | yes |

An allowlisted identity without an explicit analyst or admin binding receives the least-privileged
`viewer` role. Live WebSocket sources require `admin` because their parameters select resources on
the API host: filesystem paths, Docker containers, and capture interfaces. Analysts can persist and
investigate snapshots supplied through approved application workflows, but cannot select host
resources directly.

## Configuration

```text
TRACEHAWK_AUTH_MODE=azure_easy_auth
ALLOWED_AUTH_EMAILS=owner@example.com,analyst@example.com,viewer@example.com
TRACEHAWK_ADMIN_EMAILS=owner@example.com
TRACEHAWK_ANALYST_EMAILS=analyst@example.com
TRACEHAWK_VIEWER_EMAILS=viewer@example.com
```

Role bindings are application configuration, not authorization data supplied by the client. Keep
the deployed service behind a documented header-sanitizing identity proxy; exposing
`azure_easy_auth` mode directly would let a client forge the platform headers.

## Audit Trail

Mutating HTTP requests, denied access attempts, and live WebSocket connection attempts are stored
in SQLite. Each event contains actor, role, method, path, outcome, status, timestamp, and request ID.
Request bodies, uploaded log content, credentials, and report contents are never copied into audit
events.

```text
GET /api/audit/events?limit=100
Required role: admin
```

This is a single-instance audit trail for the portfolio deployment. A multi-instance production
service should export immutable audit events to a centralized security log with retention and
tamper controls.
