# Authentication, RBAC, And Audit Trail

TraceHawk has two explicit authentication modes. There is no automatic trust of identity headers.

| Mode | Intended boundary | Effective local role |
| --- | --- | --- |
| `disabled` | local workstation or private development network | local `admin`; Azure identity headers are ignored |
| `azure_easy_auth` | Azure Container Apps Easy Auth in front of the application | role derived from the allowlist and role bindings |

The public Azure deployment sets `TRACEHAWK_AUTH_MODE=azure_easy_auth`. Starting that mode without
an allowlist fails configuration validation. `x-ms-client-principal-name` and
`x-ms-client-principal` are trusted only in this mode and only because Azure Easy Auth removes
untrusted client identity headers before injecting its authenticated principal.

## Role Matrix

| Capability | Viewer | Analyst | Admin |
| --- | :---: | :---: | :---: |
| View runs, incidents, entities, rules, MITRE, notes, status, and settings | yes | yes | yes |
| Start upload, sample, case, or live analysis | no | yes | yes |
| Generate incident or case reports and assistant previews | no | yes | yes |
| Create, update, or delete analyst notes | no | yes | yes |
| Preview retention | no | yes | yes |
| Change assistant or retention settings | no | no | yes |
| Apply retention deletion | no | no | yes |
| Read the audit trail | no | no | yes |

An allowlisted identity without an explicit analyst or admin binding receives the least-privileged
`viewer` role. Live WebSocket sources require `analyst` or `admin`.

## Configuration

```text
TRACEHAWK_AUTH_MODE=azure_easy_auth
ALLOWED_AUTH_EMAILS=owner@example.com,analyst@example.com,viewer@example.com
TRACEHAWK_ADMIN_EMAILS=owner@example.com
TRACEHAWK_ANALYST_EMAILS=analyst@example.com
TRACEHAWK_VIEWER_EMAILS=viewer@example.com
```

Role bindings are application configuration, not authorization data supplied by the client. Keep
the deployed service behind its documented identity proxy; exposing `azure_easy_auth` mode without
Azure Easy Auth would let a direct client forge the platform headers.

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
