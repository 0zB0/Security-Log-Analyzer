# Threat Model

## Scope And Assumptions

TraceHawk is a local-first investigation assistant and a protected single-user portfolio demo. It
is not a multi-tenant SIEM. The Azure deployment relies on Azure Container Apps Easy Auth before
the application-level email allowlist. Self-hosted deployments must provide an equivalent trusted
identity boundary or keep the service private.

## Assets

- Raw log content and evidence lines.
- Parsed events, findings, incidents, notes, and entity relationships.
- SQLite analysis state and generated reports.
- Local LLM prompts and outputs.
- Authentication identity, role configuration, and deployment metadata.
- Detection rules, proof datasets, and integrity hashes.

## Trust Boundaries

```text
Browser or API client
  -> Azure Easy Auth / private reverse proxy
  -> FastAPI request-body and identity middleware
  -> parser, detection, correlation, and report services
  -> SQLite volume and optional local Ollama service
```

The application never treats log text as instructions. Deterministic services operate on parsed
fields; the optional LLM receives bounded evidence only and cannot create findings.

## Abuse Cases And Controls

| Threat | Control | Residual Risk |
| --- | --- | --- |
| Oversized upload or bundle | ASGI request-body cap plus per-file, line-count, file-count, and total bundle limits | Multipart parsing and bounded in-memory analysis still consume resources up to the configured limit |
| Decompression bomb or opaque binary | Archives and binary captures are rejected; only allowlisted UTF-8 text formats are accepted | A text payload can still be computationally expensive within its budget |
| Parser confusion | Parser selection is deterministic and covered by parser-specific fixtures | Mixed input confidence remains a separate hardening milestone |
| Malicious log prompt injection | Local-only LLM, structured prompt, bounded evidence, response validation, deterministic findings remain authoritative | LLM explanation can still be wrong and must not be treated as evidence |
| Sensitive report disclosure | Optional redaction, authenticated demo, bounded evidence, explicit handling guidance | Authorized users can still export sensitive data |
| Header spoofing | Identity headers are ignored in local mode and trusted only in explicit `azure_easy_auth` mode behind Azure's header-sanitizing identity boundary | A self-hosted deployment that exposes this mode without an equivalent trusted proxy is vulnerable to forged headers |
| Privilege misuse | Least-privileged viewer default, analyst/admin capability gates, server-attributed note authors, and persistent audit events | Application administrators can still access all locally persisted evidence |
| Request flooding | Per-principal/client in-memory rate limit and single-replica deployment | Limits are not shared across replicas and reset on restart |
| Stored evidence exposure | Private SQLite volume, retention and purge workflow, no original file retention | Evidence text needed for reports remains sensitive at rest |
| Supply-chain compromise | GitLab CI tests and container build | SBOM and vulnerability policy are planned operational hardening |

## Security Invariants

- Rejected uploads never create analysis records.
- Findings are deterministic and evidence-backed.
- The LLM cannot create, suppress, or change findings.
- Original uploaded files are not retained after request processing.
- Authentication must fail closed when the deployed allowlist is enabled.
- Allowlisted identities without a role binding receive viewer, never analyst or admin.
- Request bodies and evidence content are excluded from authorization audit events.
- Security controls documented as current must have executable tests.

## Out Of Scope

- Multi-tenant isolation.
- Malware scanning of uploaded files.
- Queue-based processing of files larger than the configured demo limit.
- Enterprise identity lifecycle, tenant isolation, and external policy administration.
- Automatic blocking, response, or remediation.
