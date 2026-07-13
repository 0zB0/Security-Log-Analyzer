# Threat Model

## Scope And Assumptions

TraceHawk is a local-first investigation assistant and a single-user portfolio system. It is not a
multi-tenant SIEM. The public quick start binds to loopback and uses local admin mode. Any deployment
that enables trusted-proxy authentication must place a header-sanitizing identity boundary before
the application-level email allowlist.

The anonymous session-only demo is a second deployment profile, not the private workspace with its
login removed. It exposes a separate stateless namespace, has no SQLite lifecycle, and must run as a
separate Container App without the private data volume.

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
  -> loopback boundary or trusted identity proxy
  -> FastAPI request-body and identity middleware
  -> live-snapshot attestation and evidence-integrity validation
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
| Parser confusion | Parser selection is deterministic, stratified, and covered by parser-specific and mixed-input fixtures | Headerless or arbitrarily interleaved stateful rows can still be skipped or misclassified |
| Malicious log prompt injection | Local-only LLM, structured prompt, bounded evidence, response validation, deterministic findings remain authoritative | LLM explanation can still be wrong and must not be treated as evidence |
| Sensitive report disclosure | Optional redaction, authenticated demo, bounded evidence, explicit handling guidance | Authorized users can still export sensitive data |
| Header spoofing | Identity headers are ignored in local mode and trusted only in explicit `azure_easy_auth` compatibility mode behind a header-sanitizing identity boundary | Exposing this mode without a trusted proxy permits forged headers |
| Privilege misuse | Least-privileged viewer default, analyst/admin capability gates, server-attributed note authors, and persistent audit events | Application administrators can still access all locally persisted evidence |
| Request flooding | Per-principal/client in-memory rate limit, Azure-validated rightmost forwarded IP, concurrency/timeout caps, and single-replica deployment | Limits are not shared across replicas and reset on restart |
| Public visitor reads another result | Public responses have no reusable analysis ID, no history endpoint, no database write, and no server result store | A visitor can still retain or share their own browser response |
| Public payload retained by cache or temporary upload spool | JSON browser-read text, non-cacheable responses, no multipart upload, and body-free logs | Platform-level memory and transport handling still exist during the bounded request |
| Public profile exposes private capability | Profile-aware allowlist returns `404` for private HTTP/WebSocket routes; separate deployment has no private volume | A future route must be added to the allowlist tests or it can create a regression |
| Collector memory exhaustion | Loopback-default listener, byte cap, fixed queue, TCP connection cap, idle timeout, bounded batch | Explicit remote bind expands exposure; queue or UDP drops lose telemetry |
| Live source growth | Fixed raw-line and event windows with signed retained/dropped counters | Evicted evidence is unavailable for later investigation |
| Stored evidence exposure | Private SQLite volume, retention and purge workflow, no original file retention | Evidence text needed for reports remains sensitive at rest |
| Forged or modified live save | Process-local HMAC over the server snapshot plus server-side hash, counter, and graph verification before persistence | Attestation proves current-process snapshot integrity, not sensor identity or legal chain of custody |
| Supply-chain compromise | Locked dependencies, SHA-pinned GitHub Actions, Dependabot, Gitleaks, Semgrep, CycloneDX SBOM, and Trivy image scanning | Upstream registries and newly disclosed vulnerabilities still require scheduled review and dependency updates |

## Security Invariants

- Rejected uploads never create analysis records.
- Findings are deterministic and evidence-backed.
- Unpurged evidence hashes are recomputed by the server before persistence.
- Live snapshot saves require a valid server-generated attestation.
- Live snapshot attestation covers bounded-window provenance and retained/dropped counters.
- Default application profiles and Azure publish no syslog listener.
- The LLM cannot create, suppress, or change findings.
- Original uploaded files are not retained after request processing.
- Authentication must fail closed when the deployed allowlist is enabled.
- Public analysis never initializes SQLite, persists a result, invokes external AI, or exposes a
  reusable analysis identifier.
- Public results are non-cacheable and private HTTP/WebSocket capabilities remain unavailable.
- Allowlisted identities without a role binding receive viewer, never analyst or admin.
- Request bodies and evidence content are excluded from authorization audit events.
- Security controls documented as current must have executable tests.

## Out Of Scope

- Multi-tenant isolation.
- Malware scanning of uploaded files.
- Queue-based processing of files larger than the configured demo limit.
- Enterprise identity lifecycle, tenant isolation, and external policy administration.
- Automatic blocking, response, or remediation.
