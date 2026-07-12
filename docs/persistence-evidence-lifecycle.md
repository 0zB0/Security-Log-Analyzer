# Persistence And Evidence Lifecycle

> Audience: backend engineers, security reviewers, privacy reviewers, and operators
> Canonical for: stored investigation state, evidence provenance, retention, and recovery
> Verified against: TraceHawk v0.7.1

TraceHawk uses SQLite to reopen bounded local investigations without retaining the original uploaded
file as a file. It does persist selected investigation state, including raw evidence text required
to explain saved findings and case links. This is sensitive local data and must not be confused with
stateless upload processing.

## Lifecycle Summary

```mermaid
flowchart LR
    U["Uploaded text or live snapshot"] --> A["In-memory analysis"]
    A --> T["SQLite transaction"]
    T --> S["Saved analysis, evidence, events, findings, incidents, entities"]
    S --> O["Reopen, annotate, report, or export"]
    S --> R["Retention preview"]
    R --> P["Purge raw evidence or full analysis"]
    S --> B["Online SQLite backup"]
```

## What Is And Is Not Retained

| Data | Retained | Notes |
| --- | --- | --- |
| Original uploaded file | No | TraceHawk does not copy the file into durable upload storage |
| Raw evidence line text | Yes | Required to reopen evidence and generate reports |
| Raw line SHA-256 | Yes | Supports integrity comparison |
| Normalized events | Yes | Includes parser-specific normalized fields |
| Findings and incidents | Yes | Includes evidence IDs, scores, and context |
| Entities | Yes | Derived index for investigation navigation |
| Analyst notes | Yes | Scoped to analysis and incident |
| Assistant prompt/response history | No general conversation store | Current responses are request-scoped unless represented elsewhere by the user |
| Application settings | Yes | Stored as bounded JSON values |
| Audit events | Yes | Body-free request and authorization metadata |

The public demo must receive sanitized input only. Not retaining the original file does not make
persisted raw line text non-sensitive.

## Data Model

```mermaid
erDiagram
    ANALYSIS_RUN ||--o{ LOG_SOURCE : describes
    ANALYSIS_RUN ||--o{ RAW_LOG_LINE : contains
    ANALYSIS_RUN ||--o{ PARSED_EVENT : produces
    ANALYSIS_RUN ||--o{ FINDING : detects
    ANALYSIS_RUN ||--o{ INCIDENT : correlates
    ANALYSIS_RUN ||--o{ ENTITY : indexes
    ANALYSIS_RUN ||--o{ ANALYST_NOTE : receives
```

Global application settings and audit events are stored independently of a single analysis.
Foreign-key columns express ownership, while several relationship lists such as finding IDs and
incident IDs are stored as JSON because this is a bounded single-instance model rather than a
general analytics warehouse.

## Record Responsibilities

| Record | Responsibility |
| --- | --- |
| `AnalysisRunRecord` | Analysis identity, parser, counts, filename, and creation time |
| `LogSourceRecord` | Source name, type, parser, and status |
| `RawLogLineRecord` | Original evidence text, line number, hash, and source |
| `ParsedEventRecord` | Normalized event fields and raw-line link |
| `FindingRecord` | Rule result, MITRE mapping, time range, and evidence IDs |
| `IncidentRecord` | Grouped finding IDs, entities, timeline, score, and status |
| `EntityRecord` | Derived IP/user/host/service/path/domain/container index |
| `AnalystNoteRecord` | Human observation, decision, follow-up, or false-positive note |
| `AppSettingRecord` | Retention and assistant configuration |
| `AuditEventRecord` | Actor, role, path, action, outcome, and request ID without request body |

The SQLAlchemy schema is defined in `apps/api/tracehawk_api/database.py`. Conversion between domain
models and database records is in `services/persistence.py`.

## Analysis Identity And Write Behavior

An analysis ID is derived from filename and source identity unless an explicit case ID is supplied.
`persist_analysis` merges the run and its related records, derives entities, and commits the
transaction. The returned `AnalysisResult` receives the durable `analysis_id`.

The current design favors deterministic demo and local workflow behavior. It is not a versioned
event-sourcing model: reprocessing the same identity can merge current records rather than retain an
immutable history of every computation.

## Evidence Provenance

Traceability relies on linked identifiers:

```text
AnalysisRun
→ ParsedEvent.raw_line_id
→ RawLogLine.id + content_hash + raw_text

Finding
→ evidence_line_ids[]
→ RawLogLine records

CrossSourceLink
→ source and target event IDs
→ source and target raw line IDs
```

SHA-256 detects content changes when the same evidence is compared later. It does not establish who
collected the source, whether the source host was trustworthy, or a legal chain of custody.

## Read Paths

The persistence service supports:

- listing recent analysis summaries;
- reopening a complete `AnalysisResult`;
- listing incidents globally or by analysis;
- listing and resolving entities;
- reading and changing analyst notes;
- exporting analysis state before retention;
- producing reports from reopened evidence.

Read ordering is explicit so incident priority, timelines, evidence lines, and entity risk remain
stable for the UI.

## Retention

Retention is a deliberate operation with preview and apply stages. Current modes can remove full
analyses or purge raw evidence while keeping higher-level findings, depending on the saved setting.

Before applying retention:

1. inspect the preview counts and affected analysis IDs;
2. export the analysis if it must be preserved;
3. create a verified SQLite backup when recovery is required;
4. apply the selected mode;
5. verify that the remaining detail matches the chosen policy.

Purging raw lines makes exact evidence unavailable even if findings remain. Reports generated after
that operation cannot recreate deleted raw text.

## Backup And Restore

`services/database_backup.py` and `tools/sqlite_backup.py` use SQLite's online backup mechanism and
integrity checks rather than copying a potentially active database file blindly. The operational
procedure is summarized in [operations](operations.md); the complete source repository also carries
the operator-only backup and restore runbook.

Backups contain sensitive persisted evidence and must receive the same access and retention
protection as the primary database.

## Security And Privacy Invariants

- The original upload is not stored as a durable file.
- Persisted raw text is still sensitive evidence.
- Audit records do not store request bodies or uploaded log content.
- Notes are attributed by the server-side authenticated identity in protected mode.
- Retention changes require the configured privileged role.
- Exports and backups are explicit operations and may outlive database retention.
- Report redaction does not modify the underlying stored evidence.

## Implementation And Verification Map

| Concern | Implementation | Verification |
| --- | --- | --- |
| Schema and sessions | `database.py` | health and API tests |
| Analysis persistence and reopen | `services/persistence.py` | `test_analyze_api.py` |
| Entities | `services/entities.py`, `persistence.py` | `test_case_bundle_api.py` |
| Notes | `services/notes.py`, `routers/notes.py` | `test_analyze_api.py`, `test_auth_gate.py` |
| Retention preview/apply/export | `services/retention.py` | retention cases in `test_analyze_api.py` |
| Backup | `services/database_backup.py`, `tools/sqlite_backup.py` | `test_sqlite_backup_tool.py` |
| Audit | `services/audit.py`, `routers/audit.py` | `test_auth_gate.py` |
| Report redaction | `services/reports/redaction.py` | report and case-bundle tests |

## Failure Modes

- Disk exhaustion or an unwritable database path makes readiness fail.
- A process crash during a transaction can prevent the current write while SQLite protects committed
  transactions.
- Purged evidence cannot be reconstructed from hashes.
- Backups can expose the same evidence as the live database if copied insecurely.
- JSON relationship lists are not suitable for high-volume analytical joins.
- Multiple replicas would not share the in-process rate limit or safely coordinate one local file.

## Production Gaps

Before broader production use, the persistence layer needs at least:

- explicit schema migrations and upgrade/rollback tests;
- a documented immutable-history policy;
- encryption and key-management decisions for stored evidence and backups;
- centralized audit and rate-limit state for multiple replicas;
- tested concurrency, corruption recovery, and disaster-recovery objectives;
- retention enforcement scheduled independently of interactive API calls.
