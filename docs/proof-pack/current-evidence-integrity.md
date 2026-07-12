# Current Evidence Integrity Proof

## Claim

TraceHawk verifies unpurged evidence hashes and analysis-graph references before persistence. A
browser-submitted live snapshot must also carry a valid process-local server attestation. These
controls detect client-side modification; they do not establish sensor identity or legal chain of
custody.

## Implemented Boundary

```text
server live source
→ canonical snapshot projection
→ process-local HMAC
→ browser round trip
→ constant-time HMAC verification
→ SHA-256 recomputation
→ counter, source, event, finding, incident, and link validation
→ SQLite transaction
```

Uploads and case bundles enter at the SHA-256 and graph-validation step because their analysis is
already produced inside the server process.

## Negative Evidence

Automated tests reject:

- missing live attestation;
- modified live evidence after attestation;
- raw text whose digest no longer matches;
- incorrect event, finding, or incident counters;
- events that point to unknown raw lines;
- findings that point to unknown evidence;
- incidents that point to unknown findings;
- partial or unknown unversioned database schemas.

The persistence tamper test first stores a valid analysis, attempts an invalid replacement, and then
reopens the original analysis. This proves validation occurs before destructive replacement.

## Retention Boundary

`purge_raw_keep_findings` intentionally replaces raw text with `[PURGED_RAW_LOG]` while retaining
the original digest as a one-way commitment. The analysis integrity state changes to `raw_purged`;
the digest must not be described as the hash of the placeholder.

## Reproduction

```bash
.venv/bin/python -m pytest \
  apps/api/tests/test_database_migrations.py \
  apps/api/tests/test_persistence_integrity.py \
  apps/api/tests/test_analyze_api.py \
  apps/api/tests/test_live_file.py \
  apps/api/tests/test_live_interface.py -q
.venv/bin/python -m ruff check apps/api/tracehawk_api apps/api/migrations apps/api/tests tools
npm --prefix apps/web run test
npm --prefix apps/web run build
```

Current targeted result on 2026-07-12:

```text
34 passed
11 frontend test files, 31 tests passed
TypeScript and Vite production build passed
```

## Residual Limits

- The HMAC key is process-local; snapshots emitted before restart are intentionally rejected.
- The attestation proves that the backend emitted the snapshot, not that the monitored host or
  interface was trustworthy.
- Authorized operators can still purge or export evidence according to their role.
- SQLite and the single-replica boundary remain unchanged.
