# Case Study: Hermetic Test Database Isolation

## Problem

The backend test suite inherited the runtime default `tracehawk.db`. A local database created by a
Docker/root process was readable but not writable by the developer account, causing persistence
tests to fail with `sqlite3.OperationalError: attempt to write a readonly database`. Even when
writable, tests could mutate developer investigation state.

## Reproduction

With an existing non-writable repository-root database, the unisolated suite reached 119 passing
tests and 36 persistence-related failures. The common failure was an attempted update of
`analysis_runs`; the detection code itself was not the cause.

## Decision

Add a supported process-level database reconfiguration seam and an autouse pytest fixture that:

- selects a unique `tmp_path` database for every test;
- rebinds the shared SQLAlchemy sessionmaker so existing imports observe the new engine;
- initializes the migrated schema before test code executes;
- restores the runtime binding after the test.

An environment-variable wrapper around the complete pytest process was rejected because it would
still share state between tests and would not protect developers who ran a focused test directly.

## Implementation And Failing-Test Boundary

- `database.configure_database` swaps the engine and reconfigures `SessionLocal`.
- `apps/api/tests/conftest.py` owns per-test setup.
- `test_database_isolation.py` asserts that the active path is temporary and the schema exists.
- upload-security tests exposed a second dependency: they queried counts before an application
  lifespan had created tables. Initializing the schema in the fixture fixed that contract directly.

## Verification

```bash
.venv/bin/python -m pytest apps/api/tests/test_database_isolation.py \
  apps/api/tests/test_upload_security.py -q
make test
```

Expected current result: the complete suite passes without a `TRACEHAWK_DB_PATH` override while an
unwritable repository-root database remains untouched.

## Residual Risk

The process still uses one global engine/sessionmaker and is intentionally single-instance. The
fixture protects pytest isolation; it is not a multi-tenant database-routing implementation.
