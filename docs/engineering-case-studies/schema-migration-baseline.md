# Case Study: Adopting Existing SQLite Evidence Into Alembic

## Problem

`Base.metadata.create_all()` can create missing tables but cannot version or transform a database.
Once TraceHawk retained investigations, raw evidence, notes, entities, settings, and audit records,
future schema edits could no longer safely assume an empty local database.

## Design Constraints

- existing v0.7.1 databases have no `alembic_version` table;
- recreating current tables over such a database would fail or risk evidence;
- Docker and local startup must use the same revision path;
- the product remains SQLite and single-replica;
- rollback must not be advertised as data-preserving when the baseline downgrade drops the schema.

## Decision

Introduce `0001_current_schema` as the adoption baseline:

1. a blank database upgrades normally and creates the current metadata plus `alembic_version`;
2. a database containing the recognized current schema but no version table is stamped at the
   baseline without recreating tables;
3. subsequent startup upgrades to `head`;
4. explicit downgrade exists for structural verification, with backup/restore documented as the
   data-preserving rollback mechanism.

## Verification

`test_database_migrations.py` covers:

- blank database → head;
- pre-Alembic database with a sanitized saved analysis → adopted head with record preserved;
- head → base → head structural round trip.

```bash
.venv/bin/python -m pytest apps/api/tests/test_database_migrations.py \
  apps/api/tests/test_sqlite_backup_tool.py -q
make test
```

## Residual Risk

The baseline freezes explicit table, column, constraint, and index operations generated from the
v0.7.1 SQLAlchemy metadata; it does not import live application metadata. The next model change must
use a separate explicit Alembic revision and a field-level data-transform fixture. Production
downgrade of a data-bearing baseline remains destructive; restore a verified backup instead.
