from pathlib import Path

import pytest
from sqlalchemy import inspect, select

from tracehawk_api import database
from tracehawk_api.database import AnalysisRunRecord


def test_blank_database_upgrades_to_alembic_head(tmp_path: Path) -> None:
    path = tmp_path / "blank.db"
    database.configure_database(str(path))

    database.init_db()

    tables = set(inspect(database.engine).get_table_names())
    assert {"alembic_version", "analysis_runs", "raw_log_lines", "audit_events"} <= tables
    assert tables - {"alembic_version"} == set(database.Base.metadata.tables)
    schema = inspect(database.engine)
    for table_name, table in database.Base.metadata.tables.items():
        migrated_columns = {column["name"] for column in schema.get_columns(table_name)}
        assert migrated_columns == set(table.columns.keys())
    with database.engine.connect() as connection:
        assert (
            connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
            == "0003_evidence_integrity"
        )


def test_existing_pre_alembic_database_is_adopted_without_losing_records(tmp_path: Path) -> None:
    path = tmp_path / "legacy.db"
    database.configure_database(str(path))
    database.migrate_database("0001_current_schema")
    with database.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE alembic_version")
        connection.exec_driver_sql(
            """
            INSERT INTO analysis_runs (
                id, source_id, filename, parser, raw_line_count, parsed_event_count,
                finding_count, incident_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "analysis:legacy",
                "source:legacy",
                "sanitized.log",
                "linux_auth",
                1,
                1,
                0,
                0,
                "2026-07-12 12:00:00",
            ),
        )

    database.init_db()

    with database.SessionLocal() as session:
        record = session.scalar(
            select(AnalysisRunRecord).where(AnalysisRunRecord.id == "analysis:legacy")
        )
        assert record is not None
        assert record.filename == "sanitized.log"
    assert "alembic_version" in inspect(database.engine).get_table_names()


def test_partial_unversioned_database_is_rejected_instead_of_stamped(tmp_path: Path) -> None:
    path = tmp_path / "partial.db"
    database.configure_database(str(path))
    with database.engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE analysis_runs (id VARCHAR(64) PRIMARY KEY)")

    with pytest.raises(RuntimeError, match="Refusing to adopt an unversioned database"):
        database.init_db()

    assert "alembic_version" not in inspect(database.engine).get_table_names()


def test_existing_v080_database_is_adopted_at_integrity_migration(tmp_path: Path) -> None:
    path = tmp_path / "v080.db"
    database.configure_database(str(path))
    database.migrate_database("0002_case_integrity")
    with database.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE alembic_version")

    database.init_db()

    schema = inspect(database.engine)
    analysis_columns = {
        column["name"] for column in schema.get_columns("analysis_runs")
    }
    assert "evidence_integrity" in analysis_columns
    with database.engine.connect() as connection:
        assert (
            connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
            == "0003_evidence_integrity"
        )


def test_baseline_downgrade_and_reupgrade_are_explicitly_supported(tmp_path: Path) -> None:
    path = tmp_path / "roundtrip.db"
    database.configure_database(str(path))
    database.init_db()

    database.downgrade_database("base")
    assert "analysis_runs" not in inspect(database.engine).get_table_names()

    database.migrate_database("head")
    assert "analysis_runs" in inspect(database.engine).get_table_names()
