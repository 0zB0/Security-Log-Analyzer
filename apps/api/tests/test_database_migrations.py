from pathlib import Path

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
        assert connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one() == "0001_current_schema"


def test_existing_pre_alembic_database_is_adopted_without_losing_records(tmp_path: Path) -> None:
    path = tmp_path / "legacy.db"
    database.configure_database(str(path))
    database.Base.metadata.create_all(bind=database.engine)
    with database.SessionLocal() as session:
        session.add(
            AnalysisRunRecord(
                id="analysis:legacy",
                source_id="source:legacy",
                filename="sanitized.log",
                parser="linux_auth",
                raw_line_count=1,
                parsed_event_count=1,
                finding_count=0,
                incident_count=0,
            )
        )
        session.commit()

    database.init_db()

    with database.SessionLocal() as session:
        record = session.scalar(
            select(AnalysisRunRecord).where(AnalysisRunRecord.id == "analysis:legacy")
        )
        assert record is not None
        assert record.filename == "sanitized.log"
    assert "alembic_version" in inspect(database.engine).get_table_names()


def test_baseline_downgrade_and_reupgrade_are_explicitly_supported(tmp_path: Path) -> None:
    path = tmp_path / "roundtrip.db"
    database.configure_database(str(path))
    database.init_db()

    database.downgrade_database("base")
    assert "analysis_runs" not in inspect(database.engine).get_table_names()

    database.migrate_database("head")
    assert "analysis_runs" in inspect(database.engine).get_table_names()
