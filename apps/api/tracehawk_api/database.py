from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Engine,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    event,
    inspect,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from tracehawk_api.config import settings


class Base(DeclarativeBase):
    pass


class AnalysisRunRecord(Base):
    __tablename__ = "analysis_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source_id: Mapped[str] = mapped_column(String(255), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    parser: Mapped[str] = mapped_column(String(80))
    raw_line_count: Mapped[int] = mapped_column(Integer)
    parsed_event_count: Mapped[int] = mapped_column(Integer)
    finding_count: Mapped[int] = mapped_column(Integer)
    incident_count: Mapped[int] = mapped_column(Integer)
    sources: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    cross_source_links: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    case_quality: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    evidence_integrity: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )


class LogSourceRecord(Base):
    __tablename__ = "log_sources"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analysis_runs.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    source_type: Mapped[str] = mapped_column(String(40))
    parser_type: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(40), default="stopped")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class RawLogLineRecord(Base):
    __tablename__ = "raw_log_lines"

    id: Mapped[str] = mapped_column(String(512), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analysis_runs.id"), index=True)
    source_id: Mapped[str] = mapped_column(String(255), index=True)
    line_number: Mapped[int] = mapped_column(Integer)
    raw_text: Mapped[str] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    timestamp_observed: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ParsedEventRecord(Base):
    __tablename__ = "parsed_events"

    id: Mapped[str] = mapped_column(String(512), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analysis_runs.id"), index=True)
    source_id: Mapped[str] = mapped_column(String(255), index=True)
    raw_line_id: Mapped[str] = mapped_column(String(512), index=True)
    event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    event_type: Mapped[str] = mapped_column(String(120), index=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    service: Mapped[str | None] = mapped_column(String(120), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    message: Mapped[str] = mapped_column(Text)
    normalized_fields: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class FindingRecord(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(512), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analysis_runs.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(255), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(40), index=True)
    confidence: Mapped[str] = mapped_column(String(40))
    summary: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    mitre: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_count: Mapped[int] = mapped_column(Integer)
    evidence_line_ids: Mapped[list[str]] = mapped_column(JSON, default=list)


class IncidentRecord(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(512), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analysis_runs.id"), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(40), index=True)
    status: Mapped[str] = mapped_column(String(40), index=True)
    summary: Mapped[str] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    score: Mapped[int] = mapped_column(Integer, index=True)
    finding_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    entities: Mapped[list[str]] = mapped_column(JSON, default=list)
    timeline: Mapped[list[str]] = mapped_column(JSON, default=list)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    score_breakdown: Mapped[dict[str, int]] = mapped_column(JSON, default=dict)
    score_rationale: Mapped[list[str]] = mapped_column(JSON, default=list)


class EntityRecord(Base):
    __tablename__ = "entities"

    id: Mapped[str] = mapped_column(String(512), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analysis_runs.id"), index=True)
    entity_type: Mapped[str] = mapped_column(String(40), index=True)
    value: Mapped[str] = mapped_column(String(512), index=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, index=True, default=0)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    source_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    finding_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    incident_ids: Mapped[list[str]] = mapped_column(JSON, default=list)


class AnalystNoteRecord(Base):
    __tablename__ = "analyst_notes"

    id: Mapped[str] = mapped_column(String(512), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analysis_runs.id"), index=True)
    incident_id: Mapped[str] = mapped_column(String(512), index=True)
    body: Mapped[str] = mapped_column(Text)
    note_type: Mapped[str] = mapped_column(String(40), index=True)
    author: Mapped[str] = mapped_column(String(120), default="local")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class AppSettingRecord(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(120), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class AuditEventRecord(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )
    actor: Mapped[str] = mapped_column(String(255), index=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    role: Mapped[str] = mapped_column(String(40), index=True)
    auth_mode: Mapped[str] = mapped_column(String(40))
    method: Mapped[str] = mapped_column(String(16))
    path: Mapped[str] = mapped_column(String(512), index=True)
    action: Mapped[str] = mapped_column(String(600))
    status_code: Mapped[int] = mapped_column(Integer, index=True)
    outcome: Mapped[str] = mapped_column(String(40), index=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True)


def _sqlite_url(path: str) -> str:
    db_path = Path(path)
    if db_path != Path(":memory:"):
        db_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{db_path}"


def _create_database_engine(path: str) -> Engine:
    database_engine = create_engine(
        _sqlite_url(path),
        connect_args={"check_same_thread": False},
    )
    event.listen(database_engine, "connect", _configure_sqlite_connection)
    return database_engine


def _configure_sqlite_connection(dbapi_connection: Any, _: Any) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
    finally:
        cursor.close()


engine = _create_database_engine(settings.db_path)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
_migration_lock = Lock()
_migrated_database_url: str | None = None


def configure_database(path: str) -> None:
    """Rebind the process database, primarily for isolated tests and controlled migrations."""
    global engine, _migrated_database_url

    previous_engine = engine
    engine = _create_database_engine(path)
    SessionLocal.configure(bind=engine)
    _migrated_database_url = None
    previous_engine.dispose()


def init_db() -> None:
    migrate_database("head")


def migrate_database(revision: str = "head") -> None:
    """Upgrade the active database and adopt the current pre-Alembic schema safely."""
    global _migrated_database_url

    database_url = engine.url.render_as_string(hide_password=False)
    if revision == "head" and _migrated_database_url == database_url:
        return

    from alembic import command
    from alembic.config import Config

    config_path = Path(__file__).resolve().parents[1] / "alembic.ini"
    migration_config = Config(config_path)
    migration_config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    with _migration_lock, engine.begin() as connection:
        migration_config.attributes["connection"] = connection
        schema = inspect(connection)
        tables = set(schema.get_table_names())
        application_tables = set(Base.metadata.tables)
        existing_application_tables = tables & application_tables
        if existing_application_tables and "alembic_version" not in tables:
            if _schema_matches_metadata(schema, omitted_columns=_V071_OMITTED_COLUMNS):
                command.stamp(migration_config, "0001_current_schema")
                command.upgrade(migration_config, revision)
            elif _schema_matches_metadata(
                schema, omitted_columns=_EVIDENCE_INTEGRITY_COLUMNS
            ):
                command.stamp(migration_config, "0002_case_integrity")
                command.upgrade(migration_config, revision)
            elif _schema_matches_metadata(schema):
                command.stamp(migration_config, "0003_evidence_integrity")
                command.upgrade(migration_config, revision)
            else:
                raise RuntimeError(
                    "Refusing to adopt an unversioned database whose tables or columns do not "
                    "match a recognized TraceHawk schema. Restore a backup or migrate it explicitly."
                )
        else:
            command.upgrade(migration_config, revision)
    _migrated_database_url = database_url if revision == "head" else None


_CASE_INTEGRITY_COLUMNS = {
    "analysis_runs": {"sources", "cross_source_links", "case_quality"},
    "incidents": {"score_breakdown", "score_rationale"},
}
_EVIDENCE_INTEGRITY_COLUMNS = {"analysis_runs": {"evidence_integrity"}}
_V071_OMITTED_COLUMNS = {
    table: set(columns)
    for table, columns in _CASE_INTEGRITY_COLUMNS.items()
}
_V071_OMITTED_COLUMNS["analysis_runs"].update(
    _EVIDENCE_INTEGRITY_COLUMNS["analysis_runs"]
)


def _schema_matches_metadata(
    schema: Any,
    *,
    omitted_columns: dict[str, set[str]] | None = None,
) -> bool:
    omitted_columns = omitted_columns or {}
    tables = set(schema.get_table_names())
    expected_tables = set(Base.metadata.tables)
    if not expected_tables <= tables:
        return False
    for table_name, table in Base.metadata.tables.items():
        expected_columns = {column.name for column in table.columns} - omitted_columns.get(
            table_name, set()
        )
        actual_columns = {column["name"] for column in schema.get_columns(table_name)}
        if actual_columns != expected_columns:
            return False
    return True


def downgrade_database(revision: str = "base") -> None:
    """Downgrade explicitly; callers must take a backup before using this on retained evidence."""
    global _migrated_database_url

    from alembic import command
    from alembic.config import Config

    config_path = Path(__file__).resolve().parents[1] / "alembic.ini"
    migration_config = Config(config_path)
    database_url = engine.url.render_as_string(hide_password=False)
    migration_config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    with _migration_lock, engine.begin() as connection:
        migration_config.attributes["connection"] = connection
        command.downgrade(migration_config, revision)
    _migrated_database_url = None


def get_session() -> Iterator[Session]:
    init_db()
    with SessionLocal() as session:
        yield session
