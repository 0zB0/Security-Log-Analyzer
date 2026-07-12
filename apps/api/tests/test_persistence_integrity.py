from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from tracehawk_api import database
from tracehawk_api.database import (
    EntityRecord,
    FindingRecord,
    IncidentRecord,
    ParsedEventRecord,
    RawLogLineRecord,
)
from tracehawk_api.models.domain import RawLogLine
from tracehawk_api.services.analysis import AnalysisResult, analyze_text
from tracehawk_api.services.case_bundle import CaseBundleInput, analyze_case_bundle
from tracehawk_api.services.ingest import build_raw_lines_from_text
from tracehawk_api.services.persistence import get_analysis_result, persist_analysis


ROOT = Path(__file__).resolve().parents[3]
RULES = ROOT / "packages/rules"


def test_sqlite_foreign_keys_are_enforced() -> None:
    with database.engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1

    orphan = RawLogLineRecord(
        id="raw:orphan",
        analysis_id="analysis:missing",
        source_id="source:missing",
        line_number=1,
        raw_text="orphan",
        content_hash="0" * 64,
        timestamp_observed=RawLogLine(
            id="raw:timestamp",
            source_id="source:missing",
            line_number=1,
            raw_text="orphan",
            content_hash="0" * 64,
        ).timestamp_observed,
    )
    with database.SessionLocal() as session:
        session.add(orphan)
        with pytest.raises(IntegrityError):
            session.commit()


def test_case_round_trip_preserves_sources_links_quality_and_scoring() -> None:
    inputs = [
        CaseBundleInput(
            filename="auth.log",
            text=(ROOT / "packages/sample-data/auth/ssh-bruteforce.log").read_text(),
        ),
        CaseBundleInput(
            filename="web.log",
            text=(ROOT / "packages/sample-data/nginx/probing.log").read_text(),
        ),
    ]
    case = analyze_case_bundle(inputs, rules_root=RULES, case_name="round-trip-case")

    with database.SessionLocal() as session:
        persisted = persist_analysis(
            session,
            case.result,
            case.raw_lines,
            "round-trip-case.bundle",
        )
        restored = get_analysis_result(session, persisted.analysis_id or "")

    assert restored is not None
    assert restored.sources == persisted.sources
    assert restored.cross_source_links == persisted.cross_source_links
    assert restored.case_quality == persisted.case_quality
    assert [incident.score_breakdown for incident in restored.incidents] == [
        incident.score_breakdown for incident in persisted.incidents
    ]
    assert [incident.score_rationale for incident in restored.incidents] == [
        incident.score_rationale for incident in persisted.incidents
    ]


def test_reanalysis_replaces_previous_children_instead_of_leaving_stale_records() -> None:
    text = (ROOT / "packages/sample-data/auth/ssh-bruteforce.log").read_text()
    first = analyze_text(text, "repeat.log", RULES)
    raw_lines = build_raw_lines_from_text(text, first.source_id)
    analysis_id = "analysis:repeat"

    with database.SessionLocal() as session:
        persist_analysis(session, first, raw_lines, "repeat.log", analysis_id=analysis_id)
        empty = AnalysisResult(
            source_id=first.source_id,
            parser=first.parser,
            raw_line_count=0,
            parsed_event_count=0,
            finding_count=0,
            incident_count=0,
        )
        persist_analysis(session, empty, [], "repeat.log", analysis_id=analysis_id)

        for record_type in (
            RawLogLineRecord,
            ParsedEventRecord,
            FindingRecord,
            IncidentRecord,
            EntityRecord,
        ):
            count = session.scalar(
                select(func.count())
                .select_from(record_type)
                .where(record_type.analysis_id == analysis_id)
            )
            assert count == 0
