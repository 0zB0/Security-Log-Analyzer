from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tracehawk_api.config import settings
from tracehawk_api.main import app
from tracehawk_api.services import live as live_service
from tracehawk_api.services.live import LiveFileTailer


ROOT = Path(__file__).resolve().parents[3]


def test_live_file_websocket_streams_snapshots_from_existing_file() -> None:
    client = TestClient(app)
    sample = ROOT / "packages/sample-data/auth/ssh-bruteforce.log"

    with client.websocket_connect(
        f"/api/live/file?path={sample}&start_at_end=false"
    ) as websocket:
        initial = websocket.receive_json()
        assert initial["message_type"] == "snapshot"
        assert initial["status"] == "active"
        assert initial["raw_line_count"] == 0
        assert initial["parser"] is None
        assert len(initial["live_snapshot_attestation"]) == 64

        websocket.send_json({"action": "pause"})
        paused = _receive_until_status(websocket, "paused")
        assert paused["status"] == "paused"

        websocket.send_json({"action": "resume"})
        resumed = _receive_until_status(websocket, "active")
        assert resumed["status"] == "active"

        latest = _receive_until_raw_line_count(websocket, 12, initial=resumed)

        assert latest["parser"] == "linux_auth"
        assert latest["raw_line_count"] == 12
        assert latest["parsed_event_count"] == 12
        assert latest["finding_count"] == 4
        assert latest["incident_count"] == 1
        assert latest["live_retention"] == {
            "raw_line_capacity": settings.live_max_raw_lines,
            "event_capacity": settings.live_max_events,
            "total_raw_lines": 12,
            "total_parsed_events": 12,
            "retained_raw_lines": 12,
            "retained_parsed_events": 12,
            "dropped_raw_lines": 0,
            "dropped_parsed_events": 0,
        }
        assert latest["incidents"][0]["title"] == "Possible SSH credential compromise"
        assert "T1136.001" in latest["incidents"][0]["mitre_techniques"]
        assert len(latest["live_snapshot_attestation"]) == 64


def test_live_folder_websocket_streams_snapshots_from_existing_folder(tmp_path: Path) -> None:
    client = TestClient(app)
    source = ROOT / "packages/sample-data/json/security-events.jsonl"
    folder = tmp_path / "logs"
    folder.mkdir()
    (folder / "security-events.log").write_text(source.read_text(), encoding="utf-8")

    with client.websocket_connect(
        f"/api/live/folder?path={folder}&pattern=*.log&start_at_end=false"
    ) as websocket:
        initial = websocket.receive_json()
        assert initial["message_type"] == "snapshot"
        assert initial["status"] == "active"
        assert len(initial["live_snapshot_attestation"]) == 64

        latest = _receive_until_raw_line_count(websocket, 6, initial=initial)

        assert latest["parser"] == "json_log"
        assert latest["raw_line_count"] == 6
        assert latest["parsed_event_count"] == 6
        assert latest["finding_count"] == 2


def test_live_file_retention_is_bounded_and_keeps_graph_references_valid() -> None:
    sample = ROOT / "packages/sample-data/auth/ssh-bruteforce.log"
    tailer = LiveFileTailer(
        sample,
        ROOT / "packages/rules",
        max_raw_lines=5,
        max_events=2,
    )

    snapshot = None
    for line_number, raw_text in enumerate(sample.read_text().splitlines()[:8], start=1):
        snapshot = tailer._process_line(line_number, raw_text)

    assert snapshot is not None
    assert snapshot.raw_line_count == 5
    assert snapshot.parsed_event_count == 2
    assert snapshot.live_retention.total_raw_lines == 8
    assert snapshot.live_retention.total_parsed_events == 8
    assert snapshot.live_retention.dropped_raw_lines == 3
    assert snapshot.live_retention.dropped_parsed_events == 6
    evidence_ids = {line.id for line in snapshot.evidence}
    assert all(event.raw_line_id in evidence_ids for event in snapshot.events)
    assert all(
        evidence_id in evidence_ids
        for finding in snapshot.findings
        for evidence_id in finding.evidence_line_ids
    )


def test_live_source_loads_rule_and_pattern_assets_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    real_load_rules = live_service.load_rules

    def counted_load_rules(path: Path):
        nonlocal calls
        calls += 1
        return real_load_rules(path)

    monkeypatch.setattr(live_service, "load_rules", counted_load_rules)
    sample = ROOT / "packages/sample-data/auth/ssh-bruteforce.log"
    tailer = LiveFileTailer(sample, ROOT / "packages/rules")

    for line_number, raw_text in enumerate(sample.read_text().splitlines()[:4], start=1):
        tailer._process_line(line_number, raw_text)

    assert calls == 1


def _receive_until_status(websocket, status: str) -> dict:
    for _ in range(20):
        message = websocket.receive_json()
        if message["status"] == status:
            return message
    raise AssertionError(f"Did not receive status {status}.")


def _receive_until_raw_line_count(websocket, count: int, *, initial: dict | None = None) -> dict:
    if initial is not None and initial["raw_line_count"] >= count:
        return initial
    for _ in range(50):
        message = websocket.receive_json()
        if message["raw_line_count"] >= count:
            return message
    raise AssertionError(f"Did not receive raw line count {count}.")
