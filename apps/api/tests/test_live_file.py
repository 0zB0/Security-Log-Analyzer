from pathlib import Path

from fastapi.testclient import TestClient

from tracehawk_api.main import app


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
        assert latest["incidents"][0]["title"] == "Possible SSH credential compromise"
        assert "T1136.001" in latest["incidents"][0]["mitre_techniques"]


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

        latest = _receive_until_raw_line_count(websocket, 6, initial=initial)

        assert latest["parser"] == "json_log"
        assert latest["raw_line_count"] == 6
        assert latest["parsed_event_count"] == 6
        assert latest["finding_count"] == 2


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
