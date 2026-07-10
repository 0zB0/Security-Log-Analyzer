import hashlib
import json
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

from fastapi.testclient import TestClient

from tracehawk_api.config import settings
from tracehawk_api.main import app


ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT / "tools/sqlite_backup.py"


def test_backup_verify_and_offline_restore(tmp_path: Path) -> None:
    database = tmp_path / "tracehawk.db"
    backup = tmp_path / "backups/tracehawk.db"
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("CREATE TABLE proof (value TEXT NOT NULL)")
        connection.execute("INSERT INTO proof VALUES ('original')")
        connection.commit()

    backup_result = _run("backup", "--source", database, "--destination", backup)
    verify_result = _run("verify", "--backup", backup)

    with closing(sqlite3.connect(database)) as connection:
        connection.execute("UPDATE proof SET value = 'changed'")
        connection.commit()

    restore_result = _run(
        "restore",
        "--backup",
        backup,
        "--destination",
        database,
        "--offline-confirmed",
    )
    with closing(sqlite3.connect(database)) as connection:
        value = connection.execute("SELECT value FROM proof").fetchone()[0]

    assert backup_result["status"] == "ok"
    assert len(backup_result["sha256"]) == 64
    assert verify_result["integrity"] == "ok"
    assert restore_result["status"] == "ok"
    assert restore_result["previous_database_backup"]
    assert value == "original"


def test_restore_requires_explicit_offline_confirmation(tmp_path: Path) -> None:
    database = tmp_path / "tracehawk.db"
    backup = tmp_path / "backup.db"
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("CREATE TABLE proof (value TEXT)")
        connection.commit()
    _run("backup", "--source", database, "--destination", backup)

    process = subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "restore",
            "--backup",
            str(backup),
            "--destination",
            str(database),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert process.returncode != 0
    assert "--offline-confirmed" in process.stderr


def test_admin_backup_endpoint_returns_verified_sqlite(monkeypatch, tmp_path: Path) -> None:
    database = tmp_path / "tracehawk.db"
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("CREATE TABLE proof (value TEXT)")
        connection.execute("INSERT INTO proof VALUES ('exported')")
        connection.commit()
    monkeypatch.setattr(settings, "db_path", str(database))

    response = TestClient(app).post("/api/operations/backup")

    assert response.status_code == 200
    assert response.content.startswith(b"SQLite format 3\x00")
    assert response.headers["content-type"].startswith("application/vnd.sqlite3")
    assert response.headers["x-tracehawk-sha256"] == hashlib.sha256(response.content).hexdigest()


def _run(command: str, *args: object) -> dict[str, object]:
    process = subprocess.run(
        [sys.executable, str(TOOL), command, *(str(arg) for arg in args)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(process.stdout)
