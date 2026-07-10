from __future__ import annotations

import hashlib
import os
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path


def create_backup(source: Path, destination: Path, *, force: bool = False) -> dict[str, object]:
    source = source.resolve()
    destination = destination.resolve()
    if not source.is_file():
        raise FileNotFoundError(f"Source database does not exist: {source}")
    if source == destination:
        raise ValueError("Backup destination must differ from the source database.")
    if destination.exists() and not force:
        raise FileExistsError(f"Backup already exists: {destination}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    try:
        with closing(sqlite3.connect(f"file:{source}?mode=ro", uri=True)) as source_db:
            with closing(sqlite3.connect(temporary)) as backup_db:
                source_db.backup(backup_db)
        _require_integrity(temporary)
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)

    return {
        "operation": "backup",
        "status": "ok",
        "source": str(source),
        "destination": str(destination),
        "bytes": destination.stat().st_size,
        "sha256": sha256_file(destination),
        "created_at": datetime.now(UTC).isoformat(),
    }


def verify_backup(backup: Path) -> dict[str, object]:
    backup = backup.resolve()
    if not backup.is_file():
        raise FileNotFoundError(f"Backup does not exist: {backup}")
    integrity = _require_integrity(backup)
    return {
        "operation": "verify",
        "status": "ok",
        "backup": str(backup),
        "bytes": backup.stat().st_size,
        "sha256": sha256_file(backup),
        "integrity": integrity,
    }


def restore_backup(
    backup: Path,
    destination: Path,
    *,
    offline_confirmed: bool = False,
) -> dict[str, object]:
    if not offline_confirmed:
        raise RuntimeError("Restore requires --offline-confirmed after stopping all app writers.")
    backup = backup.resolve()
    destination = destination.resolve()
    if backup == destination:
        raise ValueError("Restore source and destination must differ.")
    _require_integrity(backup)
    destination.parent.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    previous = destination.with_name(f"{destination.name}.pre-restore-{timestamp}.bak")
    if destination.exists():
        create_backup(destination, previous)

    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.restore.tmp")
    temporary.unlink(missing_ok=True)
    try:
        with closing(sqlite3.connect(f"file:{backup}?mode=ro", uri=True)) as backup_db:
            with closing(sqlite3.connect(temporary)) as restored_db:
                backup_db.backup(restored_db)
        _require_integrity(temporary)
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)

    return {
        "operation": "restore",
        "status": "ok",
        "backup": str(backup),
        "destination": str(destination),
        "sha256": sha256_file(destination),
        "previous_database_backup": str(previous) if previous.exists() else None,
        "restored_at": datetime.now(UTC).isoformat(),
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_integrity(path: Path) -> str:
    with closing(sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)) as database:
        result = database.execute("PRAGMA quick_check").fetchone()
    integrity = str(result[0]) if result else "missing_result"
    if integrity != "ok":
        raise ValueError(f"SQLite integrity check failed for {path}: {integrity}")
    return integrity
