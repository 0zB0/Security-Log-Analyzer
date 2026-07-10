from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException
from starlette.background import BackgroundTask
from starlette.responses import FileResponse

from tracehawk_api.config import settings
from tracehawk_api.services.database_backup import create_backup


router = APIRouter(prefix="/api/operations", tags=["operations"])


@router.post("/backup", response_class=FileResponse)
def download_database_backup() -> FileResponse:
    if settings.db_path == ":memory:":
        raise HTTPException(status_code=409, detail="In-memory databases cannot be exported.")
    source = Path(settings.db_path)
    temporary = tempfile.NamedTemporaryFile(prefix="tracehawk-backup-", suffix=".db", delete=False)
    temporary_path = Path(temporary.name)
    temporary.close()
    temporary_path.unlink(missing_ok=True)
    try:
        metadata = create_backup(source, temporary_path)
    except (FileNotFoundError, ValueError, OSError) as exc:
        temporary_path.unlink(missing_ok=True)
        raise HTTPException(status_code=503, detail="Database backup failed.") from exc

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return FileResponse(
        temporary_path,
        media_type="application/vnd.sqlite3",
        filename=f"tracehawk-{timestamp}.db",
        headers={"X-TraceHawk-SHA256": str(metadata["sha256"])},
        background=BackgroundTask(temporary_path.unlink, missing_ok=True),
    )
