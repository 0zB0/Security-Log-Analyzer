#!/usr/bin/env python3
from __future__ import annotations

import base64
import tempfile
from io import BytesIO
from pathlib import Path

from fastapi.testclient import TestClient
from pypdf import PdfReader
from tracehawk_api.config import settings
from tracehawk_api.database import configure_database
from tracehawk_api.main import app


def main() -> int:
    original_path = settings.db_path
    with tempfile.TemporaryDirectory() as tmpdir:
        configure_database(str(Path(tmpdir) / "tracehawk-smoke.db"))
        try:
            return _run_smoke()
        finally:
            configure_database(original_path)


def _run_smoke() -> int:
    client = TestClient(app)
    with open("packages/test-scenarios/auth-ssh-compromise/input.log", "rb") as handle:
        response = client.post(
            "/api/analyze/upload",
            files={"file": ("ssh-compromise.log", handle, "text/plain")},
        )
    response.raise_for_status()
    analysis = response.json()
    payload = {
        "incident": analysis["incidents"][0],
        "findings": analysis["findings"],
        "evidence": analysis["evidence"],
        "assistant_summary": "Local assistant smoke summary.",
    }

    for report_format in ("markdown", "html", "pdf"):
        report_response = client.post(f"/api/reports/incident?format={report_format}", json=payload)
        report_response.raise_for_status()
        report = report_response.json()
        assert report["format"] == report_format
        assert report["filename"]
        assert report["content"]
        if report_format == "pdf":
            pdf_bytes = base64.b64decode(report["content"])
            reader = PdfReader(BytesIO(pdf_bytes))
            assert len(reader.pages) >= 1
        else:
            assert "Possible SSH credential compromise" in report["content"]
            assert "Local assistant smoke summary." in report["content"]
        print(f"report_{report_format}=ok")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
