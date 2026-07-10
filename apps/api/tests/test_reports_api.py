from base64 import b64decode
from io import BytesIO
from pathlib import Path

from fastapi.testclient import TestClient
from pypdf import PdfReader

from tracehawk_api.main import app


ROOT = Path(__file__).resolve().parents[3]


def test_incident_markdown_report_includes_findings_evidence_and_assistant_summary() -> None:
    client = TestClient(app)
    sample = ROOT / "packages/sample-data/auth/ssh-bruteforce.log"

    with sample.open("rb") as file:
        analysis_response = client.post(
            "/api/analyze/upload",
            files={"file": ("ssh-bruteforce.log", file, "text/plain")},
        )

    assert analysis_response.status_code == 200
    analysis = analysis_response.json()
    report_response = client.post(
        "/api/reports/incident",
        json={
            "incident": analysis["incidents"][0],
            "findings": analysis["findings"],
            "evidence": analysis["evidence"],
            "assistant_summary": "Mock local assistant summary.",
        },
    )

    assert report_response.status_code == 200
    body = report_response.json()
    content = body["content"]

    assert body["format"] == "markdown"
    assert body["filename"].endswith(".md")
    assert "# TraceHawk Incident Report: Possible SSH credential compromise" in content
    assert "## Local Assistant Summary" in content
    assert "Mock local assistant summary." in content
    assert "## Scoring Rationale" in content
    assert "Sequence Quality" in content
    assert "SSH failures are followed by a successful login" in content
    assert "ssh-bruteforce-001" in content
    assert "T1110.001" in content
    assert "Jul 05 10:02:11 lab sshd" in content
    assert "SHA-256" in content
    assert "No cloud service is required" in content


def test_incident_markdown_report_can_redact_sensitive_values() -> None:
    client = TestClient(app)
    sample = ROOT / "packages/sample-data/auth/ssh-bruteforce.log"

    with sample.open("rb") as file:
        analysis_response = client.post(
            "/api/analyze/upload",
            files={"file": ("ssh-bruteforce.log", file, "text/plain")},
        )

    analysis = analysis_response.json()
    report_response = client.post(
        "/api/reports/incident",
        json={
            "incident": analysis["incidents"][0],
            "findings": analysis["findings"],
            "evidence": analysis["evidence"],
            "assistant_summary": "Source 198.51.100.10 used admin.",
            "redaction": {"enabled": True},
        },
    )

    assert report_response.status_code == 200
    content = report_response.json()["content"]

    assert "198.51.100.10" not in content
    assert "admin" not in content
    assert "[REDACTED_IP]" in content
    assert "[REDACTED_USER]" in content
    assert "SHA-256" in content
    assert "Sensitive values were redacted" in content


def test_incident_html_report_renders_downloadable_html() -> None:
    client = TestClient(app)
    sample = ROOT / "packages/sample-data/auth/ssh-bruteforce.log"

    with sample.open("rb") as file:
        analysis_response = client.post(
            "/api/analyze/upload",
            files={"file": ("ssh-bruteforce.log", file, "text/plain")},
        )

    analysis = analysis_response.json()
    report_response = client.post(
        "/api/reports/incident?format=html",
        json={
            "incident": analysis["incidents"][0],
            "findings": analysis["findings"],
            "evidence": analysis["evidence"],
            "assistant_summary": "Summary with <unsafe> marker.",
        },
    )

    assert report_response.status_code == 200
    body = report_response.json()
    content = body["content"]

    assert body["format"] == "html"
    assert body["filename"].endswith(".html")
    assert "<!doctype html>" in content
    assert "TraceHawk Incident Report: Possible SSH credential compromise" in content
    assert "Summary with &lt;unsafe&gt; marker." in content
    assert "Scoring Rationale" in content
    assert "Sequence quality" in content
    assert "<unsafe>" not in content
    assert "Jul 05 10:02:11 lab sshd" in content


def test_incident_pdf_report_renders_readable_pdf() -> None:
    client = TestClient(app)
    sample = ROOT / "packages/sample-data/auth/ssh-bruteforce.log"

    with sample.open("rb") as file:
        analysis_response = client.post(
            "/api/analyze/upload",
            files={"file": ("ssh-bruteforce.log", file, "text/plain")},
        )

    analysis = analysis_response.json()
    report_response = client.post(
        "/api/reports/incident?format=pdf",
        json={
            "incident": analysis["incidents"][0],
            "findings": analysis["findings"],
            "evidence": analysis["evidence"],
            "assistant_summary": "PDF smoke summary.",
        },
    )

    assert report_response.status_code == 200
    body = report_response.json()
    pdf_bytes = b64decode(body["content"])
    reader = PdfReader(BytesIO(pdf_bytes))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)

    assert body["format"] == "pdf"
    assert body["filename"].endswith(".pdf")
    assert pdf_bytes.startswith(b"%PDF")
    assert len(reader.pages) >= 2
    assert "TraceHawk Incident Report" in text
    assert "Possible SSH credential compromise" in text
    assert "PDF smoke summary." in text
    assert "Scoring Rationale" in text
    assert "Sequence quality" in text
    assert "Report Integrity Notes" in text


def test_incident_report_formats_preserve_core_fields_and_redaction_parity() -> None:
    client = TestClient(app)
    sample = ROOT / "packages/sample-data/auth/ssh-bruteforce.log"

    with sample.open("rb") as file:
        analysis_response = client.post(
            "/api/analyze/upload",
            files={"file": ("ssh-bruteforce.log", file, "text/plain")},
        )

    analysis = analysis_response.json()
    rendered: dict[str, str] = {}
    for report_format in ("markdown", "html", "pdf"):
        response = client.post(
            f"/api/reports/incident?format={report_format}",
            json={
                "incident": analysis["incidents"][0],
                "findings": analysis["findings"],
                "evidence": analysis["evidence"],
                "assistant_summary": "Source 198.51.100.10 used admin.",
                "redaction": {"enabled": True},
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["format"] == report_format
        content = body["content"]
        if report_format == "pdf":
            reader = PdfReader(BytesIO(b64decode(content)))
            content = "\n".join(page.extract_text() or "" for page in reader.pages)
        rendered[report_format] = content

    for report_format, content in rendered.items():
        assert "198.51.100.10" not in content, report_format
        assert " admin" not in content.lower(), report_format
        assert "[REDACTED_IP]" in content, report_format
        assert "[REDACTED_USER]" in content, report_format
        assert "Possible SSH credential compromise" in content, report_format
        assert "Scoring Rationale" in content, report_format
