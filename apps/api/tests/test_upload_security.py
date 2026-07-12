from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from tracehawk_api.config import settings
from tracehawk_api.database import AnalysisRunRecord, SessionLocal
from tracehawk_api.main import app
from tracehawk_api.security import RATE_LIMITER


ROOT = Path(__file__).resolve().parents[3]
SAMPLE = ROOT / "packages/sample-data/auth/ssh-bruteforce.log"


def test_upload_accepts_payload_at_exact_byte_limit(monkeypatch) -> None:
    payload = SAMPLE.read_bytes()
    monkeypatch.setattr(settings, "max_upload_bytes", len(payload))
    client = TestClient(app)

    response = client.post(
        "/api/analyze/upload",
        files={"file": ("auth.log", payload, "text/plain")},
    )

    assert response.status_code == 200
    assert response.json()["parser"] == "linux_auth"


def test_upload_rejects_payload_over_byte_limit_without_persisting(monkeypatch) -> None:
    payload = SAMPLE.read_bytes()
    monkeypatch.setattr(settings, "max_upload_bytes", len(payload) - 1)
    before = _analysis_run_count()
    client = TestClient(app)

    response = client.post(
        "/api/analyze/upload",
        files={"file": ("auth.log", payload, "text/plain")},
    )

    assert response.status_code == 413
    assert "byte limit" in response.json()["detail"]
    assert _analysis_run_count() == before


def test_request_body_limit_rejects_oversized_multipart_before_analysis(monkeypatch) -> None:
    monkeypatch.setattr(settings, "max_upload_bytes", 10)
    payload = b"x" * (300 * 1024)
    client = TestClient(app)

    response = client.post(
        "/api/analyze/upload",
        files={"file": ("oversized.log", payload, "text/plain")},
    )

    assert response.status_code == 413
    assert "Request body exceeds" in response.json()["detail"]


def test_upload_rejects_invalid_utf8_without_persisting() -> None:
    before = _analysis_run_count()
    client = TestClient(app)

    response = client.post(
        "/api/analyze/upload",
        files={"file": ("invalid.log", b"valid\n\xff\xfe", "text/plain")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Uploaded log must be UTF-8 text."
    assert _analysis_run_count() == before


def test_upload_rejects_unsupported_extension() -> None:
    client = TestClient(app)

    response = client.post(
        "/api/analyze/upload",
        files={"file": ("capture.exe", SAMPLE.read_bytes(), "application/octet-stream")},
    )

    assert response.status_code == 415
    assert "Unsupported upload extension" in response.json()["detail"]


def test_upload_rejects_excessive_line_count(monkeypatch) -> None:
    monkeypatch.setattr(settings, "max_upload_lines", 2)
    client = TestClient(app)

    response = client.post(
        "/api/analyze/upload",
        files={"file": ("lines.log", b"one\ntwo\nthree\n", "text/plain")},
    )

    assert response.status_code == 413
    assert "line limit" in response.json()["detail"]


def test_case_bundle_rejects_too_many_files(monkeypatch) -> None:
    monkeypatch.setattr(settings, "max_case_files", 1)
    payload = SAMPLE.read_bytes()
    client = TestClient(app)

    response = client.post(
        "/api/analyze/case-bundle",
        files=[
            ("files", ("one.log", payload, "text/plain")),
            ("files", ("two.log", payload, "text/plain")),
        ],
    )

    assert response.status_code == 413
    assert "file limit" in response.json()["detail"]


def test_case_bundle_rejects_total_bytes(monkeypatch) -> None:
    payload = SAMPLE.read_bytes()
    monkeypatch.setattr(settings, "max_upload_bytes", len(payload) + 100)
    monkeypatch.setattr(settings, "max_case_total_bytes", len(payload) * 2 - 1)
    client = TestClient(app)

    response = client.post(
        "/api/analyze/case-bundle",
        files=[
            ("files", ("one.log", payload, "text/plain")),
            ("files", ("two.log", payload, "text/plain")),
        ],
    )

    assert response.status_code == 413
    assert "total byte limit" in response.json()["detail"]


def test_expensive_endpoint_rate_limit(monkeypatch) -> None:
    monkeypatch.setattr(settings, "rate_limit_per_minute", 2)
    RATE_LIMITER.clear()
    payload = SAMPLE.read_bytes()
    client = TestClient(app)

    responses = [
        client.post(
            "/api/analyze/upload",
            files={"file": (f"{index}.log", payload, "text/plain")},
        )
        for index in range(3)
    ]

    assert [response.status_code for response in responses] == [200, 200, 429]
    assert int(responses[-1].headers["retry-after"]) >= 1
    RATE_LIMITER.clear()


def test_local_rate_limit_ignores_spoofed_azure_identity(monkeypatch) -> None:
    monkeypatch.setattr(settings, "auth_mode", "disabled")
    monkeypatch.setattr(settings, "rate_limit_per_minute", 1)
    RATE_LIMITER.clear()
    payload = SAMPLE.read_bytes()
    client = TestClient(app)

    first = client.post(
        "/api/analyze/upload",
        headers={"x-ms-client-principal-name": "spoof-a@example.com"},
        files={"file": ("first.log", payload, "text/plain")},
    )
    second = client.post(
        "/api/analyze/upload",
        headers={"x-ms-client-principal-name": "spoof-b@example.com"},
        files={"file": ("second.log", payload, "text/plain")},
    )

    assert [first.status_code, second.status_code] == [200, 429]
    RATE_LIMITER.clear()


def test_security_headers_are_attached_to_api_responses() -> None:
    response = TestClient(app).get("/api/health")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert "object-src 'none'" in response.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def _analysis_run_count() -> int:
    with SessionLocal() as session:
        return int(session.scalar(select(func.count()).select_from(AnalysisRunRecord)) or 0)
