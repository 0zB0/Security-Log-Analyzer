import os
import subprocess
import sys
from pathlib import Path
from time import sleep

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import func, select
from starlette.websockets import WebSocketDisconnect

from tracehawk_api.config import Settings, settings, validate_deployment_configuration
from tracehawk_api.database import AnalysisRunRecord, SessionLocal
from tracehawk_api.main import app
from tracehawk_api import auth
from tracehawk_api.routers import public_demo
from tracehawk_api.security import (
    PUBLIC_DEMO_CONCURRENCY,
    PUBLIC_DEMO_RATE_LIMITER,
)


ROOT = Path(__file__).resolve().parents[3]
SAMPLE = ROOT / "packages/sample-data/auth/ssh-bruteforce.log"


@pytest.fixture(autouse=True)
def reset_public_demo_guards() -> None:
    PUBLIC_DEMO_RATE_LIMITER.clear()
    PUBLIC_DEMO_CONCURRENCY.clear()
    yield
    PUBLIC_DEMO_RATE_LIMITER.clear()
    PUBLIC_DEMO_CONCURRENCY.clear()


def _enable_public_demo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "deployment_profile", "public_demo")
    monkeypatch.setattr(settings, "auth_mode", "disabled")
    monkeypatch.setattr(settings, "llm_provider", "mock")


def test_public_demo_allows_only_tutorial_video_static_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_public_demo(monkeypatch)
    assert auth.is_public_path("/tutorial-videos/manifest.json") is True
    assert auth.is_public_path("/tutorial-videos/evidence.mp4") is True
    assert auth.is_disabled_public_demo_path("/tutorial-videos/evidence.mp4") is False
    assert auth.is_disabled_public_demo_path("/private-video.mp4") is True


def _payload() -> dict[str, str]:
    return {
        "filename": "auth.log",
        "text": SAMPLE.read_text(encoding="utf-8"),
    }


def _analysis_run_count() -> int:
    with SessionLocal() as session:
        return int(session.scalar(select(func.count()).select_from(AnalysisRunRecord)) or 0)


def test_public_process_never_creates_its_configured_database(tmp_path: Path) -> None:
    database_path = tmp_path / "must-not-exist.db"
    environment = os.environ.copy()
    environment.update(
        {
            "TRACEHAWK_DEPLOYMENT_PROFILE": "public_demo",
            "TRACEHAWK_AUTH_MODE": "disabled",
            "TRACEHAWK_LLM_PROVIDER": "mock",
            "TRACEHAWK_DB_PATH": str(database_path),
        }
    )
    script = """
from fastapi.testclient import TestClient
from tracehawk_api.main import app

with TestClient(app) as client:
    response = client.post('/api/public-demo/analyze/sample/auth-ssh-compromise')
    assert response.status_code == 200, response.text
    assert response.json()['analysis']['analysis_id'] is None
"""

    subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )

    assert not database_path.exists()


def test_status_exposes_disabled_private_profile_without_authentication() -> None:
    response = TestClient(app).get("/api/public-demo/status")

    assert response.status_code == 200
    assert response.json()["enabled"] is False
    assert response.json()["profile"] == "private"
    assert response.headers["cache-control"] == "no-store, max-age=0"


def test_private_profile_does_not_expose_public_analysis() -> None:
    response = TestClient(app).post("/api/public-demo/analyze", json=_payload())

    assert response.status_code == 404
    assert response.json()["detail"] == "Public demo is not enabled."


def test_public_demo_analyzes_without_persisting(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_public_demo(monkeypatch)
    before = _analysis_run_count()

    response = TestClient(app).post("/api/public-demo/analyze", json=_payload())

    assert response.status_code == 200
    body = response.json()
    assert body["ephemeral"] is True
    assert body["stored"] is False
    assert body["external_ai"] is False
    assert body["analysis"]["analysis_id"] is None
    assert body["analysis"]["parser"] == "linux_auth"
    assert body["analysis"]["entities"]
    assert body["analysis"]["evidence_integrity"]["status"] == "verified"
    assert _analysis_run_count() == before
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["expires"] == "0"


def test_public_sample_is_stateless(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_public_demo(monkeypatch)
    before = _analysis_run_count()

    response = TestClient(app).post(
        "/api/public-demo/analyze/sample/auth-ssh-compromise"
    )

    assert response.status_code == 200
    assert response.json()["analysis"]["parser"] == "linux_auth"
    assert _analysis_run_count() == before


def test_public_demo_renders_markdown_without_persistence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_public_demo(monkeypatch)
    before = _analysis_run_count()
    analysis_response = TestClient(app).post(
        "/api/public-demo/analyze/sample/auth-ssh-compromise"
    )
    analysis = analysis_response.json()["analysis"]

    response = TestClient(app).post(
        "/api/public-demo/report/case",
        json={"analysis": analysis, "assistant_summary": "must not be included"},
    )

    assert response.status_code == 200
    assert response.json()["format"] == "markdown"
    assert "must not be included" not in response.json()["content"]
    assert _analysis_run_count() == before
    assert response.headers["cache-control"] == "no-store, max-age=0"


@pytest.mark.parametrize(
    ("payload", "status", "detail"),
    [
        ({"filename": "../auth.log", "text": "test"}, 400, "must not contain a path"),
        ({"filename": "auth.exe", "text": "test"}, 415, "Unsupported public demo"),
        ({"filename": "auth.log", "text": "test\x00line"}, 400, "text logs only"),
    ],
)
def test_public_demo_rejects_unsafe_payloads(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, str],
    status: int,
    detail: str,
) -> None:
    _enable_public_demo(monkeypatch)

    response = TestClient(app).post("/api/public-demo/analyze", json=payload)

    assert response.status_code == status
    assert detail in response.json()["detail"]


def test_public_demo_rejects_byte_and_line_overflow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_public_demo(monkeypatch)
    monkeypatch.setattr(settings, "public_demo_max_bytes", 4)
    byte_response = TestClient(app).post(
        "/api/public-demo/analyze",
        json={"filename": "auth.log", "text": "12345"},
    )

    monkeypatch.setattr(settings, "public_demo_max_bytes", 100)
    monkeypatch.setattr(settings, "public_demo_max_lines", 1)
    line_response = TestClient(app).post(
        "/api/public-demo/analyze",
        json={"filename": "auth.log", "text": "one\ntwo"},
    )

    assert byte_response.status_code == 413
    assert "byte limit" in byte_response.json()["detail"]
    assert line_response.status_code == 413
    assert "line limit" in line_response.json()["detail"]


def test_public_demo_has_independent_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_public_demo(monkeypatch)
    monkeypatch.setattr(settings, "public_demo_rate_limit_requests", 1)

    first = TestClient(app).post("/api/public-demo/analyze", json=_payload())
    second = TestClient(app).post("/api/public-demo/analyze", json=_payload())

    assert first.status_code == 200
    assert second.status_code == 429
    assert "Public demo rate limit" in second.json()["detail"]


def test_public_demo_rate_limit_uses_azure_supplied_rightmost_client_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_public_demo(monkeypatch)
    monkeypatch.setattr(settings, "runtime_mode", "azure-container-apps")
    monkeypatch.setattr(settings, "public_demo_rate_limit_requests", 1)
    client = TestClient(app)

    first = client.post(
        "/api/public-demo/analyze",
        json=_payload(),
        headers={"X-Forwarded-For": "spoofed.invalid, 198.51.100.10"},
    )
    second_client = client.post(
        "/api/public-demo/analyze",
        json=_payload(),
        headers={"X-Forwarded-For": "spoofed.invalid, 198.51.100.11"},
    )
    spoof_attempt = client.post(
        "/api/public-demo/analyze",
        json=_payload(),
        headers={"X-Forwarded-For": "203.0.113.99, 198.51.100.10"},
    )

    assert first.status_code == 200
    assert second_client.status_code == 200
    assert spoof_attempt.status_code == 429


def test_public_demo_rejects_when_concurrency_is_full(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_public_demo(monkeypatch)
    monkeypatch.setattr(settings, "public_demo_max_concurrency", 1)
    assert PUBLIC_DEMO_CONCURRENCY.try_acquire(1)

    response = TestClient(app).post("/api/public-demo/analyze", json=_payload())

    assert response.status_code == 429
    assert "busy" in response.json()["detail"]


def test_public_demo_enforces_execution_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_public_demo(monkeypatch)
    monkeypatch.setattr(settings, "public_demo_timeout_seconds", 0.001)
    monkeypatch.setattr(public_demo, "_analyze_stateless", lambda *_: sleep(0.05))

    response = TestClient(app).post("/api/public-demo/analyze", json=_payload())

    assert response.status_code == 504
    assert "execution timeout" in response.json()["detail"]


def test_public_profile_blocks_private_http_and_websocket_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_public_demo(monkeypatch)
    client = TestClient(app)

    private_response = client.get("/api/analyze/runs")
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/api/live/file?path=/tmp/missing"):
            pass

    assert private_response.status_code == 404
    assert exc.value.code == 4404


def test_public_profile_requires_disabled_auth_and_mock_llm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_public_demo(monkeypatch)
    validate_deployment_configuration()

    monkeypatch.setattr(settings, "auth_mode", "azure_easy_auth")
    with pytest.raises(RuntimeError, match="AUTH_MODE=disabled"):
        validate_deployment_configuration()

    monkeypatch.setattr(settings, "auth_mode", "disabled")
    monkeypatch.setattr(settings, "llm_provider", "ollama")
    with pytest.raises(RuntimeError, match="LLM_PROVIDER=mock"):
        validate_deployment_configuration()


def test_unknown_deployment_profile_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "deployment_profile", "unknown")

    with pytest.raises(RuntimeError, match="Unsupported TRACEHAWK_DEPLOYMENT_PROFILE"):
        validate_deployment_configuration()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("public_demo_max_bytes", 512 * 1024 + 1),
        ("public_demo_max_lines", 20_001),
        ("public_demo_rate_limit_requests", 6),
        ("public_demo_rate_limit_window_seconds", 599),
        ("public_demo_max_concurrency", 3),
        ("public_demo_timeout_seconds", 10.1),
        ("public_demo_session_timeout_seconds", 1_801),
    ],
)
def test_public_safety_settings_can_only_be_tightened(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        Settings(**{field: value})


def test_public_profile_rejects_unsafe_extension_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_public_demo(monkeypatch)
    monkeypatch.setattr(settings, "public_demo_allowed_extensions", ".log,.xml")

    with pytest.raises(RuntimeError, match="non-empty subset"):
        validate_deployment_configuration()
