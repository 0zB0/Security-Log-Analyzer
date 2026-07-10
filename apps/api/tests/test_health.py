import json

from fastapi.testclient import TestClient

from tracehawk_api.config import settings
from tracehawk_api.main import app
from tracehawk_api.observability import JsonLogFormatter


def test_health() -> None:
    client = TestClient(app)
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["mode"] == "local-only"


def test_liveness_and_readiness_expose_operational_state() -> None:
    client = TestClient(app)

    live = client.get("/api/health/live")
    ready = client.get("/api/health/ready")

    assert live.status_code == 200
    assert live.json()["status"] == "alive"
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"
    assert ready.json()["checks"]["database"] == "ok"
    assert ready.json()["checks"]["rules"] == "ok"
    assert ready.json()["checks"]["rule_count"] >= 65


def test_readiness_fails_when_database_check_fails(monkeypatch) -> None:
    class BrokenSession:
        def __enter__(self):
            raise OSError("database unavailable")

        def __exit__(self, *_args) -> None:
            return None

    monkeypatch.setattr("tracehawk_api.observability.SessionLocal", BrokenSession)
    client = TestClient(app)

    response = client.get("/api/health/ready")

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    assert response.json()["checks"]["database"] == "error:OSError"


def test_metrics_are_prometheus_compatible_and_use_route_templates() -> None:
    client = TestClient(app)

    client.get("/api/analyze/runs/does-not-exist")
    response = client.get("/metrics")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain; version=0.0.4")
    assert "tracehawk_build_info" in response.text
    assert "tracehawk_http_requests_total" in response.text
    assert 'route="/api/analyze/runs/{analysis_id}"' in response.text
    assert "does-not-exist" not in response.text


def test_metrics_require_admin_in_azure_mode(monkeypatch) -> None:
    monkeypatch.setattr(settings, "auth_mode", "azure_easy_auth")
    monkeypatch.setattr(settings, "allowed_auth_emails", "viewer@example.com")
    monkeypatch.setattr(settings, "auth_admin_emails", "")
    monkeypatch.setattr(settings, "auth_analyst_emails", "")
    monkeypatch.setattr(settings, "auth_viewer_emails", "viewer@example.com")
    client = TestClient(app)

    response = client.get(
        "/metrics",
        headers={"x-ms-client-principal-name": "viewer@example.com"},
    )

    assert response.status_code == 403
    assert "admin role" in response.json()["detail"]


def test_json_log_formatter_emits_machine_readable_fields() -> None:
    import logging

    record = logging.LogRecord(
        name="tracehawk.http",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="http_request_completed",
        args=(),
        exc_info=None,
    )
    record.request_id = "request-proof"
    record.method = "POST"
    record.route = "/api/analyze/upload"
    record.status_code = 200
    record.duration_ms = 12.5
    record.role = "analyst"

    payload = json.loads(JsonLogFormatter().format(record))

    assert payload["event"] == "http_request_completed"
    assert payload["request_id"] == "request-proof"
    assert payload["route"] == "/api/analyze/upload"
    assert payload["role"] == "analyst"
    assert "body" not in payload


def test_version_exposes_public_build_metadata(monkeypatch) -> None:
    monkeypatch.setattr("tracehawk_api.main.settings.build_commit", "abc1234")
    monkeypatch.setattr("tracehawk_api.main.settings.runtime_mode", "azure-container-apps")
    monkeypatch.setattr("tracehawk_api.main.settings.llm_provider", "mock")
    client = TestClient(app)

    response = client.get("/api/version")

    assert response.status_code == 200
    assert response.json() == {
        "app": "tracehawk",
        "api_version": "0.7.0",
        "release": "v0.7.0",
        "build_commit": "abc1234",
        "runtime_mode": "azure-container-apps",
        "llm_provider": "mock",
    }
