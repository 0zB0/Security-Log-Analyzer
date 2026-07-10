import base64
import json

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from tracehawk_api.auth import validate_auth_configuration
from tracehawk_api.config import settings
from tracehawk_api.main import app


OWNER = "owner@example.com"
VIEWER = "viewer@example.com"
ANALYST = "analyst@example.com"


def _configure_azure_auth(monkeypatch) -> None:
    monkeypatch.setattr(settings, "auth_mode", "azure_easy_auth")
    monkeypatch.setattr(
        settings,
        "allowed_auth_emails",
        f"{OWNER},{VIEWER},{ANALYST}",
    )
    monkeypatch.setattr(settings, "auth_admin_emails", OWNER)
    monkeypatch.setattr(settings, "auth_analyst_emails", ANALYST)
    monkeypatch.setattr(settings, "auth_viewer_emails", VIEWER)


def _headers(email: str, *, request_id: str | None = None) -> dict[str, str]:
    headers = {"x-ms-client-principal-name": email}
    if request_id:
        headers["x-request-id"] = request_id
    return headers


def test_auth_status_is_public_in_azure_mode(monkeypatch) -> None:
    _configure_azure_auth(monkeypatch)
    client = TestClient(app)

    response = client.get("/auth/status")

    assert response.status_code == 200
    assert response.json() == {
        "authenticated": False,
        "email": None,
        "allowed": False,
        "role": None,
        "auth_mode": "azure_easy_auth",
        "allowlist_enabled": True,
        "local_admin": False,
    }


def test_api_requires_auth_in_azure_mode(monkeypatch) -> None:
    _configure_azure_auth(monkeypatch)
    client = TestClient(app)

    response = client.get("/api/analyze/runs")

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required."


def test_viewer_can_read_but_cannot_start_analysis(monkeypatch) -> None:
    _configure_azure_auth(monkeypatch)
    client = TestClient(app)

    read_response = client.get("/api/analyze/runs", headers=_headers(VIEWER))
    settings_response = client.get("/api/retention/settings", headers=_headers(VIEWER))
    write_response = client.get("/api/analyze/demo", headers=_headers(VIEWER))

    assert read_response.status_code == 200
    assert settings_response.status_code == 200
    assert write_response.status_code == 403
    assert "analyst role" in write_response.json()["detail"]


def test_analyst_can_analyze_but_cannot_change_admin_settings(monkeypatch) -> None:
    _configure_azure_auth(monkeypatch)
    client = TestClient(app)

    analysis_response = client.get("/api/analyze/demo", headers=_headers(ANALYST))
    analysis = analysis_response.json()
    note_response = client.post(
        f"/api/notes/incidents/{analysis['incidents'][0]['id']}",
        headers=_headers(ANALYST),
        json={
            "analysis_id": analysis["analysis_id"],
            "body": "Role attribution proof.",
            "author": "spoofed-author",
        },
    )
    settings_response = client.put(
        "/api/retention/settings",
        headers=_headers(ANALYST),
        json={"mode": "keep_last_n_days", "days": 30, "delete_reports_with_runs": False},
    )
    cleanup_response = client.delete(
        f"/api/notes/{note_response.json()['id']}",
        headers=_headers(ANALYST),
    )

    assert analysis_response.status_code == 200
    assert note_response.status_code == 200
    assert note_response.json()["author"] == ANALYST
    assert cleanup_response.status_code == 200
    assert settings_response.status_code == 403
    assert "admin role" in settings_response.json()["detail"]


def test_admin_can_change_settings_and_read_audit_trail(monkeypatch) -> None:
    _configure_azure_auth(monkeypatch)
    client = TestClient(app)
    request_id = "rbac-admin-settings-proof"

    update_response = client.put(
        "/api/retention/settings",
        headers=_headers(OWNER, request_id=request_id),
        json={"mode": "keep_last_n_days", "days": 30, "delete_reports_with_runs": False},
    )
    audit_response = client.get("/api/audit/events?limit=500", headers=_headers(OWNER))

    assert update_response.status_code == 200
    assert update_response.headers["x-request-id"] == request_id
    assert audit_response.status_code == 200
    event = next(item for item in audit_response.json() if item["request_id"] == request_id)
    assert event["actor"] == OWNER
    assert event["role"] == "admin"
    assert event["action"] == "PUT /api/retention/settings"
    assert event["outcome"] == "allowed"


def test_denied_email_is_audited_without_request_content(monkeypatch) -> None:
    _configure_azure_auth(monkeypatch)
    client = TestClient(app)
    request_id = "rbac-denied-account-proof"

    denied_response = client.get(
        "/api/analyze/runs",
        headers=_headers("other@example.com", request_id=request_id),
    )
    audit_response = client.get("/api/audit/events?limit=500", headers=_headers(OWNER))

    assert denied_response.status_code == 403
    event = next(item for item in audit_response.json() if item["request_id"] == request_id)
    assert event["actor"] == "other@example.com"
    assert event["role"] == "anonymous"
    assert event["path"] == "/api/analyze/runs"
    assert event["outcome"] == "denied"
    assert "body" not in event


def test_encoded_easy_auth_claims_are_supported(monkeypatch) -> None:
    _configure_azure_auth(monkeypatch)
    client = TestClient(app)
    payload = base64.b64encode(
        json.dumps(
            {"claims": [{"typ": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "val": VIEWER}]}
        ).encode("utf-8")
    ).decode("ascii")

    response = client.get("/auth/status", headers={"x-ms-client-principal": payload})

    assert response.status_code == 200
    assert response.json()["authenticated"] is True
    assert response.json()["role"] == "viewer"


def test_local_mode_ignores_spoofed_azure_header(monkeypatch) -> None:
    monkeypatch.setattr(settings, "auth_mode", "disabled")
    monkeypatch.setattr(settings, "allowed_auth_emails", OWNER)
    monkeypatch.setattr(settings, "auth_admin_emails", OWNER)
    client = TestClient(app)

    response = client.get("/auth/status", headers=_headers(OWNER))

    assert response.status_code == 200
    assert response.json()["authenticated"] is False
    assert response.json()["email"] is None
    assert response.json()["role"] == "admin"
    assert response.json()["local_admin"] is True


def test_viewer_cannot_open_live_websocket(monkeypatch) -> None:
    _configure_azure_auth(monkeypatch)
    client = TestClient(app)

    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/api/live/file?path=/tmp/missing", headers=_headers(VIEWER)):
            pass

    assert exc.value.code == 4403


def test_azure_mode_rejects_role_binding_outside_allowlist(monkeypatch) -> None:
    _configure_azure_auth(monkeypatch)
    monkeypatch.setattr(settings, "auth_analyst_emails", "unknown@example.com")

    with pytest.raises(RuntimeError, match="subset of ALLOWED_AUTH_EMAILS"):
        validate_auth_configuration()
