from __future__ import annotations

import base64
import json
import logging
import re
from dataclasses import dataclass
from typing import Literal, Mapping
from uuid import uuid4

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from tracehawk_api.config import settings


Role = Literal["viewer", "analyst", "admin"]
AUTH_MODE_DISABLED = "disabled"
AUTH_MODE_AZURE = "azure_easy_auth"
SUPPORTED_AUTH_MODES = {AUTH_MODE_DISABLED, AUTH_MODE_AZURE}
ROLE_RANK: dict[Role, int] = {"viewer": 10, "analyst": 20, "admin": 30}
LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class Principal:
    subject: str
    email: str | None
    role: Role
    auth_mode: str
    authenticated: bool

    @property
    def audit_actor(self) -> str:
        return self.email or self.subject


@dataclass(frozen=True)
class AuthenticationResult:
    principal: Principal | None
    email: str | None
    error: Literal["missing", "not_allowed"] | None = None


def validate_auth_configuration() -> None:
    if settings.auth_mode not in SUPPORTED_AUTH_MODES:
        supported = ", ".join(sorted(SUPPORTED_AUTH_MODES))
        raise RuntimeError(f"Unsupported TRACEHAWK_AUTH_MODE. Expected one of: {supported}.")
    if settings.auth_mode == AUTH_MODE_AZURE and not allowed_emails():
        raise RuntimeError("Azure Easy Auth mode requires at least one ALLOWED_AUTH_EMAILS entry.")
    if settings.auth_mode == AUTH_MODE_AZURE:
        allowed = allowed_emails()
        role_sets = {
            "admin": _email_set(settings.auth_admin_emails),
            "analyst": _email_set(settings.auth_analyst_emails),
            "viewer": _email_set(settings.auth_viewer_emails),
        }
        bound = set().union(*role_sets.values())
        if unknown := bound - allowed:
            raise RuntimeError(
                "Role bindings must be a subset of ALLOWED_AUTH_EMAILS: "
                + ", ".join(sorted(unknown))
            )
        memberships: dict[str, list[str]] = {}
        for role, emails in role_sets.items():
            for email in emails:
                memberships.setdefault(email, []).append(role)
        if overlaps := {email: roles for email, roles in memberships.items() if len(roles) > 1}:
            details = ", ".join(
                f"{email} ({'/'.join(sorted(roles))})" for email, roles in sorted(overlaps.items())
            )
            raise RuntimeError(f"Each identity must have only one role binding: {details}")


def allowed_emails() -> set[str]:
    return _email_set(settings.allowed_auth_emails)


def authenticate_headers(headers: Mapping[str, str]) -> AuthenticationResult:
    if settings.auth_mode not in SUPPORTED_AUTH_MODES:
        raise RuntimeError("Unsupported TRACEHAWK_AUTH_MODE.")
    if settings.auth_mode == AUTH_MODE_DISABLED:
        return AuthenticationResult(
            principal=Principal(
                subject="local",
                email=None,
                role="admin",
                auth_mode=AUTH_MODE_DISABLED,
                authenticated=False,
            ),
            email=None,
        )

    email = authenticated_email(headers)
    if email is None:
        return AuthenticationResult(principal=None, email=None, error="missing")
    if email not in allowed_emails():
        return AuthenticationResult(principal=None, email=email, error="not_allowed")
    return AuthenticationResult(
        principal=Principal(
            subject=f"azure:{email}",
            email=email,
            role=role_for_email(email),
            auth_mode=AUTH_MODE_AZURE,
            authenticated=True,
        ),
        email=email,
    )


def authenticated_email(headers: Mapping[str, str]) -> str | None:
    principal_name = headers.get("x-ms-client-principal-name")
    if principal_name and "@" in principal_name:
        return principal_name.strip().lower()

    encoded_principal = headers.get("x-ms-client-principal")
    if not encoded_principal:
        return None

    try:
        payload = base64.b64decode(encoded_principal, validate=True).decode("utf-8")
        principal = json.loads(payload)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None

    for claim in principal.get("claims", []):
        claim_type = str(claim.get("typ", "")).lower()
        claim_value = str(claim.get("val", "")).strip().lower()
        if "email" in claim_type and "@" in claim_value:
            return claim_value
        if claim_type.endswith(("preferred_username", "upn", "name")) and "@" in claim_value:
            return claim_value
    return None


def role_for_email(email: str) -> Role:
    normalized = email.strip().lower()
    if normalized in _email_set(settings.auth_admin_emails):
        return "admin"
    if normalized in _email_set(settings.auth_analyst_emails):
        return "analyst"
    return "viewer"


def required_role(path: str, method: str) -> Role:
    normalized_method = method.upper()

    if path == "/api/audit/events":
        return "admin"
    if path in {"/metrics", "/api/operations/backup"}:
        return "admin"
    if path == "/api/retention/apply":
        return "admin"
    if path == "/api/retention/settings" and normalized_method != "GET":
        return "admin"
    if path == "/api/assistant/settings" and normalized_method != "GET":
        return "admin"

    analysis_generator_prefixes = (
        "/api/analyze/sample/",
        "/api/analyze/case-sample/",
    )
    if path == "/api/analyze/demo" or path.startswith(analysis_generator_prefixes):
        return "analyst"

    if normalized_method in {"GET", "HEAD", "OPTIONS"}:
        return "viewer"
    return "analyst"


def has_required_role(principal: Principal, required: Role) -> bool:
    return ROLE_RANK[principal.role] >= ROLE_RANK[required]


def is_public_path(path: str) -> bool:
    return (
        path == "/"
        or path == "/favicon.ico"
        or path == "/auth/status"
        or path in {"/api/health", "/api/health/live", "/api/health/ready", "/api/version"}
        or path.startswith("/assets/")
        or path.startswith("/.auth/")
    )


def _email_set(value: str) -> set[str]:
    return {email.strip().lower() for email in value.split(",") if email.strip()}


def request_id_from_headers(headers: Mapping[str, str]) -> str:
    supplied = headers.get("x-request-id", "")
    if re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", supplied):
        return supplied
    return uuid4().hex


class AuthRbacAuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = getattr(request.state, "request_id", None) or request_id_from_headers(
            request.headers
        )
        path = request.url.path

        if is_public_path(path):
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response

        authentication = authenticate_headers(request.headers)
        principal = authentication.principal
        if authentication.error == "missing":
            response = JSONResponse(
                {"detail": "Authentication required."},
                status_code=401,
            )
            _audit_request(request, None, response.status_code, request_id)
            response.headers["X-Request-ID"] = request_id
            return response
        if authentication.error == "not_allowed":
            response = JSONResponse(
                {"detail": "This account is not allowed to use this deployment."},
                status_code=403,
            )
            _audit_request(
                request,
                None,
                response.status_code,
                request_id,
                attempted_email=authentication.email,
            )
            response.headers["X-Request-ID"] = request_id
            return response

        assert principal is not None
        required = required_role(path, request.method)
        if not has_required_role(principal, required):
            response = JSONResponse(
                {"detail": f"The {required} role is required for this operation."},
                status_code=403,
            )
            _audit_request(request, principal, response.status_code, request_id)
            response.headers["X-Request-ID"] = request_id
            return response

        request.state.principal = principal
        request.state.request_id = request_id
        try:
            response = await call_next(request)
        except Exception:
            if _should_audit(request.method, 500):
                _audit_request(request, principal, 500, request_id)
            raise

        if _should_audit(request.method, response.status_code):
            _audit_request(request, principal, response.status_code, request_id)
        response.headers["X-Request-ID"] = request_id
        return response


def _should_audit(method: str, status_code: int) -> bool:
    return method.upper() not in {"GET", "HEAD", "OPTIONS"} or status_code in {401, 403}


def _audit_request(
    request: Request,
    principal: Principal | None,
    status_code: int,
    request_id: str,
    *,
    attempted_email: str | None = None,
) -> None:
    from tracehawk_api.database import SessionLocal, init_db
    from tracehawk_api.services.audit import record_audit_event

    try:
        init_db()
        with SessionLocal() as session:
            record_audit_event(
                session,
                principal=principal,
                method=request.method,
                path=request.url.path,
                status_code=status_code,
                request_id=request_id,
                attempted_email=attempted_email,
                auth_mode=settings.auth_mode,
            )
    except Exception:
        LOGGER.exception("Failed to persist an audit event.")
