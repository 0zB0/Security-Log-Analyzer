from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.requests import Request

from tracehawk_api.auth import (
    AUTH_MODE_DISABLED,
    AuthRbacAuditMiddleware,
    allowed_emails,
    authenticate_headers,
    validate_auth_configuration,
)
from tracehawk_api.config import settings
from tracehawk_api.database import init_db
from tracehawk_api.observability import (
    METRICS,
    ObservabilityMiddleware,
    configure_structured_logging,
    readiness_report,
)
from tracehawk_api.routers.analyze import router as analyze_router
from tracehawk_api.routers.assistant import router as assistant_router
from tracehawk_api.routers.audit import router as audit_router
from tracehawk_api.routers.entities import router as entities_router
from tracehawk_api.routers.live import router as live_router
from tracehawk_api.routers.mitre import router as mitre_router
from tracehawk_api.routers.notes import router as notes_router
from tracehawk_api.routers.operations import router as operations_router
from tracehawk_api.routers.reports import router as reports_router
from tracehawk_api.routers.retention import router as retention_router
from tracehawk_api.routers.rules import router as rules_router
from tracehawk_api.security import (
    InMemoryRateLimitMiddleware,
    RequestBodyLimitMiddleware,
    SecurityHeadersMiddleware,
)
from tracehawk_api.version import API_VERSION, RELEASE


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    configure_structured_logging()
    validate_auth_configuration()
    init_db()
    yield


app = FastAPI(
    title="TraceHawk API",
    description="Local-only live SOC assistant API.",
    version=API_VERSION,
    lifespan=lifespan,
)

app.add_middleware(InMemoryRateLimitMiddleware)
app.add_middleware(RequestBodyLimitMiddleware)
app.add_middleware(AuthRbacAuditMiddleware)
app.add_middleware(ObservabilityMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["*"],
)

app.include_router(analyze_router)
app.include_router(assistant_router)
app.include_router(audit_router)
app.include_router(entities_router)
app.include_router(live_router)
app.include_router(mitre_router)
app.include_router(notes_router)
app.include_router(operations_router)
app.include_router(reports_router)
app.include_router(retention_router)
app.include_router(rules_router)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "local-only"}


@app.get("/api/health/live")
def health_live() -> dict[str, str]:
    return {
        "status": "alive",
        "build_commit": settings.build_commit,
        "runtime_mode": settings.runtime_mode,
    }


@app.get("/api/health/ready")
def health_ready() -> JSONResponse:
    ready, report = readiness_report()
    return JSONResponse(report, status_code=200 if ready else 503)


@app.get("/metrics", include_in_schema=False)
def prometheus_metrics() -> PlainTextResponse:
    return PlainTextResponse(
        METRICS.render_prometheus(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@app.get("/api/version")
def version() -> dict[str, str]:
    return {
        "app": "tracehawk",
        "api_version": app.version,
        "release": RELEASE,
        "build_commit": settings.build_commit,
        "runtime_mode": settings.runtime_mode,
        "llm_provider": settings.llm_provider,
    }


@app.get("/auth/status")
def auth_status(request: Request) -> dict[str, object]:
    authentication = authenticate_headers(request.headers)
    principal = authentication.principal
    configured_allowed = allowed_emails()
    return {
        "authenticated": bool(principal and principal.authenticated),
        "email": principal.email if principal else authentication.email,
        "allowed": bool(principal),
        "role": principal.role if principal else None,
        "auth_mode": settings.auth_mode,
        "allowlist_enabled": bool(configured_allowed),
        "local_admin": settings.auth_mode == AUTH_MODE_DISABLED,
    }


def _web_dist_path() -> Path | None:
    if not settings.web_dist_path:
        return None
    path = Path(settings.web_dist_path).expanduser()
    return path if path.exists() and path.is_dir() else None


web_dist_path = _web_dist_path()
if web_dist_path is not None:
    assets_path = web_dist_path / "assets"
    if assets_path.exists():
        app.mount("/assets", StaticFiles(directory=assets_path), name="web-assets")

    @app.get("/", include_in_schema=False)
    def web_index() -> FileResponse:
        return FileResponse(web_dist_path / "index.html")

    @app.get("/{full_path:path}", include_in_schema=False)
    def web_fallback(full_path: str) -> FileResponse:
        if full_path.startswith(("api/", "docs", "openapi.json", "redoc")):
            raise HTTPException(status_code=404, detail="Not found")
        return FileResponse(web_dist_path / "index.html")
