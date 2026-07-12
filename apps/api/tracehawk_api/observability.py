from __future__ import annotations

import json
import logging
import sys
import threading
import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import text
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.routing import Match

from tracehawk_api.auth import request_id_from_headers
from tracehawk_api.config import settings
from tracehawk_api.database import SessionLocal, init_db
from tracehawk_api.services.correlation_patterns import (
    default_correlation_pattern_path,
    load_correlation_patterns,
)
from tracehawk_api.services.rules import load_rules


LOGGER = logging.getLogger("tracehawk.http")
PROCESS_STARTED_AT = time.time()
HISTOGRAM_BUCKETS = (0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "event": record.getMessage(),
        }
        for field in (
            "request_id",
            "method",
            "route",
            "status_code",
            "duration_ms",
            "role",
            "build_commit",
            "runtime_mode",
        ):
            if hasattr(record, field):
                payload[field] = getattr(record, field)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=True)


def configure_structured_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonLogFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    for name in ("uvicorn", "uvicorn.error"):
        logger = logging.getLogger(name)
        logger.handlers = [handler]
        logger.propagate = False
    logging.getLogger("uvicorn.access").disabled = True


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._in_progress = 0
        self._request_counts: dict[tuple[str, str, int], int] = defaultdict(int)
        self._duration_counts: dict[tuple[str, str], int] = defaultdict(int)
        self._duration_sums: dict[tuple[str, str], float] = defaultdict(float)
        self._duration_buckets: dict[tuple[str, str, float], int] = defaultdict(int)

    def started(self) -> None:
        with self._lock:
            self._in_progress += 1

    def finished(self, *, method: str, route: str, status_code: int, duration: float) -> None:
        with self._lock:
            self._in_progress = max(0, self._in_progress - 1)
            self._request_counts[(method, route, status_code)] += 1
            self._duration_counts[(method, route)] += 1
            self._duration_sums[(method, route)] += duration
            for bucket in HISTOGRAM_BUCKETS:
                if duration <= bucket:
                    self._duration_buckets[(method, route, bucket)] += 1

    def render_prometheus(self) -> str:
        with self._lock:
            lines = [
                "# HELP tracehawk_build_info Build and runtime metadata.",
                "# TYPE tracehawk_build_info gauge",
                (
                    "tracehawk_build_info"
                    f'{{commit="{_label(settings.build_commit)}",'
                    f'runtime_mode="{_label(settings.runtime_mode)}"}} 1'
                ),
                "# HELP tracehawk_process_start_time_seconds Process start time in Unix seconds.",
                "# TYPE tracehawk_process_start_time_seconds gauge",
                f"tracehawk_process_start_time_seconds {PROCESS_STARTED_AT:.3f}",
                "# HELP tracehawk_http_requests_in_progress Current in-flight HTTP requests.",
                "# TYPE tracehawk_http_requests_in_progress gauge",
                f"tracehawk_http_requests_in_progress {self._in_progress}",
                "# HELP tracehawk_http_requests_total Completed HTTP requests.",
                "# TYPE tracehawk_http_requests_total counter",
            ]
            for (method, route, status), count in sorted(self._request_counts.items()):
                lines.append(
                    "tracehawk_http_requests_total"
                    f'{{method="{_label(method)}",route="{_label(route)}",status="{status}"}} {count}'
                )
            lines.extend(
                [
                    "# HELP tracehawk_http_request_duration_seconds HTTP request duration.",
                    "# TYPE tracehawk_http_request_duration_seconds histogram",
                ]
            )
            for method, route in sorted(self._duration_counts):
                labels = f'method="{_label(method)}",route="{_label(route)}"'
                for bucket in HISTOGRAM_BUCKETS:
                    count = self._duration_buckets[(method, route, bucket)]
                    lines.append(
                        "tracehawk_http_request_duration_seconds_bucket"
                        f'{{{labels},le="{bucket:g}"}} {count}'
                    )
                total = self._duration_counts[(method, route)]
                lines.append(
                    "tracehawk_http_request_duration_seconds_bucket"
                    f'{{{labels},le="+Inf"}} {total}'
                )
                lines.append(
                    f"tracehawk_http_request_duration_seconds_sum{{{labels}}} "
                    f"{self._duration_sums[(method, route)]:.6f}"
                )
                lines.append(f"tracehawk_http_request_duration_seconds_count{{{labels}}} {total}")
            return "\n".join(lines) + "\n"


METRICS = MetricsRegistry()


class ObservabilityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request_id_from_headers(request.headers)
        request.state.request_id = request_id
        started = time.perf_counter()
        status_code = 500
        METRICS.started()
        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            duration = time.perf_counter() - started
            route = _route_label(request)
            METRICS.finished(
                method=request.method,
                route=route,
                status_code=status_code,
                duration=duration,
            )
            principal = getattr(request.state, "principal", None)
            LOGGER.info(
                "http_request_completed",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "route": route,
                    "status_code": status_code,
                    "duration_ms": round(duration * 1000, 3),
                    "role": principal.role if principal else "anonymous",
                    "build_commit": settings.build_commit,
                    "runtime_mode": settings.runtime_mode,
                },
            )


def readiness_report() -> tuple[bool, dict[str, Any]]:
    checks: dict[str, Any] = {}
    try:
        init_db()
        with SessionLocal() as session:
            session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        checks["database"] = f"error:{type(exc).__name__}"

    try:
        rules_root = _project_root() / "packages/rules"
        rules = load_rules(rules_root)
        patterns = load_correlation_patterns(
            default_correlation_pattern_path(rules_root), rules
        )
        checks["rules"] = "ok" if rules else "error:no_rules"
        checks["rule_count"] = len(rules)
        checks["correlation_patterns"] = "ok" if patterns else "error:no_patterns"
        checks["correlation_pattern_count"] = len(patterns)
    except Exception as exc:
        checks["rules"] = f"error:{type(exc).__name__}"
        checks["rule_count"] = 0
        checks["correlation_patterns"] = f"error:{type(exc).__name__}"
        checks["correlation_pattern_count"] = 0

    ready = (
        checks.get("database") == "ok"
        and checks.get("rules") == "ok"
        and checks.get("correlation_patterns") == "ok"
    )
    return ready, {
        "status": "ready" if ready else "not_ready",
        "checks": checks,
        "build_commit": settings.build_commit,
        "runtime_mode": settings.runtime_mode,
    }


def _route_label(request: Request) -> str:
    route = request.scope.get("route")
    route_path = getattr(route, "path", None)
    if route_path:
        return str(route_path)
    for candidate in request.app.routes:
        match, _ = candidate.matches(request.scope)
        candidate_path = getattr(candidate, "path", None)
        if match == Match.FULL and candidate_path:
            return str(candidate_path)
    path = request.url.path
    if path.startswith("/assets/"):
        return "/assets/{asset}"
    return path if len(path) <= 120 else "/unmatched"


def _label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]
