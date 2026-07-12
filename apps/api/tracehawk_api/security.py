from collections import defaultdict, deque
from threading import Lock
from time import monotonic

from fastapi.responses import JSONResponse
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from tracehawk_api.config import settings


EXPENSIVE_PATH_PREFIXES = (
    "/api/analyze/upload",
    "/api/analyze/case-bundle",
    "/api/assistant/explain",
    "/api/reports/",
)


class RequestBodyTooLarge(Exception):
    pass


class RequestBodyLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = _request_body_limit(str(scope.get("path", "")))
        if limit is None:
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        content_length = headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > limit:
                    await _too_large_response(limit)(scope, receive, send)
                    return
            except ValueError:
                await JSONResponse(
                    {"detail": "Invalid Content-Length header."},
                    status_code=400,
                )(scope, receive, send)
                return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise RequestBodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            await _too_large_response(limit)(scope, receive, send)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (
                            b"content-security-policy",
                            b"default-src 'self'; connect-src 'self' ws: wss:; "
                            b"img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                            b"object-src 'none'; base-uri 'self'; form-action 'self'; "
                            b"frame-ancestors 'none'",
                        ),
                        (b"referrer-policy", b"no-referrer"),
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                    ]
                )
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


class InMemoryRateLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = str(scope.get("path", ""))
        if scope["type"] != "http" or not path.startswith(EXPENSIVE_PATH_PREFIXES):
            await self.app(scope, receive, send)
            return

        limit = settings.rate_limit_per_minute
        if limit <= 0:
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        key = _rate_limit_key(request)
        allowed, retry_after = RATE_LIMITER.allow(key, limit)
        if not allowed:
            await JSONResponse(
                {"detail": "Rate limit exceeded."},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )(scope, receive, send)
            return
        await self.app(scope, receive, send)


class SlidingWindowRateLimiter:
    def __init__(self) -> None:
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key: str, limit: int) -> tuple[bool, int]:
        now = monotonic()
        cutoff = now - 60
        with self._lock:
            requests = self._requests[key]
            while requests and requests[0] <= cutoff:
                requests.popleft()
            if len(requests) >= limit:
                retry_after = max(1, int(60 - (now - requests[0])))
                return False, retry_after
            requests.append(now)
            return True, 0

    def clear(self) -> None:
        with self._lock:
            self._requests.clear()


RATE_LIMITER = SlidingWindowRateLimiter()


def _request_body_limit(path: str) -> int | None:
    multipart_overhead = 256 * 1024
    if path == "/api/analyze/upload":
        return settings.max_upload_bytes + multipart_overhead
    if path == "/api/analyze/case-bundle":
        return settings.max_case_total_bytes + multipart_overhead
    return None


def _too_large_response(limit: int) -> JSONResponse:
    return JSONResponse(
        {"detail": f"Request body exceeds the {limit} byte limit."},
        status_code=413,
    )


def _rate_limit_key(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    if principal is not None and principal.authenticated:
        return f"principal:{principal.audit_actor.lower()}"
    client_host = request.client.host if request.client else "unknown"
    return f"client:{client_host}"
