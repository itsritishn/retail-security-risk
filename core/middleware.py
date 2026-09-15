"""HTTP middleware: security headers and request correlation."""

from __future__ import annotations

import logging
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

logger = logging.getLogger("sentinelfloor.http")

#: Content Security Policy.
#:
#: No inline script and no external origins. The dashboard loads one stylesheet and one
#: script from its own origin, so the policy can be strict without workarounds. Getting
#: this right matters more than usual here: staff type free-form disposition notes that
#: are rendered back to managers, so a stored-XSS bug is a realistic path to hijacking a
#: manager session. Autoescaping is the first line of defence and this is the second.
CSP = "; ".join(
    (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self' ws: wss:",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "object-src 'none'",
    )
)

SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    # No camera, microphone, or geolocation is ever needed by this dashboard, so the
    # capability is refused outright rather than left to browser defaults.
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    # Prevents alert data sitting in a shared terminal's cache for the next shift.
    "Cache-Control": "no-store, max-age=0",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, *, enable_hsts: bool = False) -> None:
        super().__init__(app)
        self.enable_hsts = enable_hsts

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)

        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)

        # Only sent when TLS is actually in use. Setting HSTS over plain HTTP during
        # development would pin the browser to HTTPS for localhost and be a nuisance to
        # undo.
        if self.enable_hsts:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )

        # Static assets are safe to cache and are exempted from the no-store default.
        if request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "public, max-age=3600"

        return response


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a correlation id and log request outcomes.

    Query strings are not logged. They are low-value here and a habit of logging them
    leads to credentials and tokens ending up in log files.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        request.state.request_id = request_id

        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            elapsed_ms = (time.perf_counter() - started) * 1000
            logger.exception(
                "request failed id=%s %s %s after %.1fms",
                request_id,
                request.method,
                request.url.path,
                elapsed_ms,
            )
            raise

        elapsed_ms = (time.perf_counter() - started) * 1000
        response.headers["X-Request-ID"] = request_id

        log = logger.warning if response.status_code >= 400 else logger.info
        log(
            "id=%s %s %s -> %s %.1fms",
            request_id,
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
        )
        return response
