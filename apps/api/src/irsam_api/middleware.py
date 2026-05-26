"""ASGI middlewares: security headers + cross-origin guard.

The cross-origin guard is a lightweight CSRF defence: any unsafe HTTP method
(POST/PUT/PATCH/DELETE) carrying our session cookie must come from an Origin
listed in ``settings.allowed_origins``. Requests without an ``Origin`` header
(e.g. native HTTP clients, server-to-server, the pytest ASGI transport) pass
through, since browsers always attach Origin for cross-origin POSTs.
"""

from __future__ import annotations

from collections.abc import Iterable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach a baseline set of hardening headers to every response."""

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy",
                                     "camera=(), microphone=(), geolocation=()")
        # Note: HSTS only meaningful behind TLS. Safe to always send; browsers
        # ignore it on plain HTTP.
        response.headers.setdefault("Strict-Transport-Security",
                                     "max-age=63072000; includeSubDomains")
        return response


class OriginGuardMiddleware(BaseHTTPMiddleware):
    """Reject browser-issued cross-origin writes against a session cookie."""

    def __init__(self, app, *, allowed_origins: Iterable[str], cookie_name: str):  # noqa: ANN001
        super().__init__(app)
        self._allowed = {o.rstrip("/") for o in allowed_origins}
        self._cookie = cookie_name

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001
        if request.method in UNSAFE_METHODS:
            origin = request.headers.get("origin")
            if origin and self._cookie in request.cookies:
                if origin.rstrip("/") not in self._allowed:
                    return Response("cross-origin request rejected",
                                     status_code=403)
        return await call_next(request)
