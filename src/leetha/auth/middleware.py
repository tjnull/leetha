"""FastAPI authentication middleware."""
from __future__ import annotations

import logging
from starlette.requests import Request
from starlette.responses import JSONResponse

from leetha.auth.tokens import hash_token, TOKEN_PREFIX

logger = logging.getLogger(__name__)

_NO_AUTH_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

EXEMPT_PATHS = frozenset({
    "/api/auth/login",
    "/api/auth/status",
    "/health",
})

EXEMPT_PREFIXES = (
    "/assets/",
    "/ws",
)


def check_auth_required(bind_host: str, force_auth: bool | None = None) -> bool:
    """Determine whether auth should be enabled based on bind address."""
    if force_auth is not None:
        return force_auth
    return bind_host not in _NO_AUTH_HOSTS


def _is_exempt(path: str) -> bool:
    """Return True if the path does not require authentication."""
    if path in EXEMPT_PATHS:
        return True
    for prefix in EXEMPT_PREFIXES:
        if path.startswith(prefix):
            return True
    return False


async def auth_middleware(request: Request, call_next, *, db, auth_enabled: bool):
    """Middleware function that validates Bearer tokens on API requests."""
    if not auth_enabled:
        request.scope["auth_role"] = "admin"
        return await call_next(request)

    path = request.url.path

    if _is_exempt(path):
        request.scope["auth_role"] = "anonymous"
        return await call_next(request)

    if not path.startswith("/api/"):
        request.scope["auth_role"] = "anonymous"
        return await call_next(request)

    # Database not ready yet — fail closed
    if db is None:
        return JSONResponse(
            status_code=503,
            content={"error": "Service initializing", "status": "starting"},
        )

    raw_token = None
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        raw_token = auth_header[7:].strip()
    elif request.headers.get("x-api-key", "").startswith(TOKEN_PREFIX):
        raw_token = request.headers["x-api-key"].strip()
    else:
        # Fallback 1: cookie (survives reverse proxies that strip Authorization)
        raw_token = request.cookies.get("leetha_token")
    if not raw_token:
        # Fallback 2: query param (for EventSource/SSE which can't set headers)
        raw_token = request.query_params.get("token")

    if not raw_token:
        return JSONResponse(
            status_code=401,
            content={"error": "Authentication required. Provide a Bearer token."},
        )

    try:
        token_info = await db.validate_token(hash_token(raw_token))
    except Exception:
        return JSONResponse(
            status_code=503,
            content={"error": "Service initializing", "status": "starting"},
        )

    if token_info is None:
        return JSONResponse(
            status_code=401,
            content={"error": "Invalid or revoked token."},
        )

    request.scope["auth_role"] = token_info["role"]
    request.scope["auth_token_id"] = token_info["id"]
    return await call_next(request)
