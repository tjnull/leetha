"""Integration tests for auth middleware request flow."""
from unittest.mock import AsyncMock
from starlette.testclient import TestClient
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from leetha.auth.middleware import auth_middleware


def _make_app(*, db=None, auth_enabled=True):
    """Build a minimal Starlette app with the auth middleware."""

    async def protected(request: Request):
        role = request.scope.get("auth_role", "none")
        return JSONResponse({"role": role})

    async def middleware(request: Request, call_next):
        return await auth_middleware(
            request, call_next, db=db, auth_enabled=auth_enabled,
        )

    app = Starlette(
        routes=[Route("/api/test", protected)],
        middleware=[],
    )
    app.middleware("http")(middleware)
    return app


def test_db_none_returns_503():
    """When DB is None (startup), protected routes must return 503."""
    app = _make_app(db=None, auth_enabled=True)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/test")
    assert resp.status_code == 503
    assert "initializing" in resp.json()["error"].lower()


def test_db_validate_throws_returns_503():
    """When db.validate_token() raises, protected routes must return 503."""
    mock_db = AsyncMock()
    mock_db.validate_token.side_effect = Exception("DB not initialized")
    app = _make_app(db=mock_db, auth_enabled=True)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/test", headers={"Authorization": "Bearer lta_faketoken123"})
    assert resp.status_code == 503
    assert "initializing" in resp.json()["error"].lower()


def test_health_exempt_when_db_none():
    """The /health path must remain accessible even when DB is None."""

    async def health_handler(request):
        return JSONResponse({"status": "ok", "ready": False})

    async def mw(request, call_next):
        return await auth_middleware(
            request, call_next, db=None, auth_enabled=True,
        )

    app = Starlette(routes=[Route("/health", health_handler)])
    app.middleware("http")(mw)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_missing_token_returns_401():
    """Protected route with no token must return 401, not 503 or 200."""
    mock_db = AsyncMock()
    app = _make_app(db=mock_db, auth_enabled=True)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/test")
    assert resp.status_code == 401
    assert "authentication required" in resp.json()["error"].lower()


def test_invalid_token_returns_401():
    """A token that doesn't match any DB record must return 401."""
    mock_db = AsyncMock()
    mock_db.validate_token.return_value = None
    app = _make_app(db=mock_db, auth_enabled=True)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/test", headers={"Authorization": "Bearer lta_badtoken999"})
    assert resp.status_code == 401
    assert "invalid" in resp.json()["error"].lower()


def test_valid_admin_token_succeeds():
    """A valid admin token must pass through and set auth_role=admin."""
    mock_db = AsyncMock()
    mock_db.validate_token.return_value = {"id": 1, "role": "admin", "label": "test"}
    app = _make_app(db=mock_db, auth_enabled=True)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/test", headers={"Authorization": "Bearer lta_goodtoken123"})
    assert resp.status_code == 200
    assert resp.json()["role"] == "admin"


def test_analyst_on_admin_route_returns_403():
    """An analyst token on an admin-only route must return 403."""
    from leetha.auth.roles import requires_admin

    mock_db = AsyncMock()
    mock_db.validate_token.return_value = {"id": 2, "role": "analyst", "label": "readonly"}

    async def admin_endpoint(request):
        return JSONResponse({"ok": True})

    async def auth_mw(request, call_next):
        return await auth_middleware(
            request, call_next, db=mock_db, auth_enabled=True,
        )

    async def role_mw(request, call_next):
        role = request.scope.get("auth_role", "anonymous")
        if request.url.path.startswith("/api/") and requires_admin(request.method, request.url.path) and role != "admin":
            return JSONResponse(status_code=403, content={"error": "Admin access required."})
        return await call_next(request)

    app = Starlette(routes=[Route("/api/auth/tokens", admin_endpoint)])
    # Role middleware runs first (outermost), then auth
    app.middleware("http")(auth_mw)
    app.middleware("http")(role_mw)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get(
        "/api/auth/tokens",
        headers={"Authorization": "Bearer lta_analystkey"},
    )
    assert resp.status_code == 403
    assert "admin" in resp.json()["error"].lower()


def test_auth_disabled_grants_admin():
    """When auth is disabled, all requests get admin role."""
    app = _make_app(db=None, auth_enabled=False)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/test")
    assert resp.status_code == 200
    assert resp.json()["role"] == "admin"
