"""Auth-related API routes."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter()

_SERVICE_INITIALIZING = JSONResponse(
    status_code=503,
    content={"error": "Service initializing — please try again shortly."},
)


def _get_db():
    """Return the database handle, or None if the backend isn't ready."""
    from leetha.ui.web.app import app_instance
    if not app_instance or not app_instance._running:
        return None
    return app_instance.db


@router.post("/api/auth/login")
async def api_auth_login(request: Request):
    """Validate a token and return the associated role."""
    db = _get_db()
    if db is None:
        return _SERVICE_INITIALIZING

    body = await request.json()
    raw_token = body.get("token", "").strip()
    if not raw_token:
        return JSONResponse(status_code=400, content={"error": "Token required."})
    from leetha.auth.tokens import hash_token
    token_info = await db.validate_token(hash_token(raw_token))
    if token_info is None:
        return JSONResponse(status_code=401, content={"error": "Invalid or revoked token."})
    return {"valid": True, "role": token_info["role"]}


@router.get("/api/auth/status")
async def api_auth_status():
    """Return whether auth is enabled (public endpoint for frontend)."""
    from leetha.ui.web.app import _auth_enabled

    return {"auth_enabled": _auth_enabled}


@router.get("/api/auth/tokens")
async def api_auth_list_tokens():
    """List all tokens (admin only — enforced by role middleware)."""
    db = _get_db()
    if db is None:
        return _SERVICE_INITIALIZING

    tokens = await db.list_auth_tokens()
    return {"tokens": tokens}


@router.post("/api/auth/tokens")
async def api_auth_create_token(request: Request):
    """Create a new token (admin only)."""
    db = _get_db()
    if db is None:
        return _SERVICE_INITIALIZING

    body = await request.json()
    role = body.get("role", "analyst")
    label = body.get("label")
    if role not in ("admin", "analyst"):
        return JSONResponse(status_code=400, content={"error": "Role must be 'admin' or 'analyst'."})
    from leetha.auth.tokens import generate_token, hash_token
    raw_token = generate_token()
    token_id = await db.create_auth_token(hash_token(raw_token), role=role, label=label)
    return {"token": raw_token, "id": token_id, "role": role}


@router.delete("/api/auth/tokens/{token_id}")
async def api_auth_revoke_token(token_id: int):
    """Revoke a token by ID (admin only)."""
    db = _get_db()
    if db is None:
        return _SERVICE_INITIALIZING

    await db.revoke_auth_token(token_id)
    return {"status": "ok", "revoked": token_id}
