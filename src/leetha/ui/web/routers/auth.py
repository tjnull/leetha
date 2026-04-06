"""Auth-related API routes."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter()


@router.post("/api/auth/login")
async def api_auth_login(request: Request):
    """Validate a token and return the associated role."""
    from leetha.ui.web.app import app_instance

    body = await request.json()
    raw_token = body.get("token", "").strip()
    if not raw_token:
        return JSONResponse(status_code=400, content={"error": "Token required."})
    from leetha.auth.tokens import hash_token
    token_info = await app_instance.db.validate_token(hash_token(raw_token))
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
    from leetha.ui.web.app import app_instance

    tokens = await app_instance.db.list_auth_tokens()
    return {"tokens": tokens}


@router.post("/api/auth/tokens")
async def api_auth_create_token(request: Request):
    """Create a new token (admin only)."""
    from leetha.ui.web.app import app_instance

    body = await request.json()
    role = body.get("role", "analyst")
    label = body.get("label")
    if role not in ("admin", "analyst"):
        return JSONResponse(status_code=400, content={"error": "Role must be 'admin' or 'analyst'."})
    from leetha.auth.tokens import generate_token, hash_token
    raw_token = generate_token()
    token_id = await app_instance.db.create_auth_token(hash_token(raw_token), role=role, label=label)
    return {"token": raw_token, "id": token_id, "role": role}


@router.delete("/api/auth/tokens/{token_id}")
async def api_auth_revoke_token(token_id: int):
    """Revoke a token by ID (admin only)."""
    from leetha.ui.web.app import app_instance

    await app_instance.db.revoke_auth_token(token_id)
    return {"status": "ok", "revoked": token_id}
