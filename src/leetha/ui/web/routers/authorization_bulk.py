"""Phase A follow-up — bulk authorization endpoints."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

router = APIRouter()


class BulkAuthorizationBody(BaseModel):
    action: Literal["approve", "reject", "revoke"]
    macs: list[str] = Field(min_length=1, max_length=500)
    reason: str | None = Field(default=None, max_length=500)


def _get_app():
    from leetha.ui.web.app import app_instance
    return app_instance


def _actor(request: Request) -> str:
    token_id = getattr(request.state, "token_id", None)
    return str(token_id) if token_id else "bulk-anonymous"


@router.post("/api/devices/bulk/authorization")
async def bulk_authorization(body: BulkAuthorizationBody, request: Request):
    """Apply the same authorization action to many devices at once.

    Returns ``{updated: N, missing: [mac, ...]}`` — the updated count excludes
    MACs not present in the devices table.
    """
    app_instance = _get_app()
    if app_instance is None or getattr(app_instance, "db", None) is None:
        raise HTTPException(503, "Server not ready")

    actor = _actor(request)
    mutators = {
        "approve": app_instance.db.approve_device,
        "reject": app_instance.db.reject_device,
        "revoke": app_instance.db.revoke_device,
    }
    fn = mutators[body.action]

    # Share the ensure-row helper with the per-device endpoints — live-capture
    # hosts may not have a ``devices`` row yet.
    from leetha.ui.web.routers.devices import _ensure_device_row

    updated = 0
    missing: list[str] = []
    for mac in body.macs:
        if not await _ensure_device_row(app_instance, mac):
            missing.append(mac)
            continue
        result = await fn(mac, actor=actor, reason=body.reason)
        if result is None:
            missing.append(mac)
        else:
            updated += 1
    return {"updated": updated, "missing": missing, "action": body.action}
