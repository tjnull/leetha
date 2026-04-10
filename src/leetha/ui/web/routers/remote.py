"""REST API for remote sensor management."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/remote", tags=["remote"])


def _get_manager():
    from leetha.ui.web.app import app_instance
    if not app_instance:
        raise HTTPException(503, "App not initialized")
    return app_instance._remote_sensor_manager


@router.get("/sensors")
async def list_sensors():
    manager = _get_manager()
    return manager.list_sensors()


@router.delete("/sensors/{name}")
async def disconnect_sensor(name: str):
    manager = _get_manager()
    if name not in manager.sensors:
        raise HTTPException(404, f"Sensor '{name}' not found")
    manager.unregister(name)
    return {"status": "disconnected", "name": name}
