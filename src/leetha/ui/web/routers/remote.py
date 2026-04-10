"""REST API for remote sensor management and build."""
from __future__ import annotations

import json
import asyncio
from pathlib import Path
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

router = APIRouter(prefix="/api/remote", tags=["remote"])


def _find_sensor_dir() -> Path | None:
    """Locate the sensor Rust source directory.

    Search order:
    1. LEETHA_SENSOR_DIR environment variable
    2. Relative to the leetha data directory (~/.leetha/sensor)
    3. Relative to the Python package (development installs)
    4. Common project locations
    """
    import os

    # 1. Environment variable override
    env_dir = os.environ.get("LEETHA_SENSOR_DIR")
    if env_dir:
        p = Path(env_dir)
        if (p / "Cargo.toml").exists():
            return p

    # 2. Next to the data directory
    try:
        data_dir = _get_data_dir()
        candidate = data_dir / "sensor"
        if (candidate / "Cargo.toml").exists():
            return candidate
    except Exception:
        pass

    # 3. Relative to Python package (works for editable/dev installs)
    pkg_dir = Path(__file__).resolve().parents[4] / "sensor"
    if (pkg_dir / "Cargo.toml").exists():
        return pkg_dir

    # 4. Walk up from CWD looking for sensor/Cargo.toml
    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        candidate = parent / "sensor"
        if (candidate / "Cargo.toml").exists():
            return candidate
        # Stop at home directory
        if parent == Path.home():
            break

    # 5. Check common project paths
    for common in [
        Path.home() / "Documents" / "scripts" / "leetha" / "sensor",
        Path.home() / "leetha" / "sensor",
        Path("/opt/leetha/sensor"),
    ]:
        if (common / "Cargo.toml").exists():
            return common

    return None


def _get_manager():
    from leetha.ui.web.app import app_instance
    if not app_instance:
        raise HTTPException(503, "App not initialized")
    return app_instance._remote_sensor_manager


def _get_data_dir() -> Path:
    from leetha.ui.web.app import app_instance
    if not app_instance:
        raise HTTPException(503, "App not initialized")
    return Path(app_instance.config.data_dir)


@router.get("/sensors")
async def list_sensors():
    manager = _get_manager()
    return manager.list_sensors()


@router.get("/sensors/{name}")
async def get_sensor(name: str):
    manager = _get_manager()
    if name not in manager.sensors:
        raise HTTPException(404, f"Sensor '{name}' not found")
    return manager.sensors[name].stats()


@router.delete("/sensors/{name}")
async def disconnect_sensor(name: str):
    manager = _get_manager()
    if name not in manager.sensors:
        raise HTTPException(404, f"Sensor '{name}' not found")
    manager.unregister(name)
    return {"status": "disconnected", "name": name}


# --- Build Endpoints ---

@router.get("/server-addresses")
async def list_server_addresses():
    """List IP addresses available on the leetha server for sensor connections."""
    from leetha.ui.web.app import app_instance
    if not app_instance:
        raise HTTPException(503, "App not initialized")

    import psutil
    addresses = []
    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            # Only include IPv4 addresses, skip loopback
            if addr.family.name == "AF_INET" and addr.address != "127.0.0.1":
                addresses.append({
                    "interface": name,
                    "address": addr.address,
                })
    return addresses


@router.get("/targets")
async def list_targets():
    """List available build targets with default buffer sizes."""
    from leetha.capture.remote.build import TARGET_MAP

    labels = {
        "linux-x86_64": "Linux x86_64",
        "linux-arm": "Linux ARM (32-bit)",
        "linux-arm64": "Linux ARM64",
        "linux-mips": "Linux MIPS",
        "windows-x86_64": "Windows x86_64",
    }
    return [
        {
            "id": target_id,
            "label": labels.get(target_id, target_id),
            "triple": info["triple"],
            "default_buffer_mb": info["default_buffer_mb"],
        }
        for target_id, info in TARGET_MAP.items()
    ]


@router.get("/build/check")
async def check_build_prerequisites(target: str = Query(...)):
    """Check if build tools are available for the given target."""
    from leetha.capture.remote.build import check_prerequisites
    ok, message = check_prerequisites(target)
    return {"ok": ok, "message": message}


@router.get("/build/check-name")
async def check_sensor_name(name: str = Query(...)):
    """Check if a sensor certificate already exists for this name."""
    from leetha.capture.remote.ca import list_certs, CANotInitialized
    ca_dir = _get_data_dir() / "ca"
    try:
        certs = list_certs(ca_dir)
        for c in certs:
            if c["name"] == name and not c["revoked"]:
                return {"exists": True, "name": name}
    except CANotInitialized:
        pass
    return {"exists": False, "name": name}


class BuildRequestBody(BaseModel):
    name: str
    server: str
    target: str = "linux-x86_64"
    buffer_size_mb: int = 100


@router.post("/build")
async def build_sensor(body: BuildRequestBody):
    """Build a sensor binary. Returns SSE stream with build progress."""
    from leetha.capture.remote.build import (
        BuildRequest, SensorBuilder, TARGET_MAP,
    )

    if body.target not in TARGET_MAP:
        raise HTTPException(400, f"Unknown target: {body.target}")

    data_dir = _get_data_dir()
    ca_dir = data_dir / "ca"
    if not (ca_dir / "ca.crt").exists():
        from leetha.capture.remote.ca import init_ca
        init_ca(ca_dir)

    # Find sensor source directory — check multiple locations
    sensor_dir = _find_sensor_dir()
    if not sensor_dir:
        raise HTTPException(500, "Sensor source not found. Set LEETHA_SENSOR_DIR or ensure the sensor/ directory is in the project root.")

    request = BuildRequest(
        name=body.name,
        server=body.server,
        target=body.target,
        buffer_size_mb=body.buffer_size_mb,
    )

    builder = SensorBuilder(sensor_dir=sensor_dir, ca_dir=ca_dir)

    async def event_stream():
        queue: asyncio.Queue[str | None] = asyncio.Queue()

        async def on_progress(stage: str, message: str):
            event = json.dumps({"stage": stage, "message": message})
            await queue.put(f"data: {event}\n\n")

        async def run_build():
            try:
                await builder.build(request, progress_callback=on_progress)
            finally:
                await queue.put(None)

        task = asyncio.create_task(run_build())

        while True:
            item = await queue.get()
            if item is None:
                break
            yield item

        await task

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/build/{download_id}")
async def download_build(download_id: str):
    """Download a completed sensor binary."""
    from leetha.capture.remote.build import get_artifact, _cleanup_artifact

    artifact = get_artifact(download_id)
    if not artifact:
        raise HTTPException(404, "Build not found or expired")

    path = Path(artifact["path"])
    if not path.exists():
        _cleanup_artifact(download_id)
        raise HTTPException(404, "Build artifact missing")

    return FileResponse(
        path=str(path),
        filename=artifact["filename"],
        media_type="application/octet-stream",
    )
