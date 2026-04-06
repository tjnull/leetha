"""Settings-related API routes."""

from __future__ import annotations

import re as _re

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from leetha.config import save_config, _PERSISTABLE_FIELDS

router = APIRouter()


@router.get("/api/settings")
async def get_settings():
    from leetha.ui.web.app import app_instance

    config = app_instance.config
    return {k: getattr(config, k) for k in _PERSISTABLE_FIELDS}


@router.put("/api/settings")
async def put_settings(request: Request):
    from leetha.ui.web.app import app_instance

    body = await request.json()
    config = app_instance.config
    for key, value in body.items():
        if key in _PERSISTABLE_FIELDS and hasattr(config, key):
            setattr(config, key, type(getattr(config, key))(value))
    save_config(config)
    return {k: getattr(config, k) for k in _PERSISTABLE_FIELDS}


@router.post("/api/settings/apply")
async def apply_settings():
    return {"status": "restart_required", "message": "Please restart Leetha for changes to take effect."}


@router.post("/api/settings/reset")
async def reset_settings():
    from leetha.ui.web.app import app_instance
    from leetha.config import LeethaConfig

    config = app_instance.config
    defaults = LeethaConfig(data_dir=config.data_dir, cache_dir=config.cache_dir)
    for key in _PERSISTABLE_FIELDS:
        setattr(config, key, getattr(defaults, key))
    save_config(config)
    return {k: getattr(config, k) for k in _PERSISTABLE_FIELDS}


@router.get("/api/settings/export")
async def export_settings():
    from leetha.ui.web.app import app_instance
    import json as _json
    from starlette.responses import Response

    config = app_instance.config
    data = {k: getattr(config, k) for k in _PERSISTABLE_FIELDS}
    return Response(
        content=_json.dumps(data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=leetha-settings.json"},
    )


@router.post("/api/settings/import")
async def import_settings(request: Request):
    from leetha.ui.web.app import app_instance

    body = await request.json()
    config = app_instance.config
    for key, value in body.items():
        if key in _PERSISTABLE_FIELDS and hasattr(config, key):
            setattr(config, key, type(getattr(config, key))(value))
    save_config(config)
    return {k: getattr(config, k) for k in _PERSISTABLE_FIELDS}


@router.get("/api/settings/db-info")
async def db_info():
    from leetha.ui.web.app import app_instance

    config = app_instance.config
    db_size = 0
    if config.db_path.exists():
        db_size = config.db_path.stat().st_size
    try:
        device_count = await app_instance.store.hosts.count()
    except Exception:
        device_count = await app_instance.db.get_identity_count()
    return {
        "db_path": str(config.db_path),
        "db_size_bytes": db_size,
        "device_count": device_count,
        "cache_dir": str(config.cache_dir),
    }


@router.post("/api/settings/query")
async def run_query(request: Request):
    from leetha.ui.web.app import app_instance

    body = await request.json()
    sql = body.get("sql", "").strip()

    # Strict validation
    if not sql:
        return JSONResponse(status_code=400, content={"error": "Empty query"})

    # Reject multi-statement
    if ";" in sql:
        return JSONResponse(status_code=400, content={"error": "Multi-statement queries not allowed"})

    # Must start with SELECT
    if not sql.upper().lstrip().startswith("SELECT"):
        return JSONResponse(status_code=400, content={"error": "Only SELECT queries are allowed"})

    # Block dangerous keywords anywhere in the query
    upper = sql.upper()
    for kw in ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE", "REPLACE", "ATTACH", "DETACH", "PRAGMA"]:
        # Check as whole words to avoid false positives
        if _re.search(r'\b' + kw + r'\b', upper):
            return JSONResponse(status_code=400, content={"error": f"Forbidden keyword: {kw}"})

    # Enforce a row limit to prevent excessive memory usage
    if "limit" not in sql.lower():
        sql = sql.rstrip(";") + " LIMIT 10000"

    # Try new Store first (has verdicts, hosts, sightings, findings tables)
    try:
        cursor = await app_instance.store.connection.execute(sql)
        rows = await cursor.fetchall()
        if rows:
            columns = [d[0] for d in cursor.description] if cursor.description else []
            return {"columns": columns, "rows": [list(r) for r in rows]}
        return {"columns": [], "rows": []}
    except Exception:
        pass
    # Fall back to old Database (has devices, observations, alerts, etc.)
    try:
        result = await app_instance.db.execute_readonly_query(sql)
        return result
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@router.delete("/api/settings/db")
async def clear_database():
    from leetha.ui.web.app import app_instance

    # Clear old tables
    await app_instance.db.clear_all_devices()
    # Clear new tables (verdicts, hosts, findings, sightings)
    conn = app_instance.store.connection
    await conn.execute("DELETE FROM verdicts")
    await conn.execute("DELETE FROM hosts")
    await conn.execute("DELETE FROM findings")
    await conn.execute("DELETE FROM sightings")
    await conn.execute("DELETE FROM fingerprint_snapshots")
    await conn.execute("DELETE FROM identities")
    await conn.commit()
    # Clear in-memory evidence buffers
    if app_instance.pipeline:
        app_instance.pipeline._evidence_buffer.clear()
    return {"status": "ok", "message": "All devices and findings cleared."}
