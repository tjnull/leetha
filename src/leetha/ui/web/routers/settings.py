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
            current = getattr(config, key)
            if isinstance(current, list):
                setattr(config, key, value if isinstance(value, list) else [value])
            elif isinstance(current, bool):
                if isinstance(value, str):
                    setattr(config, key, value.lower() in ("true", "1", "yes"))
                else:
                    setattr(config, key, bool(value))
            else:
                setattr(config, key, type(current)(value))
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
            current = getattr(config, key)
            if isinstance(current, list):
                setattr(config, key, value if isinstance(value, list) else [value])
            elif isinstance(current, bool):
                if isinstance(value, str):
                    setattr(config, key, value.lower() in ("true", "1", "yes"))
                else:
                    setattr(config, key, bool(value))
            else:
                setattr(config, key, type(current)(value))
    save_config(config)
    return {k: getattr(config, k) for k in _PERSISTABLE_FIELDS}


@router.get("/api/settings/db-info")
async def db_info():
    from leetha.ui.web.app import app_instance
    import os

    config = app_instance.config
    db_path = config.db_path
    db_size = 0
    wal_size = 0
    if db_path.exists():
        db_size = db_path.stat().st_size
        wal_path = db_path.with_suffix(".db-wal")
        if wal_path.exists():
            wal_size = wal_path.stat().st_size

    # Table row counts
    table_counts = {}
    conn = app_instance.store.connection
    for table in ("hosts", "verdicts", "sightings", "findings", "fingerprint_snapshots", "identities"):
        try:
            cursor = await conn.execute(f"SELECT COUNT(*) FROM {table}")  # noqa: S608
            row = await cursor.fetchone()
            table_counts[table] = row[0] if row else 0
        except Exception:
            table_counts[table] = 0

    # SQLite page info
    page_count = 0
    page_size = 0
    try:
        cursor = await conn.execute("PRAGMA page_count")
        row = await cursor.fetchone()
        page_count = row[0] if row else 0
        cursor = await conn.execute("PRAGMA page_size")
        row = await cursor.fetchone()
        page_size = row[0] if row else 0
    except Exception:
        pass

    # Last modified time
    last_modified = None
    if db_path.exists():
        last_modified = os.path.getmtime(db_path)

    try:
        device_count = await app_instance.store.hosts.count()
    except Exception:
        device_count = await app_instance.db.get_identity_count()

    return {
        "db_path": str(db_path),
        "db_size_bytes": db_size,
        "wal_size_bytes": wal_size,
        "device_count": device_count,
        "cache_dir": str(config.cache_dir),
        "table_counts": table_counts,
        "page_count": page_count,
        "page_size": page_size,
        "last_modified": last_modified,
    }


@router.get("/api/settings/db-export")
async def db_export(request: Request):
    from leetha.ui.web.app import app_instance
    from fastapi.responses import FileResponse, StreamingResponse
    import io

    fmt = request.query_params.get("format", "sqlite")
    config = app_instance.config
    db_path = config.db_path

    if not db_path.exists():
        return JSONResponse(status_code=404, content={"error": "Database file not found"})

    if fmt == "sqlite":
        # Flush WAL to main DB file first
        try:
            conn = app_instance.store.connection
            await conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except Exception:
            pass
        return FileResponse(
            path=str(db_path),
            media_type="application/x-sqlite3",
            filename="leetha.db",
        )

    elif fmt == "sql":
        import aiosqlite
        lines: list[str] = []

        async with aiosqlite.connect(str(db_path)) as db:
            # Schema
            cursor = await db.execute(
                "SELECT sql FROM sqlite_master WHERE type IN ('table', 'index') AND sql IS NOT NULL ORDER BY type DESC, name"
            )
            rows = await cursor.fetchall()
            for (ddl,) in rows:
                lines.append(f"{ddl};\n")
            lines.append("\n")

            # Data per table
            cursor = await db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
            tables = [r[0] for r in await cursor.fetchall()]
            for table in tables:
                cursor = await db.execute(f"SELECT * FROM [{table}]")  # noqa: S608
                col_names = [d[0] for d in cursor.description] if cursor.description else []
                async for row in cursor:
                    values = ", ".join(
                        "NULL" if v is None else f"'{str(v).replace(chr(39), chr(39)+chr(39))}'" if isinstance(v, str) else str(v)
                        for v in row
                    )
                    cols = ", ".join(f"[{c}]" for c in col_names)
                    lines.append(f"INSERT INTO [{table}] ({cols}) VALUES ({values});\n")
                lines.append("\n")

        content = "".join(lines)
        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="application/sql",
            headers={"Content-Disposition": "attachment; filename=leetha-dump.sql"},
        )

    return JSONResponse(status_code=400, content={"error": "Invalid format. Use 'sqlite' or 'sql'."})


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
    for kw in ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE", "REPLACE", "ATTACH", "DETACH", "PRAGMA", "LOAD_EXTENSION", "WRITEFILE", "READFILE", "FTS3_TOKENIZER"]:
        # Check as whole words to avoid false positives
        if _re.search(r'\b' + kw + r'\b', upper):
            return JSONResponse(status_code=400, content={"error": f"Forbidden keyword: {kw}"})

    # Enforce a row limit to prevent excessive memory usage
    if "limit" not in sql.lower():
        sql = sql.rstrip(";") + " LIMIT 10000"

    # Try new Store first (has verdicts, hosts, sightings, findings tables)
    try:
        conn = app_instance.store.connection
        await conn.execute("PRAGMA query_only = 1")
        try:
            cursor = await conn.execute(sql)
            rows = await cursor.fetchall()
            if rows:
                columns = [d[0] for d in cursor.description] if cursor.description else []
                return {"columns": columns, "rows": [list(r) for r in rows]}
            return {"columns": [], "rows": []}
        finally:
            await conn.execute("PRAGMA query_only = 0")
    except Exception as exc:
        import logging
        logging.getLogger(__name__).debug("Store query failed, trying legacy: %s", exc)
    # Fall back to old Database (has devices, observations, alerts, etc.)
    try:
        result = await app_instance.db.execute_readonly_query(sql)
        return result
    except Exception as e:
        import logging
        logging.getLogger(__name__).exception("Query execution failed")
        return JSONResponse(status_code=400, content={"error": "Query execution failed"})


@router.get("/api/settings/browse")
async def browse_filesystem(request: Request):
    """List directory contents for the file browser dialog."""
    import os
    from pathlib import Path as _Path

    raw_path = request.query_params.get("path", "")
    target = _Path(raw_path) if raw_path else _Path.home()

    # Resolve to absolute
    try:
        target = target.resolve()
    except (OSError, ValueError):
        return JSONResponse(status_code=400, content={"error": "Invalid path"})

    # Restrict browsing to safe directories
    allowed_roots = [os.path.expanduser("~"), "/etc/leetha", "/var/lib/leetha"]
    resolved = os.path.realpath(str(target))
    if not any(resolved.startswith(root) for root in allowed_roots):
        return JSONResponse(status_code=403, content={"error": "Access denied"})

    if not target.is_dir():
        return JSONResponse(status_code=400, content={"error": "Not a directory"})

    entries: list[dict] = []
    try:
        for item in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            # Skip hidden files unless they start with .leetha
            if item.name.startswith(".") and not item.name.startswith(".leetha"):
                continue
            try:
                entries.append({
                    "name": item.name,
                    "path": str(item),
                    "is_dir": item.is_dir(),
                    "size": item.stat().st_size if item.is_file() else None,
                })
            except (PermissionError, OSError):
                continue
    except PermissionError:
        return JSONResponse(status_code=403, content={"error": "Permission denied"})

    return {
        "current": str(target),
        "parent": str(target.parent) if target != target.parent else None,
        "entries": entries,
    }


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
