"""Alert/finding-related API routes."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter()


@router.get("/api/alerts")
async def api_alerts(page: int = 1, per_page: int = 100):
    from leetha.ui.web.app import app_instance, _finding_to_alert_dict

    # Clamp per_page to prevent abuse
    per_page = min(max(per_page, 1), 500)
    offset = (page - 1) * per_page
    findings = await app_instance.store.findings.list_active(
        limit=per_page, offset=offset,
    )
    total = await app_instance.store.findings.count_active()
    return {
        "alerts": [_finding_to_alert_dict(f) for f in findings],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
    }


@router.get("/api/alerts/export")
async def export_alerts(format: str = "csv"):
    """Export alerts as CSV or JSON."""
    from fastapi import HTTPException
    from fastapi.responses import Response
    from leetha.ui.web.app import app_instance, _finding_to_alert_dict
    import csv
    import io

    findings = await app_instance.store.findings.list_active(limit=10000)
    alerts = [_finding_to_alert_dict(f) for f in findings]

    alert_fields = ["id", "device_mac", "alert_type", "severity", "message", "timestamp", "acknowledged"]

    if format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=alert_fields)
        writer.writeheader()
        for a in alerts:
            writer.writerow(a)

        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=alerts.csv"},
        )

    elif format == "json":
        return JSONResponse(
            content=alerts,
            headers={"Content-Disposition": "attachment; filename=alerts.json"},
        )

    else:
        raise HTTPException(400, "Invalid format")


@router.post("/api/alerts/bulk")
async def bulk_alert_action(request: Request):
    """Bulk acknowledge or delete alerts."""
    from fastapi import HTTPException
    from leetha.ui.web.app import app_instance

    data = await request.json()
    alert_ids = data.get("ids", [])
    action = data.get("action")  # "acknowledge" | "delete"

    if action == "acknowledge":
        count = await app_instance.store.findings.resolve_many(alert_ids)
        return {"status": "ok", "updated": count}

    elif action == "delete":
        # Findings table doesn't support hard delete; resolve instead
        count = await app_instance.store.findings.resolve_many(alert_ids)
        return {"status": "ok", "deleted": count}

    else:
        raise HTTPException(400, "Invalid action")


@router.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int):
    from leetha.ui.web.app import app_instance

    await app_instance.store.findings.resolve(alert_id)
    return {"status": "ok"}


@router.delete("/api/alerts/resolved")
async def api_delete_resolved_alerts():
    from leetha.ui.web.app import app_instance

    # Findings use soft-delete (resolved flag); purge resolved rows
    try:
        cursor = await app_instance.store.connection.execute(
            "DELETE FROM findings WHERE resolved = 1"
        )
        await app_instance.store.connection.commit()
        return {"deleted": cursor.rowcount}
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to delete resolved alerts: {e}"},
        )


@router.delete("/api/alerts/all")
async def api_delete_all_alerts(confirm: bool = False):
    from leetha.ui.web.app import app_instance

    if not confirm:
        return JSONResponse(
            status_code=400,
            content={"error": "Pass ?confirm=true to delete all alerts"},
        )
    try:
        cursor = await app_instance.store.connection.execute(
            "DELETE FROM findings"
        )
        await app_instance.store.connection.commit()
        return {"deleted": cursor.rowcount}
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to delete alerts: {e}"},
        )
