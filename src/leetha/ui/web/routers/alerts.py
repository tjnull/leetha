"""Alert/finding-related API routes."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter()


@router.get("/api/alerts")
async def api_alerts():
    from leetha.ui.web.app import app_instance, _finding_to_alert_dict

    findings = await app_instance.store.findings.list_active(limit=100)
    return [_finding_to_alert_dict(f) for f in findings]


@router.get("/api/alerts/export")
async def export_alerts(format: str = "csv"):
    """Export alerts as CSV or JSON."""
    from fastapi import HTTPException
    from fastapi.responses import Response, JSONResponse
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
        for aid in alert_ids:
            await app_instance.store.findings.resolve(aid)
        return {"status": "ok", "updated": len(alert_ids)}

    elif action == "delete":
        # Findings table doesn't support hard delete; resolve instead
        for aid in alert_ids:
            await app_instance.store.findings.resolve(aid)
        return {"status": "ok", "deleted": len(alert_ids)}

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
    except Exception:
        return {"deleted": 0}


@router.delete("/api/alerts/all")
async def api_delete_all_alerts(confirm: bool = False):
    from leetha.ui.web.app import app_instance

    if not confirm:
        return {"error": "Pass ?confirm=true to delete all alerts"}
    try:
        cursor = await app_instance.store.connection.execute(
            "DELETE FROM findings"
        )
        await app_instance.store.connection.commit()
        return {"deleted": cursor.rowcount}
    except Exception:
        return {"deleted": 0}
