"""Notification settings API routes."""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from leetha.config import save_config

router = APIRouter()


@router.get("/api/settings/notifications")
async def get_notification_settings():
    from leetha.ui.web.app import app_instance
    config = app_instance.config
    return {
        "urls": config.notification_urls,
        "min_severity": config.notification_min_severity,
    }


@router.put("/api/settings/notifications")
async def put_notification_settings(request: Request):
    from leetha.ui.web.app import app_instance
    body = await request.json()
    config = app_instance.config

    if "urls" in body:
        config.notification_urls = body["urls"]
    if "min_severity" in body:
        config.notification_min_severity = body["min_severity"]

    # Update live dispatcher (rebuild Apprise with new URLs)
    app_instance._notifier.update_urls(config.notification_urls)
    from leetha.notifications import _SEVERITY_ORDER
    app_instance._notifier._min_level = _SEVERITY_ORDER.get(
        config.notification_min_severity, 2)

    save_config(config)
    return {
        "urls": config.notification_urls,
        "min_severity": config.notification_min_severity,
    }


@router.post("/api/settings/notifications/test")
async def test_notification():
    from leetha.ui.web.app import app_instance
    from leetha.store.models import Finding, FindingRule, AlertSeverity

    if not app_instance._notifier._urls:
        return JSONResponse(status_code=400, content={"error": "No notification URLs configured"})

    finding = Finding(
        hw_addr="00:00:00:00:00:00",
        rule=FindingRule.NEW_HOST,
        severity=AlertSeverity.WARNING,
        message="Test notification from Leetha",
    )
    # Bypass rate limiting for test
    title, body = app_instance._notifier.format(finding)
    import apprise
    ap = apprise.Apprise()
    for url in app_instance._notifier._urls:
        ap.add(url)
    try:
        result = await ap.async_notify(title=title, body=body)
        if result:
            return {"status": "ok", "message": "Test notification sent"}
        return JSONResponse(status_code=500, content={"error": "Notification delivery failed"})
    except Exception as e:
        import logging
        logging.getLogger(__name__).exception("Notification test failed")
        return JSONResponse(status_code=500, content={"error": "Operation failed"})
