"""
FastAPI web backend for LEETHA.

Serves the dashboard HTML, provides REST API endpoints for devices/alerts,
and a WebSocket for real-time updates from the capture engine.
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse

from leetha.app import LeethaApp

logger = logging.getLogger(__name__)

web_dir = Path(__file__).parent
app_instance: LeethaApp | None = None
_auth_enabled: bool = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Minimal lifespan — yields immediately. All initialization deferred."""
    yield
    # Shutdown
    if app_instance and app_instance._running:
        try:
            await app_instance.stop()
        except Exception:
            pass


fastapi_app = FastAPI(
    title="LEETHA",
    description="Network host identification and threat surface analysis",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

import re as _re

def _validate_mac(mac: str) -> str | None:
    """Validate and normalize a MAC address. Returns normalized or None."""
    mac = mac.strip().lower()
    if _re.match(r'^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$', mac):
        return mac
    return None

def _sanitize_hostname(name: str | None) -> str | None:
    """Clean mDNS service instance names globally for all API responses."""
    if not name:
        return name
    c = name.rstrip(".")
    if "._tcp." in c or "._udp." in c:
        parts = c.split("._")
        instance = parts[0]
        service = parts[1] if len(parts) > 1 else ""
        instance = _re.sub(r'-[0-9a-f]{12,}$', '', instance, flags=_re.IGNORECASE)
        if len(instance) <= 5 and service and service not in ("tcp", "udp"):
            c = service
        else:
            c = instance
    if c.endswith(".local"):
        c = c[:-6]
    c = c.rstrip(".")
    return c or name


# --- Rate limiting (in-memory token bucket) ---
import time as _time
from collections import defaultdict

class _RateLimiter:
    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self._max = max_requests
        self._window = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)

    def allow(self, client_ip: str) -> bool:
        now = _time.monotonic()
        reqs = self._requests[client_ip]
        # Remove old entries
        reqs[:] = [t for t in reqs if now - t < self._window]
        if len(reqs) >= self._max:
            return False
        reqs.append(now)
        return True

_rate_limiter = _RateLimiter(max_requests=120, window_seconds=60)


def _build_device_dict(verdict, host) -> dict:
    """Map Verdict + Host to the JSON shape the frontend expects."""
    d = {
        "mac": verdict.hw_addr if verdict else (host.hw_addr if host else ""),
        "manufacturer": verdict.vendor if verdict else None,
        "device_type": verdict.category if verdict else None,
        "os_family": verdict.platform if verdict else None,
        "os_version": verdict.platform_version if verdict else None,
        "hostname": verdict.hostname if verdict else None,
        "confidence": verdict.certainty if verdict else 0,
        "model": verdict.model if verdict else None,
        "ip_v4": host.ip_addr if host else None,
        "ip_v6": host.ip_v6 if host else None,
        "first_seen": host.discovered_at.isoformat() if host and host.discovered_at else None,
        "last_seen": host.last_active.isoformat() if host and host.last_active else None,
        "alert_status": host.disposition if host else "new",
        "is_randomized_mac": host.mac_randomized if host else False,
        "correlated_mac": host.real_hw_addr if host else None,
    }
    if verdict and verdict.evidence_chain:
        d["raw_evidence"] = {
            "chain": [e.to_dict() for e in verdict.evidence_chain[:50]],
            "source_count": len(set(e.source for e in verdict.evidence_chain)),
        }
    else:
        d["raw_evidence"] = {}
    return d


def _finding_to_alert_dict(finding) -> dict:
    """Map Finding to the alert JSON shape the frontend expects."""
    return {
        "id": finding.id,
        "device_mac": finding.hw_addr,
        "alert_type": finding.rule.value,
        "severity": finding.severity.value,
        "message": finding.message,
        "timestamp": finding.timestamp.isoformat(),
        "acknowledged": finding.resolved,
    }

@fastapi_app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        client_ip = request.client.host if request.client else "unknown"
        if not _rate_limiter.allow(client_ip):
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded. Max 120 requests/minute."}
            )
    return await call_next(request)


@fastapi_app.middleware("http")
async def _role_middleware(request: Request, call_next):
    """Enforce admin-only routes after authentication."""
    if not _auth_enabled:
        return await call_next(request)
    from leetha.auth.roles import requires_admin
    role = request.scope.get("auth_role", "anonymous")
    if request.url.path.startswith("/api/") and requires_admin(request.method, request.url.path) and role != "admin":
        return JSONResponse(status_code=403, content={"error": "Admin access required."})
    return await call_next(request)


@fastapi_app.middleware("http")
async def _auth_middleware(request: Request, call_next):
    """Authenticate API requests when auth is enabled."""
    from leetha.auth.middleware import auth_middleware as _run_auth
    db = app_instance.db if app_instance else None
    return await _run_auth(request, call_next, db=db, auth_enabled=_auth_enabled)


# GZip compression for all responses > 500 bytes
from starlette.middleware.gzip import GZipMiddleware
fastapi_app.add_middleware(GZipMiddleware, minimum_size=500)


def _require_app():
    """Return app_instance or raise 503 if still initializing."""
    if not app_instance or not app_instance._running:
        raise Exception("Service initializing")
    return app_instance



# --- HTML Routes removed — React SPA serves all pages via middleware ---


from leetha.config import save_config, _PERSISTABLE_FIELDS

@fastapi_app.get("/api/settings")
async def get_settings():
    config = app_instance.config
    return {k: getattr(config, k) for k in _PERSISTABLE_FIELDS}


@fastapi_app.put("/api/settings")
async def put_settings(request: Request):
    body = await request.json()
    config = app_instance.config
    for key, value in body.items():
        if key in _PERSISTABLE_FIELDS and hasattr(config, key):
            setattr(config, key, type(getattr(config, key))(value))
    save_config(config)
    return {k: getattr(config, k) for k in _PERSISTABLE_FIELDS}


@fastapi_app.post("/api/settings/apply")
async def apply_settings():
    return {"status": "restart_required", "message": "Please restart Leetha for changes to take effect."}


@fastapi_app.post("/api/settings/reset")
async def reset_settings():
    from leetha.config import LeethaConfig
    config = app_instance.config
    defaults = LeethaConfig(data_dir=config.data_dir, cache_dir=config.cache_dir)
    for key in _PERSISTABLE_FIELDS:
        setattr(config, key, getattr(defaults, key))
    save_config(config)
    return {k: getattr(config, k) for k in _PERSISTABLE_FIELDS}


@fastapi_app.get("/api/settings/export")
async def export_settings():
    import json as _json
    config = app_instance.config
    data = {k: getattr(config, k) for k in _PERSISTABLE_FIELDS}
    from starlette.responses import Response
    return Response(
        content=_json.dumps(data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=leetha-settings.json"},
    )


@fastapi_app.post("/api/settings/import")
async def import_settings(request: Request):
    body = await request.json()
    config = app_instance.config
    for key, value in body.items():
        if key in _PERSISTABLE_FIELDS and hasattr(config, key):
            setattr(config, key, type(getattr(config, key))(value))
    save_config(config)
    return {k: getattr(config, k) for k in _PERSISTABLE_FIELDS}


# --- Auth Endpoints ---

@fastapi_app.post("/api/auth/login")
async def api_auth_login(request: Request):
    """Validate a token and return the associated role."""
    body = await request.json()
    raw_token = body.get("token", "").strip()
    if not raw_token:
        return JSONResponse(status_code=400, content={"error": "Token required."})
    from leetha.auth.tokens import hash_token
    token_info = await app_instance.db.validate_token(hash_token(raw_token))
    if token_info is None:
        return JSONResponse(status_code=401, content={"error": "Invalid or revoked token."})
    return {"valid": True, "role": token_info["role"]}


@fastapi_app.get("/api/auth/status")
async def api_auth_status():
    """Return whether auth is enabled (public endpoint for frontend)."""
    return {"auth_enabled": _auth_enabled}


@fastapi_app.get("/api/auth/tokens")
async def api_auth_list_tokens():
    """List all tokens (admin only — enforced by role middleware)."""
    tokens = await app_instance.db.list_auth_tokens()
    return {"tokens": tokens}


@fastapi_app.post("/api/auth/tokens")
async def api_auth_create_token(request: Request):
    """Create a new token (admin only)."""
    body = await request.json()
    role = body.get("role", "analyst")
    label = body.get("label")
    if role not in ("admin", "analyst"):
        return JSONResponse(status_code=400, content={"error": "Role must be 'admin' or 'analyst'."})
    from leetha.auth.tokens import generate_token, hash_token
    raw_token = generate_token()
    token_id = await app_instance.db.create_auth_token(hash_token(raw_token), role=role, label=label)
    return {"token": raw_token, "id": token_id, "role": role}


@fastapi_app.delete("/api/auth/tokens/{token_id}")
async def api_auth_revoke_token(token_id: int):
    """Revoke a token by ID (admin only)."""
    await app_instance.db.revoke_auth_token(token_id)
    return {"status": "ok", "revoked": token_id}


@fastapi_app.get("/api/settings/db-info")
async def db_info():
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


@fastapi_app.post("/api/settings/query")
async def run_query(request: Request):
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
        import re as _re
        if _re.search(r'\b' + kw + r'\b', upper):
            return JSONResponse(status_code=400, content={"error": f"Forbidden keyword: {kw}"})

    # Enforce a row limit to prevent excessive memory usage
    if "limit" not in sql.lower():
        sql = sql.rstrip(";") + " LIMIT 10000"

    try:
        result = await app_instance.db.execute_readonly_query(sql)
        return result
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@fastapi_app.delete("/api/settings/db")
async def clear_database():
    # Clear old tables
    await app_instance.db.clear_all_devices()
    # Clear new tables (verdicts, hosts, findings, sightings)
    conn = app_instance.store.connection
    await conn.execute("DELETE FROM verdicts")
    await conn.execute("DELETE FROM hosts")
    await conn.execute("DELETE FROM findings")
    await conn.execute("DELETE FROM sightings")
    await conn.commit()
    # Clear in-memory evidence buffers
    if app_instance.pipeline:
        app_instance.pipeline._evidence_buffer.clear()
    return {"status": "ok", "message": "All devices and findings cleared."}


# --- Wiki / Information pages ---

def _find_wiki_dir() -> Path:
    """Locate the docs/wiki directory, trying multiple strategies.

    When running as ``sudo leetha --web`` the CWD may differ from the
    project root, and ``__file__`` may resolve through symlinks.  We try
    several paths to find the wiki markdown files.
    """
    candidates: list[Path] = []

    # Strategy 1: Relative to this source file (src/leetha/ui/web/app.py)
    # Walk up to project root: web/ → ui/ → leetha/ → src/ → root/
    candidates.append(
        Path(__file__).resolve().parent.parent.parent.parent.parent / "docs" / "wiki"
    )

    # Strategy 2: Relative to CWD
    candidates.append(Path.cwd() / "docs" / "wiki")

    # Strategy 3: Walk up from this file looking for docs/wiki
    current = Path(__file__).resolve().parent
    for _ in range(8):
        candidates.append(current / "docs" / "wiki")
        current = current.parent

    # Strategy 4: Bundled inside the package (leetha/docs/wiki)
    import leetha
    pkg_root = Path(leetha.__file__).resolve().parent
    candidates.append(pkg_root / "docs" / "wiki")

    for candidate in candidates:
        if candidate.is_dir():
            return candidate

    # Fallback: return first candidate (will show "not found" per page)
    logger.warning("Could not locate docs/wiki directory; searched %d paths", len(candidates))
    return candidates[0]


_WIKI_DIR = _find_wiki_dir()

# Ordered list of wiki pages: (slug, filename, display title)
_WIKI_PAGES = [
    ("home", "Home.md", "Overview"),
    ("getting-started", "Getting-Started.md", "Getting Started"),
    ("how-it-works", "How-It-Works.md", "How It Works"),
    ("fingerprint-sources", "Fingerprint-Sources.md", "Fingerprint Sources"),
    ("passive-discovery", "Passive-Network-Discovery.md", "Passive Discovery"),
    ("active-probing", "Active-Probing.md", "Active Probing"),
    ("interface-types", "Interface-Types-VPN-Capture.md", "Interface Types & VPN"),
    ("attack-surface", "Attack-Surface-Analysis.md", "Attack Surface Analysis"),
    ("spoofing-detection", "Spoofing-Detection.md", "Spoofing Detection"),
    ("web-dashboard", "Web-Dashboard.md", "Web Dashboard"),
    ("cli-reference", "CLI-Reference.md", "CLI Reference"),
]

_WIKI_SLUG_MAP = {slug: (fn, title) for slug, fn, title in _WIKI_PAGES}


# Sanitize HTML — allow only safe tags
ALLOWED_TAGS = {'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'a', 'b', 'i', 'em', 'strong',
                'code', 'pre', 'blockquote', 'ul', 'ol', 'li', 'table', 'thead', 'tbody',
                'tr', 'th', 'td', 'br', 'hr', 'img', 'span', 'div', 'dl', 'dt', 'dd'}
ALLOWED_ATTRS = {'a': ['href', 'title'], 'img': ['src', 'alt'], 'td': ['align'], 'th': ['align']}

def _sanitize_html(html: str) -> str:
    """Strip dangerous HTML tags, keeping only safe formatting."""
    import re as _re_san
    # Remove script/style/iframe/object/embed tags and their content
    html = _re_san.sub(r'<(script|style|iframe|object|embed|form|input|button)[^>]*>.*?</\1>', '', html, flags=_re_san.DOTALL | _re_san.IGNORECASE)
    html = _re_san.sub(r'<(script|style|iframe|object|embed|form|input|button)[^>]*/>', '', html, flags=_re_san.IGNORECASE)
    # Remove on* event handlers from any tag
    html = _re_san.sub(r'\s+on\w+\s*=\s*["\'][^"\']*["\']', '', html, flags=_re_san.IGNORECASE)
    html = _re_san.sub(r'\s+on\w+\s*=\s*\S+', '', html, flags=_re_san.IGNORECASE)
    # Remove javascript: URLs
    html = _re_san.sub(r'href\s*=\s*["\']javascript:[^"\']*["\']', 'href="#"', html, flags=_re_san.IGNORECASE)
    return html


def _render_wiki_page(slug: str) -> tuple[str, str]:
    """Load and render a wiki markdown file. Returns (html, title)."""
    import markdown

    entry = _WIKI_SLUG_MAP.get(slug)
    if not entry:
        return "<p>Page not found.</p>", "Not Found"

    filename, title = entry
    filepath = _WIKI_DIR / filename
    if not filepath.exists():
        logger.warning("Wiki file not found: %s (wiki_dir=%s)", filepath, _WIKI_DIR)
        return (
            f"<p>Wiki file <code>{filename}</code> not found.</p>"
            f"<p style='color:var(--text-tertiary);font-size:0.8rem;'>"
            f"Searched: <code>{filepath}</code></p>",
            title,
        )

    md_text = filepath.read_text(encoding="utf-8")

    # Convert inter-wiki links: [Text](Getting-Started.md) → [Text](/info/getting-started)
    import re
    for s, fn, _ in _WIKI_PAGES:
        md_text = re.sub(
            rf'\]\({re.escape(fn)}\)',
            f'](/info/{s})',
            md_text,
        )

    html = markdown.markdown(
        md_text,
        extensions=["tables", "fenced_code", "toc"],
    )
    html = _sanitize_html(html)
    return html, title


@fastapi_app.get("/api/wiki/{slug}")
async def api_wiki_page(slug: str):
    """Return rendered wiki HTML content for the React frontend."""
    content_html, page_title = _render_wiki_page(slug)
    return {"slug": slug, "title": page_title, "html": content_html}


@fastapi_app.get("/api/wiki")
async def api_wiki_pages():
    """Return list of wiki pages."""
    return {"pages": [{"slug": s, "title": t} for s, _, t in _WIKI_PAGES]}


@fastapi_app.get("/info")
async def info_index(request: Request):
    """Redirect /info to the first wiki page."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/info/home", status_code=302)


# --- REST API ---

@fastapi_app.get("/api/devices")
async def api_devices(
    page: int = 1,
    per_page: int = 50,
    sort: str = "last_seen",
    order: str = "desc",
    q: str | None = None,
    manufacturer: str | None = None,
    device_type: str | None = None,
    os_family: str | None = None,
    alert_status: str | None = None,
    interface: str | None = None,
    confidence_min: int | None = None,
    raw: bool = False,
):
    """Paginated, filtered, sorted device list."""
    # Read from new Verdict/Host tables (Store)
    verdicts = await app_instance.store.verdicts.find_all(limit=500)
    result = []
    for v in verdicts:
        h = await app_instance.store.hosts.find_by_addr(v.hw_addr)
        result.append(_build_device_dict(v, h))

    # Apply search filter
    if q:
        q_lower = q.lower()
        result = [
            d for d in result
            if q_lower in (d.get("mac") or "").lower()
            or q_lower in (d.get("hostname") or "").lower()
            or q_lower in (d.get("manufacturer") or "").lower()
            or q_lower in (d.get("ip_v4") or "").lower()
        ]

    if manufacturer:
        result = [d for d in result if d.get("manufacturer") == manufacturer]
    if device_type:
        result = [d for d in result if d.get("device_type") == device_type]
    if os_family:
        result = [d for d in result if d.get("os_family") == os_family]
    if alert_status:
        result = [d for d in result if d.get("alert_status") == alert_status]
    if confidence_min is not None:
        result = [d for d in result if (d.get("confidence") or 0) >= confidence_min]

    # Sanitize hostnames
    for d in result:
        d["hostname"] = _sanitize_hostname(d.get("hostname"))

    total = len(result)
    start = (page - 1) * per_page
    end = start + per_page
    page_devices = result[start:end]

    return {
        "devices": page_devices,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
    }


@fastapi_app.get("/api/devices/export")
async def export_devices(
    format: str = "csv",
    q: str | None = None,
    manufacturer: str | None = None,
    device_type: str | None = None,
    os_family: str | None = None,
    alert_status: str | None = None,
):
    """Export devices as CSV or JSON, respecting current filters."""
    from fastapi import HTTPException
    from fastapi.responses import Response, JSONResponse
    import csv
    import io

    # Build device dicts from verdicts+hosts
    verdicts = await app_instance.store.verdicts.find_all(limit=10000)
    all_devices = []
    for v in verdicts:
        h = await app_instance.store.hosts.find_by_addr(v.hw_addr)
        all_devices.append(_build_device_dict(v, h))

    # Apply filters
    if q:
        q_lower = q.lower()
        all_devices = [
            d for d in all_devices
            if q_lower in (d.get("mac") or "").lower()
            or q_lower in (d.get("ip_v4") or "").lower()
            or q_lower in (d.get("hostname") or "").lower()
            or q_lower in (d.get("manufacturer") or "").lower()
        ]
    if manufacturer:
        all_devices = [d for d in all_devices if d.get("manufacturer") == manufacturer]
    if device_type:
        all_devices = [d for d in all_devices if d.get("device_type") == device_type]
    if os_family:
        all_devices = [d for d in all_devices if d.get("os_family") == os_family]
    if alert_status:
        all_devices = [d for d in all_devices if d.get("alert_status") == alert_status]

    csv_fields = [
        "mac", "ip_v4", "ip_v6", "manufacturer", "device_type",
        "os_family", "os_version", "hostname", "confidence",
        "first_seen", "last_seen", "alert_status",
    ]

    if format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=csv_fields)
        writer.writeheader()
        for d in all_devices:
            writer.writerow({k: d.get(k) for k in csv_fields})

        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=devices.csv"},
        )

    elif format == "json":
        export_data = []
        for d in all_devices:
            dd = dict(d)
            dd.pop("raw_evidence", None)
            export_data.append(dd)
        return JSONResponse(
            content=export_data,
            headers={"Content-Disposition": "attachment; filename=devices.json"},
        )

    else:
        raise HTTPException(400, "Invalid format. Use csv or json.")


@fastapi_app.get("/api/alerts/export")
async def export_alerts(format: str = "csv"):
    """Export alerts as CSV or JSON."""
    from fastapi import HTTPException
    from fastapi.responses import Response, JSONResponse
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


@fastapi_app.post("/api/devices/bulk")
async def bulk_device_action(request: Request):
    """Bulk update device status."""
    from fastapi import HTTPException

    data = await request.json()
    macs = data.get("macs", [])
    action = data.get("action")  # "mark_known" | "mark_suspicious"

    if action == "mark_known":
        status = "known"
    elif action == "mark_suspicious":
        status = "suspicious"
    else:
        raise HTTPException(400, "Invalid action. Use mark_known or mark_suspicious.")

    updated = 0
    for mac in macs:
        host = await app_instance.store.hosts.find_by_addr(mac)
        if host:
            host.disposition = status
            await app_instance.store.hosts.upsert(host)
            updated += 1

    return {"status": "ok", "updated": updated}


@fastapi_app.post("/api/alerts/bulk")
async def bulk_alert_action(request: Request):
    """Bulk acknowledge or delete alerts."""
    from fastapi import HTTPException

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


@fastapi_app.get("/api/devices/{mac}")
async def api_device(mac: str):
    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})
    verdict = await app_instance.store.verdicts.find_by_addr(mac)
    host = await app_instance.store.hosts.find_by_addr(mac)
    if not verdict and not host:
        return JSONResponse(status_code=404, content={"error": "Device not found"})
    device = _build_device_dict(verdict, host)
    device["hostname"] = _sanitize_hostname(device.get("hostname"))
    # Include sightings as observations for compatibility
    try:
        sightings = await app_instance.store.sightings.for_host(mac)
    except Exception:
        sightings = []
    return {
        "device": device,
        "observations": [
            {
                "source_type": s.source,
                "raw_data": json.dumps(s.payload) if isinstance(s.payload, dict) else str(s.payload),
                "match_result": json.dumps(s.analysis) if isinstance(s.analysis, dict) else str(s.analysis),
                "confidence": int(s.certainty * 100) if s.certainty <= 1 else int(s.certainty),
                "timestamp": s.timestamp.isoformat() if s.timestamp else None,
            }
            for s in sightings
        ],
    }


@fastapi_app.get("/api/devices/{mac}/override")
async def get_device_override(mac: str):
    """Get the manual override for a device.

    TODO: migrate overrides to new schema — currently still reads from old devices table.
    """
    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})
    try:
        device = await app_instance.db.get_device(mac)
    except Exception:
        device = None
    if device is None:
        return {"mac": mac, "override": None}
    return {"mac": mac, "override": device.manual_override}


@fastapi_app.put("/api/devices/{mac}/override")
async def set_device_override(mac: str, request: Request):
    """Set or update the manual override for a device.

    TODO: migrate overrides to new schema — currently still writes to old devices table.
    """
    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})
    device = await app_instance.db.get_device(mac)
    if device is None:
        return JSONResponse(status_code=404, content={"error": "Device not found"})

    override_data = await request.json()

    # Only allow known override fields
    allowed_fields = {"device_type", "manufacturer", "os_family", "os_version", "model"}
    filtered = {k: v for k, v in override_data.items() if k in allowed_fields}

    if not filtered:
        return JSONResponse(status_code=400, content={"error": "No valid override fields provided"})

    device.manual_override = filtered

    # Apply override to device fields immediately
    for field in ("device_type", "manufacturer", "os_family", "os_version"):
        val = filtered.get(field)
        if val is not None:
            setattr(device, field, val)

    await app_instance.db.upsert_device(device)
    return {"status": "ok", "mac": mac, "override": filtered}


@fastapi_app.delete("/api/devices/{mac}/override")
async def delete_device_override(mac: str):
    """Clear the manual override for a device.

    TODO: migrate overrides to new schema — currently still writes to old devices table.
    """
    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})
    try:
        device = await app_instance.db.get_device(mac)
    except Exception:
        device = None
    if device is None:
        return {"status": "ok", "mac": mac}

    device.manual_override = None
    await app_instance.db.upsert_device(device)
    return {"status": "ok", "mac": mac}


@fastapi_app.get("/api/trust")
async def api_trust_list():
    """List all trusted MAC/IP bindings."""
    bindings = await app_instance.db.list_trusted_bindings()
    return {"bindings": bindings}


@fastapi_app.post("/api/trust")
async def api_trust_add(request: Request):
    """Add a trusted MAC/IP binding."""
    data = await request.json()
    mac = data.get("mac", "").lower()
    ip = data.get("ip", "")
    if not mac or not ip:
        return JSONResponse({"error": "mac and ip required"}, status_code=400)
    await app_instance.db.add_trusted_binding(mac, ip, "manual", None)
    if hasattr(app_instance, "spoofing_detector"):
        app_instance.spoofing_detector._addr_associations[ip] = mac
    return {"status": "ok", "mac": mac, "ip": ip}


@fastapi_app.delete("/api/trust/{mac}")
async def api_trust_remove(mac: str):
    """Remove a trusted binding."""
    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})
    mac = mac.lower()
    await app_instance.db.remove_trusted_binding(mac)
    if hasattr(app_instance, "spoofing_detector"):
        to_remove = [
            ip for ip, m in app_instance.spoofing_detector._addr_associations.items()
            if m == mac
        ]
        for ip in to_remove:
            del app_instance.spoofing_detector._addr_associations[ip]
    return {"status": "ok"}


@fastapi_app.get("/api/devices/{mac}/arp-history")
async def api_device_arp_history(mac: str):
    """Get ARP history for a device."""
    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})
    history = await app_instance.db.get_arp_history_for_mac(mac.lower())
    return {"history": history}


# --- Suppression Rules API ---

@fastapi_app.get("/api/suppressions")
async def api_suppressions_list():
    """List all suppression rules."""
    rules = await app_instance.db.list_suppression_rules()
    return {"rules": rules}


@fastapi_app.post("/api/suppressions")
async def api_suppressions_add(request: Request):
    """Create a suppression rule."""
    data = await request.json()
    mac = data.get("mac") or None
    ip = data.get("ip") or None
    subtype = data.get("subtype") or None
    reason = data.get("reason", "")
    if not mac and not ip and not subtype:
        return JSONResponse({"error": "At least one of mac, ip, or subtype required"}, status_code=400)
    rule_id = await app_instance.db.add_suppression_rule(mac=mac, ip=ip, subtype=subtype, reason=reason)
    # Reload suppression cache in detector
    if hasattr(app_instance, "spoofing_detector"):
        await app_instance.spoofing_detector.reload_suppressions()
    return {"status": "ok", "id": rule_id}


@fastapi_app.delete("/api/suppressions/{rule_id}")
async def api_suppressions_remove(rule_id: int):
    """Remove a suppression rule."""
    await app_instance.db.remove_suppression_rule(rule_id)
    if hasattr(app_instance, "spoofing_detector"):
        await app_instance.spoofing_detector.reload_suppressions()
    return {"status": "ok"}


# --- ARP History API ---

@fastapi_app.get("/api/arp-history")
async def api_arp_history(mac: str | None = None, ip: str | None = None):
    """Query ARP history by MAC or IP."""
    if mac:
        history = await app_instance.db.get_arp_history_for_mac(mac.lower())
    elif ip:
        history = await app_instance.db.get_arp_history_for_ip(ip)
    else:
        return JSONResponse({"error": "Provide mac or ip query parameter"}, status_code=400)
    return {"history": history}


@fastapi_app.get("/api/patterns")
async def get_custom_patterns():
    """Get all custom patterns."""
    from leetha.fingerprint.lookup import load_custom_patterns
    patterns = load_custom_patterns(app_instance.config.data_dir)
    return patterns


@fastapi_app.post("/api/patterns/{pattern_type}")
async def add_custom_pattern(pattern_type: str, request: Request):
    """Add a custom pattern of the given type."""
    from leetha.fingerprint.lookup import load_custom_patterns, save_custom_patterns

    allowed_types = {"hostname", "dhcp_opt55", "dhcp_opt60", "mac_prefix"}
    if pattern_type not in allowed_types:
        return JSONResponse(status_code=400, content={"error": f"Invalid type. Use: {', '.join(allowed_types)}"})

    entry = await request.json()
    patterns = load_custom_patterns(app_instance.config.data_dir)

    if pattern_type == "dhcp_opt55":
        # opt55 is a dict keyed by option list
        if "key" not in entry:
            return JSONResponse(status_code=400, content={"error": "dhcp_opt55 requires a 'key' field"})
        patterns.setdefault("dhcp_opt55", {})[entry.pop("key")] = entry
    elif pattern_type == "mac_prefix":
        if "prefix" not in entry:
            return JSONResponse(status_code=400, content={"error": "mac_prefix requires a 'prefix' field"})
        patterns.setdefault("mac_prefix", {})[entry.pop("prefix")] = entry
    else:
        # hostname, dhcp_opt60 are lists
        patterns.setdefault(pattern_type, []).append(entry)

    save_custom_patterns(app_instance.config.data_dir, patterns)

    # Reload patterns into fingerprint engine
    app_instance.fingerprint_engine.lookup.load_custom_patterns(app_instance.config.data_dir)

    return {"status": "ok", "type": pattern_type}


@fastapi_app.delete("/api/patterns/{pattern_type}/{index}")
async def delete_custom_pattern(pattern_type: str, index: int):
    """Delete a custom pattern by type and index."""
    from leetha.fingerprint.lookup import load_custom_patterns, save_custom_patterns

    patterns = load_custom_patterns(app_instance.config.data_dir)

    if pattern_type not in patterns:
        return JSONResponse(status_code=404, content={"error": f"No patterns of type '{pattern_type}'"})

    entries = patterns[pattern_type]
    if isinstance(entries, list):
        if index < 0 or index >= len(entries):
            return JSONResponse(status_code=404, content={"error": "Index out of range"})
        entries.pop(index)
    elif isinstance(entries, dict):
        keys = list(entries.keys())
        if index < 0 or index >= len(keys):
            return JSONResponse(status_code=404, content={"error": "Index out of range"})
        del entries[keys[index]]

    save_custom_patterns(app_instance.config.data_dir, patterns)

    # Reload patterns
    app_instance.fingerprint_engine.lookup.load_custom_patterns(app_instance.config.data_dir)

    return {"status": "ok", "type": pattern_type}


@fastapi_app.post("/api/validate")
async def api_run_validation():
    """Trigger a validation run."""
    from leetha.analysis.validator import run_validation
    report = await run_validation(app_instance.db, app_instance.config.cache_dir)

    # Save report
    report_path = app_instance.config.data_dir / "validation_report.json"
    import json as _json
    with open(report_path, "w") as f:
        _json.dump(report, f, indent=2)

    return report


@fastapi_app.get("/api/validate/report")
async def api_get_validation_report():
    """Get the latest validation report."""
    report_path = app_instance.config.data_dir / "validation_report.json"
    if not report_path.is_file():
        return JSONResponse(status_code=404, content={"error": "No validation report found. Run validation first."})

    import json as _json
    with open(report_path) as f:
        return _json.load(f)


@fastapi_app.get("/api/devices/{mac}/detail")
async def get_device_detail(mac: str):
    """Full device info + evidence breakdown."""
    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})
    from fastapi import HTTPException

    verdict = await app_instance.store.verdicts.find_by_addr(mac)
    host = await app_instance.store.hosts.find_by_addr(mac)
    if not verdict and not host:
        raise HTTPException(404, "Device not found")

    device = _build_device_dict(verdict, host)
    device["hostname"] = _sanitize_hostname(device.get("hostname"))
    evidence = device.get("raw_evidence", {})

    return {
        "device": device,
        "evidence": evidence,
    }


@fastapi_app.get("/api/devices/{mac}/coverage")
async def get_device_coverage(mac: str):
    """Diagnostic: what evidence sources have been observed for this device."""
    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})
    verdict = await app_instance.store.verdicts.find_by_addr(mac)
    host = await app_instance.store.hosts.find_by_addr(mac)
    if not verdict and not host:
        return JSONResponse(status_code=404, content={"error": "Device not found"})

    device = _build_device_dict(verdict, host)

    # Get observation source types from sightings
    try:
        cursor = await app_instance.store.connection.execute(
            "SELECT source, COUNT(*) as cnt, MAX(timestamp) as last "
            "FROM sightings WHERE hw_addr = ? GROUP BY source ORDER BY cnt DESC",
            (mac,),
        )
        rows = await cursor.fetchall()
        observed_sources = {r[0]: {"count": r[1], "last_seen": r[2]} for r in rows}
    except Exception:
        observed_sources = {}

    # Define all possible sources and what they provide
    ALL_SOURCES = {
        "arp": {"provides": ["MAC-IP binding"], "passive": True, "layer": "L2"},
        "tcp_syn": {"provides": ["OS family (TTL)", "TCP stack fingerprint"], "passive": True, "layer": "L3"},
        "dhcpv4": {"provides": ["Hostname", "Vendor class", "OS fingerprint", "Device type"], "passive": True, "layer": "L3"},
        "dhcpv6": {"provides": ["IPv6 fingerprint", "Enterprise ID", "Vendor class"], "passive": True, "layer": "L3"},
        "mdns": {"provides": ["Device model", "Friendly name", "Services", "Manufacturer"], "passive": True, "layer": "L3 multicast"},
        "ssdp": {"provides": ["Manufacturer", "Model", "Firmware", "Device description"], "passive": True, "layer": "L3 multicast"},
        "dns": {"provides": ["Hostname patterns", "Cloud services used"], "passive": True, "layer": "L3"},
        "tls": {"provides": ["JA3/JA4 fingerprint", "SNI (services used)"], "passive": True, "layer": "L4"},
        "http_useragent": {"provides": ["OS", "Browser", "Device type", "App identification"], "passive": True, "layer": "L7"},
        "netbios": {"provides": ["NetBIOS name", "Workgroup", "OS hints"], "passive": True, "layer": "L3"},
        "icmpv6": {"provides": ["IPv6 RA info", "Router identification"], "passive": True, "layer": "L3"},
        "lldp": {"provides": ["Switch/router model", "Port", "System name", "Capabilities"], "passive": True, "layer": "L2"},
        "cdp": {"provides": ["Cisco device ID", "Platform", "Software version", "VLAN"], "passive": True, "layer": "L2"},
        "snmp": {"provides": ["Community string", "Device version", "Management info"], "passive": True, "layer": "L3"},
        "banner": {"provides": ["Service version", "Protocol identification"], "passive": False, "layer": "L7"},
        "ip_observed": {"provides": ["IP-MAC mapping", "TTL-based OS hint"], "passive": True, "layer": "L3"},
    }

    # Build coverage report
    observed = []
    missing = []
    for source, info in ALL_SOURCES.items():
        entry = {
            "source": source,
            "provides": info["provides"],
            "passive": info["passive"],
            "layer": info["layer"],
        }
        if source in observed_sources:
            entry["status"] = "observed"
            entry["count"] = observed_sources[source]["count"]
            entry["last_seen"] = observed_sources[source]["last_seen"]
            observed.append(entry)
        else:
            entry["status"] = "not_observed"
            entry["count"] = 0
            missing.append(entry)

    # Generate recommendations
    recommendations = []
    missing_names = {m["source"] for m in missing}

    if "mdns" in missing_names:
        recommendations.append({
            "priority": "high",
            "message": "No mDNS data observed. mDNS reveals device model, friendly name, and services.",
            "action": "Ensure capture interface is on the same VLAN as this device, or enable mDNS reflection on your gateway. Alternatively, enable active probing to send mDNS queries.",
        })
    if "ssdp" in missing_names:
        recommendations.append({
            "priority": "high",
            "message": "No SSDP/UPnP data observed. SSDP reveals manufacturer, model, and firmware.",
            "action": "SSDP is multicast — capture must be on the same subnet. Enable SSDP probing for cross-VLAN discovery.",
        })
    if "dhcpv4" in missing_names and "dhcpv6" in missing_names:
        recommendations.append({
            "priority": "medium",
            "message": "No DHCP data observed. DHCP reveals hostname, vendor class, and OS fingerprint.",
            "action": "DHCP broadcasts are VLAN-local. Wait for the device to renew its lease, or capture on the device's VLAN.",
        })
    if "tcp_syn" in missing_names:
        recommendations.append({
            "priority": "medium",
            "message": "No TCP SYN observed. TCP fingerprinting reveals OS family via TTL and window size.",
            "action": "This device may not initiate TCP connections through the capture point. Consider capturing closer to the device.",
        })
    if "tls" in missing_names and "http_useragent" in missing_names:
        recommendations.append({
            "priority": "low",
            "message": "No HTTP/TLS traffic observed. These reveal OS, browser, and cloud services.",
            "action": "This device may not use web services, or traffic is routed through a different path.",
        })
    if "lldp" in missing_names and device.get("device_type") in ("switch", "router", "access_point"):
        recommendations.append({
            "priority": "high",
            "message": "No LLDP data observed for a network device. LLDP reveals exact model and firmware.",
            "action": "Ensure LLDP is enabled on this device. Capture must be on a directly connected port.",
        })

    # Evidence quality score
    raw_ev = device.get("raw_evidence", {})
    evidence_count = len(raw_ev.get("chain", [])) if isinstance(raw_ev, dict) else 0
    source_count = len(observed)
    quality = "excellent" if source_count >= 5 else "good" if source_count >= 3 else "limited" if source_count >= 2 else "minimal"

    return {
        "mac": mac,
        "confidence": device.get("confidence", 0),
        "evidence_count": evidence_count,
        "source_count": source_count,
        "quality": quality,
        "observed": observed,
        "missing": missing,
        "recommendations": recommendations,
    }


@fastapi_app.get("/api/capture/visibility")
async def get_capture_visibility():
    """Subnet/VLAN visibility report — shows coverage gaps per network segment."""
    import ipaddress

    try:
        # Get all devices with IPs and their sighting source types
        cursor = await app_instance.store.connection.execute(
            "SELECT h.hw_addr, h.ip_addr, v.vendor, v.category, v.certainty, v.hostname, "
            "  GROUP_CONCAT(DISTINCT s.source) as sources, "
            "  COUNT(DISTINCT s.source) as source_count "
            "FROM hosts h "
            "LEFT JOIN verdicts v ON h.hw_addr = v.hw_addr "
            "LEFT JOIN sightings s ON h.hw_addr = s.hw_addr "
            "WHERE h.ip_addr IS NOT NULL "
            "GROUP BY h.hw_addr"
        )
        raw_rows = await cursor.fetchall()

        # Group by /24 subnet
        subnets: dict[str, dict] = {}
        for r in raw_rows:
            mac, ip, mfr, dtype, conf, hostname, sources, src_count = (
                r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]
            )
            try:
                net = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            except (ValueError, TypeError):
                continue

            if net not in subnets:
                subnets[net] = {
                    "subnet": net,
                    "devices": [],
                    "total": 0,
                    "protocols_seen": set(),
                    "rich_evidence": 0,  # 3+ sources
                    "limited_evidence": 0,  # 1-2 sources
                    "no_evidence": 0,  # 0 sources
                }

            sub = subnets[net]
            sub["total"] += 1
            source_list = sources.split(",") if sources else []
            sub["protocols_seen"].update(source_list)

            src_count_int = int(src_count) if src_count else 0
            if src_count_int >= 3:
                sub["rich_evidence"] += 1
            elif src_count_int >= 1:
                sub["limited_evidence"] += 1
            else:
                sub["no_evidence"] += 1

            sub["devices"].append({
                "mac": mac, "ip": ip, "manufacturer": mfr,
                "device_type": dtype, "confidence": conf,
                "hostname": hostname, "sources": source_list,
                "source_count": src_count_int,
            })

        # Build visibility report per subnet
        result = []
        for net, sub in sorted(subnets.items(), key=lambda x: -x[1]["total"]):
            protocols_seen = sub["protocols_seen"] - {""}
            has_l2 = bool(protocols_seen & {"arp", "lldp", "cdp", "stp"})
            has_dhcp = bool(protocols_seen & {"dhcpv4", "dhcpv6"})
            has_mdns = "mdns" in protocols_seen
            has_ssdp = "ssdp" in protocols_seen
            has_tcp = bool(protocols_seen & {"tcp_syn", "tls"})
            has_dns = "dns" in protocols_seen

            # Calculate visibility score
            score_parts = []
            if has_l2: score_parts.append("L2")
            if has_dhcp: score_parts.append("DHCP")
            if has_mdns: score_parts.append("mDNS")
            if has_ssdp: score_parts.append("SSDP")
            if has_tcp: score_parts.append("TCP/TLS")
            if has_dns: score_parts.append("DNS")

            visibility = len(score_parts)
            if visibility >= 5:
                level = "excellent"
            elif visibility >= 3:
                level = "good"
            elif visibility >= 2:
                level = "partial"
            else:
                level = "limited"

            gaps = []
            if not has_mdns:
                gaps.append({"protocol": "mDNS", "impact": "Cannot identify IoT device models, smart speakers, Apple devices", "fix": "Capture on this VLAN or enable mDNS reflection"})
            if not has_ssdp:
                gaps.append({"protocol": "SSDP", "impact": "Cannot discover UPnP devices (TVs, media players, printers)", "fix": "Capture on this VLAN or enable SSDP probing"})
            if not has_dhcp:
                gaps.append({"protocol": "DHCP", "impact": "Missing hostnames, vendor class, OS fingerprints", "fix": "Capture on this VLAN or wait for lease renewals"})
            if not has_tcp:
                gaps.append({"protocol": "TCP/TLS", "impact": "No OS fingerprinting via TCP stack, no JA3/JA4", "fix": "Ensure traffic from this subnet routes through capture point"})
            if not has_l2:
                gaps.append({"protocol": "L2 (ARP/LLDP)", "impact": "No Layer 2 visibility — cannot detect spoofing or infrastructure", "fix": "Capture on this VLAN directly"})

            result.append({
                "subnet": net,
                "total_devices": sub["total"],
                "visibility_level": level,
                "visibility_score": visibility,
                "protocols_seen": sorted(protocols_seen),
                "coverage_summary": score_parts,
                "rich_evidence": sub["rich_evidence"],
                "limited_evidence": sub["limited_evidence"],
                "no_evidence": sub["no_evidence"],
                "gaps": gaps,
                "devices": sorted(sub["devices"], key=lambda d: -d["source_count"])[:20],
            })

        return {"subnets": result}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@fastapi_app.get("/api/capture/health")
async def get_capture_health():
    """Diagnostic: overall capture health and protocol coverage."""
    try:
        conn = app_instance.store.connection

        # Protocol counts in last hour
        cursor = await conn.execute(
            "SELECT source, COUNT(*) as cnt FROM sightings "
            "WHERE timestamp > datetime('now', '-1 hour') "
            "GROUP BY source ORDER BY cnt DESC"
        )
        proto_rows = await cursor.fetchall()
        recent_protocols = {r[0]: r[1] for r in proto_rows}

        # Total device count
        total_devices = await app_instance.store.hosts.count()

        # Devices with only ARP evidence
        cursor = await conn.execute(
            "SELECT COUNT(DISTINCT hw_addr) FROM sightings "
            "WHERE hw_addr NOT IN ("
            "  SELECT DISTINCT hw_addr FROM sightings WHERE source != 'arp' AND source != 'ip_observed'"
            ")"
        )
        row = await cursor.fetchone()
        arp_only_count = row[0] if row else 0

        # Devices with high evidence (3+ sources)
        cursor = await conn.execute(
            "SELECT COUNT(*) FROM ("
            "  SELECT hw_addr, COUNT(DISTINCT source) as src_count FROM sightings "
            "  GROUP BY hw_addr HAVING src_count >= 3"
            ")"
        )
        row = await cursor.fetchone()
        rich_count = row[0] if row else 0

        # VLAN detection: devices seen on multiple subnets
        cursor = await conn.execute(
            "SELECT hw_addr, GROUP_CONCAT(DISTINCT ip_addr) as ips FROM hosts "
            "WHERE ip_addr IS NOT NULL GROUP BY hw_addr "
            "HAVING COUNT(DISTINCT SUBSTR(ip_addr, 1, INSTR(ip_addr, '.') + INSTR(SUBSTR(ip_addr, INSTR(ip_addr, '.') + 1), '.'))) > 1"
        )
        multi_subnet_rows = await cursor.fetchall()
        multi_subnet_devices = len(multi_subnet_rows)

        issues = []
        if "mdns" not in recent_protocols:
            issues.append({"severity": "warning", "message": "No mDNS traffic captured in the last hour. IoT device identification will be limited."})
        if "ssdp" not in recent_protocols:
            issues.append({"severity": "warning", "message": "No SSDP traffic captured. UPnP device discovery is not available."})
        if "dhcpv4" not in recent_protocols and "dhcpv6" not in recent_protocols:
            issues.append({"severity": "warning", "message": "No DHCP traffic captured. Hostname and vendor identification will be limited."})
        if "lldp" not in recent_protocols and "cdp" not in recent_protocols:
            issues.append({"severity": "info", "message": "No LLDP/CDP traffic captured. Network infrastructure identification relies on OUI only."})
        if arp_only_count > total_devices * 0.5:
            issues.append({"severity": "warning", "message": f"{arp_only_count} of {total_devices} devices have only ARP evidence. Consider capturing on additional VLANs or enabling probing."})

        return {
            "total_devices": total_devices,
            "protocols_last_hour": recent_protocols,
            "arp_only_devices": arp_only_count,
            "rich_evidence_devices": rich_count,
            "multi_subnet_devices": multi_subnet_devices,
            "issues": issues,
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@fastapi_app.get("/api/devices/{mac}/observations")
async def get_device_observations(mac: str, limit: int = 50, offset: int = 0):
    """Paginated observation history."""
    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})
    try:
        sightings = await app_instance.store.sightings.for_host(mac, limit=limit)
        # Get total count
        conn = app_instance.store.connection
        cursor = await conn.execute(
            "SELECT COUNT(*) FROM sightings WHERE hw_addr = ?", (mac,)
        )
        row = await cursor.fetchone()
        total = row[0] if row else 0
    except Exception:
        sightings = []
        total = 0

    observations = [
        {
            "source_type": s.source,
            "timestamp": s.timestamp.isoformat() if hasattr(s.timestamp, 'isoformat') else str(s.timestamp),
            "raw_data": s.payload,
            "certainty": s.certainty,
        }
        for s in sightings
    ]

    return {
        "observations": observations,
        "total": total,
        "has_more": (offset + limit) < total,
    }


@fastapi_app.get("/api/devices/{mac}/activity")
async def get_device_activity(mac: str):
    """24-hour packet activity (hourly buckets)."""
    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})
    try:
        conn = app_instance.store.connection
        cursor = await conn.execute(
            "SELECT strftime('%H', timestamp) as hour, COUNT(*) as cnt "
            "FROM sightings WHERE hw_addr = ? AND timestamp > datetime('now', '-24 hours') "
            "GROUP BY hour ORDER BY hour",
            (mac,))
        rows = await cursor.fetchall()
        activity = {row[0]: row[1] for row in rows}
    except Exception:
        activity = {}
    return {"hourly_counts": activity}


@fastapi_app.get("/api/devices/{mac}/timeline")
async def get_device_timeline(mac: str, limit: int = 100):
    """Chronological event timeline for a device."""
    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})

    from leetha.timeline import build_timeline

    verdict = await app_instance.store.verdicts.find_by_addr(mac)
    host = await app_instance.store.hosts.find_by_addr(mac)
    device_dict = _build_device_dict(verdict, host) if (verdict or host) else None

    # Get sightings as observations
    try:
        sightings = await app_instance.store.sightings.for_host(mac, limit=200)
    except Exception:
        sightings = []
    observations = [{"timestamp": s.timestamp.isoformat() if hasattr(s.timestamp, 'isoformat') else str(s.timestamp),
                      "source_type": s.source, "raw_data": json.dumps(s.payload) if isinstance(s.payload, dict) else str(s.payload),
                      "confidence": int(s.certainty * 100) if s.certainty <= 1 else int(s.certainty)} for s in sightings]

    fp_history = []
    try:
        async with app_instance.db.db.execute(
            "SELECT timestamp, device_type, manufacturer, os_family, hostname, oui_vendor FROM fingerprint_history WHERE mac = ? ORDER BY timestamp DESC LIMIT 50",
            (mac,),
        ) as cursor:
            fp_history = [dict(row) for row in await cursor.fetchall()]
    except Exception:
        pass

    arp_history = []
    try:
        arp_history = await app_instance.db.get_arp_history_for_mac(mac)
    except Exception:
        pass

    # Get findings for this device as alert-compatible dicts
    findings = []
    try:
        cursor = await app_instance.store.connection.execute(
            "SELECT rule, severity, message, timestamp FROM findings WHERE hw_addr = ? ORDER BY timestamp DESC LIMIT 50",
            (mac,),
        )
        for row in await cursor.fetchall():
            findings.append({"alert_type": row[0], "severity": row[1], "message": row[2], "timestamp": row[3]})
    except Exception:
        pass

    events = build_timeline(
        mac=mac, device=device_dict, observations=observations,
        fingerprint_history=fp_history, arp_history=arp_history,
        findings=findings, limit=limit,
    )

    return {"events": events, "total": len(events)}


@fastapi_app.get("/api/devices/{mac}/services")
async def get_device_services(mac: str):
    """Return active probe results for a device."""
    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})
    services = await app_instance.db.get_device_services(mac)
    return services


_attack_surface_cache = None
_attack_surface_cache_ts = 0.0
_ATTACK_SURFACE_TTL = 30.0  # seconds


async def _get_cached_attack_surface():
    global _attack_surface_cache, _attack_surface_cache_ts
    now = _time.monotonic()
    if _attack_surface_cache is None or (now - _attack_surface_cache_ts) > _ATTACK_SURFACE_TTL:
        from leetha.analysis.attack_surface import analyze_attack_surface
        data_dir = getattr(app_instance.config, "data_dir", None)
        interface = getattr(app_instance.config, "interface", None)
        try:
            _attack_surface_cache = await analyze_attack_surface(app_instance.db, data_dir, interface=interface)
        except Exception:
            _attack_surface_cache = {"chains": [], "services": [], "summary": {}}
        _attack_surface_cache_ts = now
    return _attack_surface_cache


@fastapi_app.get("/api/attack-surface")
async def api_attack_surface():
    """Run full attack surface analysis and return all findings + chains."""
    return await _get_cached_attack_surface()


@fastapi_app.get("/api/attack-surface/summary")
async def api_attack_surface_summary():
    """Lightweight summary stats (finding/chain counts by severity)."""
    report = await _get_cached_attack_surface()
    return report["summary"]


@fastapi_app.get("/api/attack-surface/chains")
async def api_attack_surface_chains():
    """Return attack chains only."""
    report = await _get_cached_attack_surface()
    return {"chains": report["chains"]}


@fastapi_app.get("/api/attack-surface/exclusions")
async def api_attack_surface_exclusions():
    """List current attack surface exclusions."""
    import json as _json
    data_dir = getattr(app_instance.config, "data_dir", None)
    if not data_dir:
        return {"exclusions": []}
    exc_file = data_dir / "attack_surface_exclusions.json"
    if not exc_file.exists():
        return {"exclusions": []}
    try:
        return _json.loads(exc_file.read_text())
    except (_json.JSONDecodeError, OSError):
        return {"exclusions": []}


@fastapi_app.post("/api/attack-surface/exclude")
async def api_attack_surface_exclude(request: Request):
    """Add an exclusion (type: ip|mac|rule, value: string)."""
    import json as _json
    from datetime import datetime
    body = await request.json()
    exc_type = body.get("type")
    exc_value = body.get("value")
    if exc_type not in ("ip", "mac", "rule") or not exc_value:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            content={"error": "type must be ip|mac|rule and value is required"},
            status_code=400,
        )
    data_dir = getattr(app_instance.config, "data_dir", None)
    if not data_dir:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            content={"error": "data_dir not configured"},
            status_code=500,
        )
    exc_file = data_dir / "attack_surface_exclusions.json"
    data = {"exclusions": []}
    if exc_file.exists():
        try:
            data = _json.loads(exc_file.read_text())
        except (_json.JSONDecodeError, OSError):
            pass
    # Avoid duplicates
    for e in data["exclusions"]:
        if e["type"] == exc_type and e["value"] == exc_value:
            return {"status": "already_excluded"}
    data["exclusions"].append({
        "type": exc_type, "value": exc_value,
        "added": datetime.now().isoformat(),
    })
    exc_file.write_text(_json.dumps(data, indent=2))
    return {"status": "excluded"}


@fastapi_app.delete("/api/attack-surface/exclude/{exc_type}/{exc_value:path}")
async def api_attack_surface_unexclude(exc_type: str, exc_value: str):
    """Remove an exclusion."""
    import json as _json
    data_dir = getattr(app_instance.config, "data_dir", None)
    if not data_dir:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            content={"error": "data_dir not configured"},
            status_code=500,
        )
    exc_file = data_dir / "attack_surface_exclusions.json"
    if not exc_file.exists():
        return {"status": "not_found"}
    try:
        data = _json.loads(exc_file.read_text())
    except (_json.JSONDecodeError, OSError):
        return {"status": "not_found"}
    original = len(data.get("exclusions", []))
    data["exclusions"] = [
        e for e in data.get("exclusions", [])
        if not (e["type"] == exc_type and e["value"] == exc_value)
    ]
    if len(data["exclusions"]) == original:
        return {"status": "not_found"}
    exc_file.write_text(_json.dumps(data, indent=2))
    return {"status": "removed"}


@fastapi_app.get("/api/interfaces")
async def api_interfaces():
    """Return detected system interfaces and currently active capture interfaces."""
    from leetha.capture.interfaces import (
        detect_interfaces, get_routes, enrich_interfaces, load_interface_config,
        sort_interfaces,
    )
    detected = sort_interfaces(detect_interfaces(include_down=True))
    routes = get_routes()
    enrich_interfaces(detected, routes)
    saved = load_interface_config(app_instance.config.data_dir)
    saved_names = {s.name for s in saved}
    observed = await app_instance.db.list_observed_interfaces()
    return {
        "detected": [
            {
                "name": d.name, "mac": d.mac, "state": d.state,
                "type": d.type, "mtu": d.mtu,
                "bindings": [b.to_dict() for b in d.bindings],
                "routes": [{"dst": r.destination, "gw": r.gateway, "src": r.source}
                           for r in d.routes],
                "selected": d.name in saved_names,
                "capturing": d.name in app_instance.capture_engine.interfaces,
            }
            for d in detected
        ],
        "active": [
            {"name": c.name, "type": c.type, "label": c.label,
             "probe_mode": getattr(c, "probe_mode", "passive")}
            for c in (app_instance.config.interfaces or [])
        ],
        "observed": observed,
    }


@fastapi_app.post("/api/interfaces/{name}/enable")
async def enable_interface(name: str):
    """Start capture on an interface."""
    from leetha.capture.interfaces import (
        detect_interfaces, InterfaceConfig, save_interface_config,
    )

    # Already capturing?
    if name in app_instance.capture_engine.interfaces:
        return {"status": "already_active"}

    # Find the interface in system interfaces
    detected = detect_interfaces(include_down=True)
    match = next((d for d in detected if d.name == name), None)
    if not match:
        return JSONResponse(status_code=404, content={"error": f"Interface '{name}' not found"})

    if match.state != "up":
        return JSONResponse(status_code=400, content={"error": f"Interface '{name}' is down"})

    config = InterfaceConfig(
        name=name,
        type=match.type,
        bindings=list(match.bindings),
    )

    # Hot-add to capture engine
    app_instance.capture_engine.add_interface(config)

    # Persist to saved config
    current = app_instance.config.interfaces or []
    if not any(c.name == name for c in current):
        current.append(config)
        app_instance.config.interfaces = current
    save_interface_config(app_instance.config.data_dir, current)

    return {"status": "ok", "interface": name}


@fastapi_app.post("/api/interfaces/{name}/disable")
async def disable_interface(name: str):
    """Stop capture on an interface."""
    from leetha.capture.interfaces import save_interface_config

    if name not in app_instance.capture_engine.interfaces:
        return {"status": "not_active"}

    # Hot-remove from capture engine
    app_instance.capture_engine.remove_interface(name)

    # Remove from config and persist
    current = app_instance.config.interfaces or []
    current = [c for c in current if c.name != name]
    app_instance.config.interfaces = current
    save_interface_config(app_instance.config.data_dir, current)

    return {"status": "ok", "interface": name}


@fastapi_app.put("/api/interfaces/{name}/probe-mode")
async def set_probe_mode(name: str, request: Request):
    """Toggle probe mode for an interface."""
    body = await request.json()
    mode = body.get("mode", "passive")
    if mode not in ("passive", "probe-enabled"):
        return JSONResponse({"error": "Invalid mode"}, status_code=400)

    config = app_instance.capture_engine.interfaces.get(name)
    if not config:
        return JSONResponse({"error": f"Interface {name} not found"}, status_code=404)

    config.probe_mode = mode
    return {"interface": name, "probe_mode": mode}


@fastapi_app.post("/api/interfaces/{name}/probe")
async def run_probes(name: str, request: Request):
    """Run probes on an interface."""
    from leetha.capture.probes import ProbeDispatcher

    body = await request.json()
    probe_names = body.get("probes", [])

    config = app_instance.capture_engine.interfaces.get(name)
    if not config:
        return JSONResponse({"error": f"Interface {name} not found"}, status_code=404)

    if getattr(config, "probe_mode", "passive") != "probe-enabled":
        return JSONResponse(
            {"error": f"Probing not enabled on {name}. Enable first."},
            status_code=400,
        )

    dispatcher = ProbeDispatcher()

    if "all" in probe_names:
        results = await dispatcher.run_all(config)
    else:
        results = []
        for pname in probe_names:
            try:
                result = await dispatcher.run_probe(pname, config)
                results.append({"probe": pname, "status": "sent", **result})
            except ValueError as e:
                results.append({"probe": pname, "status": "error", "error": str(e)})

    return {"interface": name, "results": results}


@fastapi_app.get("/api/interfaces/{name}/probe-status")
async def get_probe_status(name: str):
    """Get probe status for an interface."""
    from leetha.capture.probes import get_available_probes
    from leetha.capture.interfaces import classify_capture_mode

    config = app_instance.capture_engine.interfaces.get(name)
    if not config:
        return JSONResponse({"error": f"Interface {name} not found"}, status_code=404)

    capture_mode = classify_capture_mode(name)
    available = get_available_probes(capture_mode)

    return {
        "interface": name,
        "probe_mode": getattr(config, "probe_mode", "passive"),
        "capture_mode": capture_mode,
        "available_probes": [
            {"name": k, "description": v.description, "requires_l2": v.requires_l2}
            for k, v in available.items()
        ],
    }


@fastapi_app.get("/api/alerts")
async def api_alerts():
    findings = await app_instance.store.findings.list_active(limit=100)
    return [_finding_to_alert_dict(f) for f in findings]


@fastapi_app.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int):
    await app_instance.store.findings.resolve(alert_id)
    return {"status": "ok"}


@fastapi_app.delete("/api/alerts/resolved")
async def api_delete_resolved_alerts():
    # Findings use soft-delete (resolved flag); purge resolved rows
    try:
        cursor = await app_instance.store.connection.execute(
            "DELETE FROM findings WHERE resolved = 1"
        )
        await app_instance.store.connection.commit()
        return {"deleted": cursor.rowcount}
    except Exception:
        return {"deleted": 0}


@fastapi_app.delete("/api/alerts/all")
async def api_delete_all_alerts(confirm: bool = False):
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


@fastapi_app.get("/api/incidents")
async def api_incidents():
    """Group alerts into incidents by (device_mac, subtype) within time windows."""
    import re
    from collections import defaultdict

    findings = await app_instance.store.findings.list_active(limit=10000)
    alerts = [_finding_to_alert_dict(f) for f in findings]
    # Attach the original Finding objects for access to .rule etc.
    for ad, f in zip(alerts, findings):
        ad["_finding"] = f

    # Extract subtype from finding rule + message
    def extract_subtype(rule: str, msg: str) -> str:
        # Map new FindingRule values to subtypes the frontend expects
        rule_map = {
            "new_host": "new_device",
            "platform_drift": "fingerprint_drift",
            "addr_conflict": "ip_conflict",
            "low_certainty": "unclassified",
            "stale_source": "source_stale",
            "randomized_addr": "mac_randomized",
            "dhcp_anomaly": "dhcp_anomaly",
            "identity_shift": "mac_spoofing",
            "behavioral_drift": "fingerprint_drift",
        }
        mapped = rule_map.get(rule, rule)
        # For spoofing-related rules, try to parse more specific subtypes from message
        if mapped in ("spoofing", "other"):
            msg_l = msg.lower()
            if "gateway" in msg_l or "trusted binding" in msg_l:
                return "gateway_impersonation"
            if "ip conflict" in msg_l or "conflict" in msg_l:
                return "ip_conflict"
            if "flip" in msg_l and "flop" in msg_l:
                return "flip_flop"
            if "gratuitous" in msg_l and "flood" in msg_l:
                return "grat_flood"
        return mapped or "other"

    # Group ALL alerts by (device_mac, subtype)
    groups = defaultdict(list)
    for a in alerts:
        rule = a.get("_finding").rule.value if a.get("_finding") else a.get("alert_type", "")
        sub = extract_subtype(rule, a.get("message") or "")
        groups[(a["device_mac"], sub)].append(a)

    # Check MAC randomization status
    mac_cache = {}
    async def is_mac_randomized(mac: str) -> tuple[bool, str | None]:
        if mac in mac_cache:
            return mac_cache[mac]
        host = await app_instance.store.hosts.find_by_addr(mac)
        if host:
            result = (host.mac_randomized, host.real_hw_addr)
        else:
            # Check locally-administered bit
            try:
                first_octet = int(mac.split(":")[0], 16)
                result = (bool(first_octet & 0x02), None)
            except Exception:
                result = (False, None)
        mac_cache[mac] = result
        return result

    # Classify severity
    THREAT_SUBTYPES = {"gateway_impersonation", "flip_flop", "mac_spoofing", "infra_offline"}
    INFO_SUBTYPES = {"new_device", "mac_randomized", "source_stale"}
    INFO_SUBTYPES_IF_RANDOMIZED = {"fingerprint_drift", "oui_mismatch"}

    incidents = []
    threat_count = 0
    suspicious_count = 0
    info_count = 0

    for (mac, subtype), alert_list in groups.items():
        alert_list.sort(key=lambda a: a.get("timestamp") or "")
        randomized, correlated = await is_mac_randomized(mac)

        # Determine severity
        if subtype in THREAT_SUBTYPES:
            severity = "threat"
            threat_count += 1
        elif subtype in INFO_SUBTYPES:
            severity = "informational"
            info_count += 1
        elif randomized and subtype in INFO_SUBTYPES_IF_RANDOMIZED:
            severity = "informational"
            info_count += 1
        else:
            severity = "suspicious"
            suspicious_count += 1

        # Build summary from first alert message
        first_msg = alert_list[0].get("message") or ""
        summary = first_msg
        if len(summary) > 120:
            summary = summary[:117] + "..."

        # Get device info for context
        verdict = await app_instance.store.verdicts.find_by_addr(mac)
        host = await app_instance.store.hosts.find_by_addr(mac)
        ip = host.ip_addr if host else None
        manufacturer = verdict.vendor if verdict else None

        first_ts = alert_list[0].get("timestamp")
        last_ts = alert_list[-1].get("timestamp")

        incidents.append({
            "id": f"{subtype}_{mac.replace(':', '')}",
            "subtype": subtype,
            "severity": severity,
            "device_mac": mac,
            "device_ip": ip,
            "manufacturer": manufacturer,
            "alert_count": len(alert_list),
            "first_seen": first_ts,
            "last_seen": last_ts,
            "summary": summary,
            "is_randomized_mac": randomized,
            "correlated_mac": correlated,
            "alert_ids": [a.get("id") for a in alert_list],
        })

    # Sort: threats first, then suspicious, then info. Within same severity, most alerts first.
    sev_order = {"threat": 0, "suspicious": 1, "informational": 2}
    incidents.sort(key=lambda i: (sev_order.get(i["severity"], 9), -i["alert_count"]))

    return {
        "incidents": incidents,
        "counts": {
            "threat": threat_count,
            "suspicious": suspicious_count,
            "informational": info_count,
            "total": len(incidents),
        },
    }


@fastapi_app.get("/api/incidents/{incident_id}/detail")
async def api_incident_detail(incident_id: str):
    """Full evidence context for an incident."""
    # Parse: everything after the last _ is the MAC hex (12 chars)
    last_underscore = incident_id.rfind("_")
    if last_underscore == -1:
        return JSONResponse(status_code=400, content={"error": "Invalid incident ID"})

    subtype = incident_id[:last_underscore]
    mac_hex = incident_id[last_underscore + 1:]

    # Reconstruct MAC with colons
    if len(mac_hex) == 12:
        mac = ":".join(mac_hex[i:i+2] for i in range(0, 12, 2))
    else:
        mac = mac_hex

    # Fetch all context from new store
    verdict = await app_instance.store.verdicts.find_by_addr(mac)
    host = await app_instance.store.hosts.find_by_addr(mac)
    if not verdict and not host:
        return JSONResponse(status_code=404, content={"error": "Device not found"})

    device_dict = _build_device_dict(verdict, host)

    # Evidence from verdict
    evidence = device_dict.get("raw_evidence", {})

    # ARP history
    arp_history = await app_instance.db.get_arp_history_for_mac(mac)

    # Fingerprint history
    try:
        fp_history = await app_instance.db.get_fingerprint_history(mac, limit=20)
    except Exception:
        fp_history = []

    # Recent sightings as observations
    try:
        sightings = await app_instance.store.sightings.for_host(mac, limit=15)
    except Exception:
        sightings = []
    obs_list = [
        {
            "id": None,
            "timestamp": s.timestamp.isoformat() if s.timestamp else None,
            "source_type": s.source,
            "raw_data": json.dumps(s.payload) if isinstance(s.payload, dict) else str(s.payload),
            "match_result": json.dumps(s.analysis) if isinstance(s.analysis, dict) else str(s.analysis),
            "confidence": int(s.certainty * 100) if s.certainty <= 1 else int(s.certainty),
        }
        for s in sightings
    ]

    ip_addr = host.ip_addr if host else None
    # Trusted bindings for this device
    bindings = await app_instance.db.list_trusted_bindings()
    device_bindings = [b for b in bindings if b.get("mac") == mac or b.get("ip") == ip_addr]

    # Suppression rules for this device
    rules = await app_instance.db.list_suppression_rules()
    device_rules = [r for r in rules if (r.get("mac") and r.get("mac") == mac) or (r.get("ip") and r.get("ip") == ip_addr) or (r.get("subtype") and r.get("subtype") == subtype)]

    # Detection context
    DETECTION_METHODS = {
        "new_device": {
            "rule": "new_device",
            "trigger": "Previously unseen MAC address appeared on the network",
            "method": "Fires when a MAC address is observed for the first time and has no entry in the devices table.",
            "cooldown_seconds": 0,
        },
        "os_change": {
            "rule": "os_change",
            "trigger": "Known device's OS fingerprint changed from previously stored value",
            "method": "Compares the newly identified OS family against the stored value in the devices table. Fires when they differ.",
            "cooldown_seconds": 300,
        },
        "mac_randomized": {
            "rule": "mac_randomized",
            "trigger": "MAC address randomization detected on first sighting",
            "method": "Checks the locally-administered bit (bit 1 of first octet) and applies correlation heuristics to group randomized MACs to a persistent identity.",
            "cooldown_seconds": 0,
        },
        "unclassified": {
            "rule": "unclassified",
            "trigger": "Device fingerprint confidence is below 50%",
            "method": "After fingerprint analysis, if the highest confidence score across all sources is below 50%, the device is flagged for manual review.",
            "cooldown_seconds": 300,
        },
        "source_stale": {
            "rule": "source_stale",
            "trigger": "Fingerprint database file is older than the configured threshold",
            "method": "Checks modification timestamps of fingerprint source files against a 30-day threshold. Run 'leetha sync' to update.",
            "cooldown_seconds": 0,
        },
        "dhcp_anomaly": {
            "rule": "dhcp_anomaly",
            "trigger": "DHCP option field failed RFC 2132 validation",
            "method": "Validates DHCP option fields against expected types (IPv4 addresses, printable text, numeric values). Detects malformed or suspicious DHCP traffic.",
            "cooldown_seconds": 300,
        },
        "fingerprint_drift": {
            "rule": "fingerprint_drift",
            "trigger": "OS or manufacturer changed from stored fingerprint snapshot",
            "method": "Compares current device fingerprint against fingerprint_history table. Fires when os_family or manufacturer differs from the most recent snapshot.",
            "cooldown_seconds": 300,
        },
        "oui_mismatch": {
            "rule": "oui_mismatch",
            "trigger": "OUI vendor name differs from fingerprint-identified manufacturer",
            "method": "Compares the IEEE OUI lookup for the MAC prefix against the manufacturer identified by DHCP/DNS/mDNS fingerprinting. Requires confidence >= 60% and non-randomized MAC.",
            "cooldown_seconds": 300,
        },
        "gateway_impersonation": {
            "rule": "gateway_impersonation",
            "trigger": "ARP reply for trusted gateway IP from untrusted MAC",
            "method": "Checks ARP source MAC against trusted_bindings table for the claimed IP. Fires when an unknown MAC sends ARP replies for a trusted gateway IP.",
            "cooldown_seconds": 300,
        },
        "ip_conflict": {
            "rule": "ip_conflict",
            "trigger": "Two different MACs claiming the same IP via ARP",
            "method": "Maintains ARP cache mapping IPs to MACs. Fires when a new MAC claims an IP already assigned to a different MAC.",
            "cooldown_seconds": 300,
        },
        "grat_flood": {
            "rule": "grat_flood",
            "trigger": "More than 10 gratuitous ARPs in 60 seconds from same MAC",
            "method": "Tracks gratuitous ARP timestamps per source MAC in a sliding 60-second window. Gratuitous ARPs are ARP replies where sender IP equals target IP.",
            "cooldown_seconds": 300,
        },
        "flip_flop": {
            "rule": "flip_flop",
            "trigger": "IP address bouncing between 3+ MACs within 5 minutes",
            "method": "Maintains history of (MAC, timestamp) pairs per IP over a 300-second sliding window. Fires when 3+ distinct MAC transitions occur.",
            "cooldown_seconds": 300,
        },
        "mac_spoofing": {
            "rule": "mac_spoofing",
            "trigger": "Device identity behind a fixed MAC changed significantly — OUI vendor shift or combined OS + manufacturer change",
            "method": "Compares current OUI vendor and fingerprint identity against the most recent fingerprint snapshot. Fires when the OUI vendor changes (hardware swap) or both OS and manufacturer change simultaneously on a non-randomized MAC.",
            "cooldown_seconds": 300,
        },
        "infra_offline": {
            "rule": "infra_offline",
            "trigger": "Infrastructure device (router, switch, or access point) has not been seen for 5+ minutes",
            "method": "Periodic check (every 30 seconds) compares each infrastructure device's last_seen timestamp against a 5-minute threshold. Only fires for routers, switches, APs, firewalls, and gateways — not client devices.",
            "cooldown_seconds": 0,
        },
    }
    detection = DETECTION_METHODS.get(subtype, {
        "rule": subtype,
        "trigger": "Unknown trigger",
        "method": "Detection method not documented",
        "cooldown_seconds": 300,
    })

    # Generate recommendation
    randomized = host.mac_randomized if host else False
    recommendations = {
        # Non-spoofing subtypes (randomized status irrelevant for most)
        ("new_device", True): "New device with a randomized MAC. This is normal for modern phones, laptops, and IoT devices. Acknowledge once reviewed.",
        ("new_device", False): "New device discovered on the network. Review the fingerprint evidence to confirm it belongs here.",
        ("os_change", True): "OS fingerprint changed on a randomized MAC. Could be a different device reusing the address, or an OS update.",
        ("os_change", False): "OS fingerprint changed on a fixed MAC. Could indicate a firmware update, device replacement, or dual-boot system. Verify if expected.",
        ("mac_randomized", True): "MAC randomization detected. This is standard behavior for modern operating systems. The device has been correlated to a persistent identity where possible.",
        ("mac_randomized", False): "MAC randomization flag raised but MAC appears to be fixed. Unusual — review the device.",
        ("unclassified", True): "Low confidence identification on a randomized MAC. Limited fingerprint data available. More observations may improve confidence over time.",
        ("unclassified", False): "Low confidence identification. The device has not produced enough protocol fingerprints to classify reliably. Active probing may help.",
        ("source_stale", True): "Fingerprint database is outdated. Run 'leetha sync' to update fingerprint sources for improved identification accuracy.",
        ("source_stale", False): "Fingerprint database is outdated. Run 'leetha sync' to update fingerprint sources for improved identification accuracy.",
        ("dhcp_anomaly", True): "DHCP option anomaly from a randomized MAC. Could indicate a misconfigured or malicious DHCP client. Review the option details.",
        ("dhcp_anomaly", False): "DHCP option anomaly detected. The device sent DHCP options that violate RFC 2132 formatting. Could indicate misconfiguration or a crafted packet.",
        # MAC spoofing
        ("mac_spoofing", True): "MAC spoofing detected on a randomized MAC. This is unusual — randomized MACs change by design, but the underlying identity shift is suspicious. Investigate the device.",
        ("mac_spoofing", False): "HIGH: Possible MAC spoofing detected. A different physical device appears to be using this MAC address. The OUI vendor or device identity changed significantly. Physically verify the device and check for unauthorized hardware on the network.",
        # Infrastructure offline
        ("infra_offline", True): "Infrastructure device with randomized MAC went offline. This is unusual for network equipment. Verify the device is still operational.",
        ("infra_offline", False): "CRITICAL: Infrastructure device is no longer responding. Check physical connectivity, power status, and device health. If this is a gateway, the network segment behind it may be unreachable.",
        # Spoofing subtypes
        ("fingerprint_drift", True): "Randomized MAC — identity changes are expected behavior. Safe to suppress fingerprint_drift for this MAC.",
        ("fingerprint_drift", False): "Fixed MAC with OS/manufacturer changes. Investigate — could indicate firmware updates, device replacement, or spoofing.",
        ("oui_mismatch", True): "Randomized MAC has no real OUI. This is expected behavior. Safe to suppress.",
        ("oui_mismatch", False): "Hardware MAC vendor doesn't match fingerprint identification. Could indicate MAC address spoofing. Verify the device physically.",
        ("gateway_impersonation", True): "CRITICAL: Device claiming gateway IP. Even with randomized MAC, this is suspicious. Investigate immediately.",
        ("gateway_impersonation", False): "CRITICAL: Untrusted device claiming gateway IP with a real hardware MAC. Likely ARP poisoning. Investigate immediately.",
        ("ip_conflict", True): "IP conflict from randomized MAC. Could be a device that reconnected with a new MAC. Monitor for persistence.",
        ("ip_conflict", False): "Two physical devices sharing an IP. Check for DHCP misconfiguration, rogue device, or MITM.",
        ("grat_flood", True): "Excessive gratuitous ARPs from randomized MAC. Unusual — may indicate ARP cache poisoning attempt.",
        ("grat_flood", False): "Excessive gratuitous ARPs from fixed MAC. May indicate ARP cache poisoning or a misconfigured device.",
        ("flip_flop", True): "IP bouncing between MACs including randomized ones. Likely device reconnections with new MACs.",
        ("flip_flop", False): "IP bouncing between fixed MACs. Could indicate active MITM, HSRP/VRRP failover, or DHCP race condition.",
    }
    recommendation = recommendations.get((subtype, randomized), "Review the evidence below and determine if this activity is expected for this device and network.")

    return {
        "incident_id": incident_id,
        "subtype": subtype,
        "device": device_dict,
        "evidence": evidence,
        "arp_history": arp_history,
        "fingerprint_history": fp_history,
        "recent_observations": obs_list,
        "trusted_bindings": device_bindings,
        "suppression_rules": device_rules,
        "detection_context": {
            **detection,
            "mac_randomized": randomized,
            "correlated_mac": host.real_hw_addr if host else None,
            "recommendation": recommendation,
        },
    }


@fastapi_app.get("/api/stats")
async def api_stats():
    try:
        device_count = await app_instance.store.hosts.count()
        alert_count = await app_instance.store.findings.count_active()
    except Exception:
        # Fallback to old tables during transition
        device_count = await app_instance.db.get_identity_count()
        alerts = await app_instance.db.list_alerts(acknowledged=False)
        alert_count = len(alerts)
    capturing_count = len(app_instance.capture_engine.interfaces) if app_instance else 0
    return {
        "device_count": device_count,
        "alert_count": alert_count,
        "capturing_count": capturing_count,
    }


@fastapi_app.get("/api/stats/device-types")
async def api_device_type_stats():
    """Device count by type for dashboard breakdown."""
    try:
        # Use new verdicts table
        cursor = await app_instance.store.connection.execute(
            "SELECT COALESCE(category, 'unknown') as dtype, COUNT(*) as cnt "
            "FROM verdicts GROUP BY dtype ORDER BY cnt DESC"
        )
        rows = await cursor.fetchall()
        return {"types": [{"type": r[0], "count": r[1]} for r in rows]}
    except Exception:
        try:
            # Fallback to old devices table
            rows = await app_instance.db.execute_readonly_query(
                "SELECT COALESCE(device_type, 'unknown') as dtype, COUNT(*) as cnt FROM devices GROUP BY dtype ORDER BY cnt DESC"
            )
            return {"types": [{"type": r[0], "count": r[1]} for r in rows.get("rows", [])]}
        except Exception:
            return {"types": []}


@fastapi_app.get("/api/stats/activity")
async def api_activity_stats():
    """24-hour packet activity for dashboard timeline."""
    try:
        conn = app_instance.store.connection
        cursor = await conn.execute(
            "SELECT strftime('%H', timestamp) as hour, COUNT(*) as cnt "
            "FROM sightings WHERE timestamp > datetime('now', '-24 hours') "
            "GROUP BY hour ORDER BY hour"
        )
        rows = await cursor.fetchall()
        # Build 24-element array
        counts = [0] * 24
        for r in rows:
            try:
                h = int(r[0])
                counts[h] = r[1]
            except (ValueError, IndexError):
                pass
        return {"hourly_counts": counts}
    except Exception:
        return {"hourly_counts": [0] * 24}


@fastapi_app.get("/api/stats/filters")
async def api_filter_options():
    """Available filter values for device dropdowns (cached 30s)."""
    try:
        dt_cursor = await app_instance.store.connection.execute(
            "SELECT DISTINCT category FROM verdicts WHERE category IS NOT NULL ORDER BY category"
        )
        os_cursor = await app_instance.store.connection.execute(
            "SELECT DISTINCT platform FROM verdicts WHERE platform IS NOT NULL ORDER BY platform"
        )
        mfr_cursor = await app_instance.store.connection.execute(
            "SELECT DISTINCT vendor FROM verdicts WHERE vendor IS NOT NULL ORDER BY vendor"
        )
        return {
            "device_types": [r[0] for r in await dt_cursor.fetchall()],
            "os_families": [r[0] for r in await os_cursor.fetchall()],
            "manufacturers": [r[0] for r in await mfr_cursor.fetchall()],
        }
    except Exception:
        return {"device_types": [], "os_families": [], "manufacturers": []}


@fastapi_app.get("/api/stats/protocols")
async def api_protocol_stats():
    """Protocol distribution for dashboard pie chart."""
    try:
        conn = app_instance.store.connection
        cursor = await conn.execute(
            "SELECT COALESCE(source, 'unknown') as proto, COUNT(*) as cnt "
            "FROM sightings WHERE timestamp > datetime('now', '-24 hours') "
            "GROUP BY proto ORDER BY cnt DESC LIMIT 15"
        )
        rows = await cursor.fetchall()
        return {"protocols": [{"protocol": r[0], "count": r[1]} for r in rows]}
    except Exception:
        return {"protocols": []}


@fastapi_app.get("/api/stats/alert-types")
async def api_alert_type_stats():
    """Alert count by type for dashboard breakdown."""
    try:
        cursor = await app_instance.store.connection.execute(
            "SELECT COALESCE(rule, 'unknown') as atype, severity, COUNT(*) as cnt "
            "FROM findings WHERE resolved = 0 "
            "GROUP BY atype, severity ORDER BY cnt DESC"
        )
        rows = await cursor.fetchall()
        return {"types": [{"type": r[0], "severity": r[1], "count": r[2]} for r in rows]}
    except Exception:
        return {"types": []}


@fastapi_app.get("/api/stats/targeted-devices")
async def api_targeted_devices():
    """Most alerted devices for dashboard."""
    try:
        cursor = await app_instance.store.connection.execute(
            "SELECT f.hw_addr, COUNT(*) as cnt "
            "FROM findings f WHERE f.resolved = 0 "
            "GROUP BY f.hw_addr ORDER BY cnt DESC LIMIT 10"
        )
        rows = await cursor.fetchall()
        result = []
        for r in rows:
            hw_addr, cnt = r[0], r[1]
            verdict = await app_instance.store.verdicts.find_by_addr(hw_addr)
            host = await app_instance.store.hosts.find_by_addr(hw_addr)
            result.append({
                "mac": hw_addr,
                "count": cnt,
                "ip": host.ip_addr if host else None,
                "manufacturer": verdict.vendor if verdict else None,
                "device_type": verdict.category if verdict else None,
            })
        return {"devices": result}
    except Exception:
        return {"devices": []}


@fastapi_app.get("/api/stats/alert-trend")
async def api_alert_trend():
    """Hourly alert counts over last 24 hours for trend line chart."""
    try:
        cursor = await app_instance.store.connection.execute(
            "SELECT strftime('%H', timestamp) as hour, COUNT(*) as cnt "
            "FROM findings WHERE timestamp > datetime('now', '-24 hours') "
            "GROUP BY hour ORDER BY hour"
        )
        rows = await cursor.fetchall()
        counts = [0] * 24
        for r in rows:
            try:
                counts[int(r[0])] = r[1]
            except (ValueError, IndexError):
                pass
        return {"hourly_counts": counts}
    except Exception:
        return {"hourly_counts": [0] * 24}


@fastapi_app.get("/api/stats/new-devices")
async def api_new_devices_timeline():
    """New devices discovered per hour over last 24h."""
    try:
        cursor = await app_instance.store.connection.execute(
            "SELECT strftime('%H', discovered_at) as hour, COUNT(*) as cnt "
            "FROM hosts WHERE discovered_at > datetime('now', '-24 hours') "
            "GROUP BY hour ORDER BY hour"
        )
        rows = await cursor.fetchall()
        counts = [0] * 24
        for r in rows:
            try:
                counts[int(r[0])] = r[1]
            except (ValueError, IndexError):
                pass
        return {"hourly_counts": counts}
    except Exception:
        return {"hourly_counts": [0] * 24}


@fastapi_app.get("/api/stats/top-connections")
async def api_top_connections():
    """Top source→destination IP pairs by observation count."""
    try:
        conn = app_instance.store.connection
        cursor = await conn.execute(
            "SELECT "
            "  COALESCE(json_extract(payload, '$.src_ip'), 'unknown') as src, "
            "  COALESCE(json_extract(payload, '$.dst_ip'), json_extract(payload, '$.target_ip'), 'unknown') as dst, "
            "  COUNT(*) as cnt "
            "FROM sightings "
            "WHERE timestamp > datetime('now', '-24 hours') "
            "  AND json_extract(payload, '$.src_ip') IS NOT NULL "
            "  AND (json_extract(payload, '$.dst_ip') IS NOT NULL OR json_extract(payload, '$.target_ip') IS NOT NULL) "
            "GROUP BY src, dst "
            "ORDER BY cnt DESC LIMIT 20"
        )
        rows = await cursor.fetchall()
        return {"connections": [{"src": r[0], "dst": r[1], "count": r[2]} for r in rows]}
    except Exception:
        return {"connections": []}


_topology_cache: dict = {"data": None, "ts": 0}


@fastapi_app.get("/api/topology")
async def api_topology():
    """Build and return the network topology graph."""
    import time as _time
    import json as _json
    from leetha.topology import build_topology_graph

    now = _time.time()
    if _topology_cache["data"] is not None and (now - _topology_cache["ts"]) < 30:
        return _topology_cache["data"]

    try:
        # 1. Devices — from verdicts + hosts
        verdicts = await app_instance.store.verdicts.find_all(limit=1000)
        devices = []
        for v in verdicts:
            h = await app_instance.store.hosts.find_by_addr(v.hw_addr)
            d = _build_device_dict(v, h)
            devices.append(d)

        # 1b. Gather mDNS services and LLDP/CDP presence per device for connection type
        device_mdns_services: dict[str, list[str]] = {}
        device_has_lldp: set[str] = set()
        device_has_cdp: set[str] = set()
        try:
            svc_cursor = await app_instance.store.connection.execute(
                "SELECT hw_addr, source, payload FROM sightings "
                "WHERE source IN ('mdns', 'lldp', 'cdp') "
                "ORDER BY timestamp DESC LIMIT 5000"
            )
            svc_rows = await svc_cursor.fetchall()
            for r in svc_rows:
                dev_mac, src_type, raw = r[0], r[1], r[2]
                if src_type == "lldp":
                    device_has_lldp.add(dev_mac)
                elif src_type == "cdp":
                    device_has_cdp.add(dev_mac)
                elif src_type == "mdns" and raw:
                    try:
                        svc_data = _json.loads(raw) if isinstance(raw, str) else raw
                        svc_name = svc_data.get("service") or svc_data.get("name") or svc_data.get("service_type")
                        if svc_name:
                            device_mdns_services.setdefault(dev_mac, []).append(svc_name)
                    except Exception:
                        pass
        except Exception:
            pass

        # 1c. Infer connection type for each device
        from leetha.connection_type import infer_connection_type
        for d in devices:
            d["connection_type"] = infer_connection_type(
                mac=d["mac"],
                device_type=d.get("device_type"),
                is_randomized_mac=d.get("is_randomized_mac", False),
                manufacturer=d.get("manufacturer"),
                observed_services=device_mdns_services.get(d["mac"]),
                has_lldp=d["mac"] in device_has_lldp,
                has_cdp=d["mac"] in device_has_cdp,
            )

        # 2. Gateways — from trusted bindings with gateway source,
        #    or inferred from device_type=router if no explicit gateways found
        gateways = []
        try:
            bindings = await app_instance.db.list_trusted_bindings()
            for b in bindings:
                src = b.get("source", "")
                # Only treat DHCP servers and auto-detected gateways as actual gateways
                if src in ("dhcp_server", "auto_gateway") and b.get("mac") and b.get("ip"):
                    gateways.append({"mac": b["mac"], "ip": b["ip"], "source": src})
        except Exception:
            pass

        # Fallback: if no gateways from trusted_bindings, find router-type devices.
        # Normalize device_type first since the DB may store model names
        # (e.g. "UniFi Dream Machine Pro") instead of generic types.
        if not gateways:
            from leetha.topology import _normalize_device_type
            for d in devices:
                raw_type = d.get("device_type") or ""
                normalized = _normalize_device_type(raw_type)
                if normalized in ("router", "gateway", "firewall") and d.get("ip_v4"):
                    gateways.append({"mac": d["mac"], "ip": d["ip_v4"], "source": "inferred"})

        # Last resort: find gateway-like IPs (.1 or .2) on every subnet
        if not gateways:
            import ipaddress
            seen_subnets: set[str] = set()
            for d in devices:
                ip = d.get("ip_v4")
                if not ip:
                    continue
                try:
                    net = str(ipaddress.ip_network(f"{ip}/24", strict=False))
                    seen_subnets.add(net)
                except Exception:
                    pass

            gateway_macs_found: set[str] = set()
            for subnet in seen_subnets:
                prefix = subnet.replace(".0/24", ".")
                # Look for .1 first, then .2 (common gateway addresses)
                for suffix in ("1", "2"):
                    candidate_ip = prefix + suffix
                    for d in devices:
                        if d.get("ip_v4") == candidate_ip and d["mac"] not in gateway_macs_found:
                            gateways.append({"mac": d["mac"], "ip": candidate_ip, "source": "inferred"})
                            gateway_macs_found.add(d["mac"])
                            break
                    if any(g["ip"].startswith(prefix) for g in gateways):
                        break  # Found a gateway for this subnet

        # 3. ARP entries
        arp_entries = []
        try:
            arp_rows = await app_instance.db.execute_readonly_query(
                "SELECT mac, ip, packet_count FROM arp_history"
            )
            for r in arp_rows.get("rows", []):
                arp_entries.append({"mac": r[0], "ip": r[1], "packet_count": r[2]})
        except Exception:
            pass

        # 4. LLDP/CDP neighbors
        lldp_neighbors = []
        try:
            lldp_cursor = await app_instance.store.connection.execute(
                "SELECT hw_addr, payload FROM sightings WHERE source IN ('lldp', 'cdp')"
            )
            lldp_rows = await lldp_cursor.fetchall()
            for r in lldp_rows:
                device_mac = r[0]
                try:
                    raw = _json.loads(r[1]) if isinstance(r[1], str) else (r[1] or {})
                    neighbor_mac = raw.get("chassis_id") or raw.get("device_id")
                    if neighbor_mac:
                        lldp_neighbors.append({
                            "device_mac": device_mac,
                            "neighbor_mac": neighbor_mac,
                            "port_id": raw.get("port_id"),
                        })
                except Exception:
                    pass
        except Exception:
            pass

        result = build_topology_graph(
            devices=devices,
            gateways=gateways,
            arp_entries=arp_entries,
            lldp_neighbors=lldp_neighbors,
            device_mdns_services=device_mdns_services,
        )
        _topology_cache["data"] = result
        _topology_cache["ts"] = now
        return result
    except Exception as e:
        logger.exception("Topology build failed")
        return {"nodes": [], "edges": [], "subnets": [], "error": str(e)}


@fastapi_app.get("/api/capture/export")
async def export_pcap():
    """Export captured packets as PCAP file."""
    from starlette.responses import Response
    import tempfile
    import os

    if not app_instance or not hasattr(app_instance.capture_engine, '_packet_buffer'):
        return JSONResponse(status_code=404, content={"error": "No packet buffer available"})

    packets = list(app_instance.capture_engine._packet_buffer)
    if not packets:
        return JSONResponse(status_code=404, content={"error": "No packets captured"})

    try:
        from scapy.all import Ether, wrpcap
        pkts = []
        for raw in packets:
            try:
                pkts.append(Ether(raw))
            except Exception:
                pass

        if not pkts:
            return JSONResponse(status_code=404, content={"error": "No valid packets"})

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            wrpcap(f.name, pkts)
            pcap_path = f.name

        pcap_bytes = open(pcap_path, "rb").read()
        os.unlink(pcap_path)

        return Response(
            content=pcap_bytes,
            media_type="application/vnd.tcpdump.pcap",
            headers={"Content-Disposition": "attachment; filename=leetha-capture.pcap"},
        )
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@fastapi_app.post("/api/import")
async def api_import_pcap(file: UploadFile = File(...)):
    """Upload and process a PCAP file through the fingerprinting pipeline."""
    import os
    from leetha.import_pcap import validate_pcap_file, process_pcap, SUPPORTED_EXTENSIONS

    # Validate extension
    filename = file.filename or "upload.pcap"
    ext = os.path.splitext(filename)[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        return JSONResponse(status_code=400, content={
            "error": f"Unsupported format: {ext} (expected {', '.join(SUPPORTED_EXTENSIONS)})"
        })

    # Save to temp directory
    import_dir = Path(app_instance.config.data_dir) / "imports"
    import_dir.mkdir(parents=True, exist_ok=True)
    dest = import_dir / filename

    try:
        contents = await file.read()
        if len(contents) > 500 * 1024 * 1024:
            return JSONResponse(status_code=400, content={"error": "File too large (max 500 MB)"})
        dest.write_bytes(contents)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Upload failed: {e}"})

    # Validate the saved file
    err = validate_pcap_file(dest)
    if err:
        dest.unlink(missing_ok=True)
        return JSONResponse(status_code=400, content={"error": err})

    # Process in background task
    async def _background_import():
        try:
            def on_progress(p):
                for sub in app_instance.event_subscribers:
                    try:
                        sub.put_nowait({
                            "type": "import_progress",
                            "filename": p.filename,
                            "processed": p.processed,
                            "total": p.total_packets,
                            "done": p.done,
                        })
                    except Exception:
                        pass

            result = await process_pcap(
                dest,
                app_instance.packet_queue,
                on_progress=on_progress,
            )

            for sub in app_instance.event_subscribers:
                try:
                    sub.put_nowait({
                        "type": "import_complete",
                        "filename": result.filename,
                        "processed": result.processed,
                        "total": result.total_packets,
                        "errors": result.errors,
                    })
                except Exception:
                    pass
        finally:
            dest.unlink(missing_ok=True)

    asyncio.create_task(_background_import())

    return {"status": "importing", "filename": filename}


@fastapi_app.get("/api/capture/status")
async def api_capture_status():
    """Return detailed capture engine status for the console page."""
    from leetha.capture.interfaces import classify_capture_mode
    engine = app_instance.capture_engine
    ifaces = []
    for name, config in engine.interfaces.items():
        mode = classify_capture_mode(name)
        if config.bpf_filter:
            bpf = config.bpf_filter
        elif engine.bpf_filter:
            bpf = engine.bpf_filter
        else:
            from leetha.capture.engine import _bpf_for_mode
            bpf = _bpf_for_mode(mode)
        ifaces.append({
            "name": name,
            "capture_mode": mode,
            "bpf_filter": bpf,
            "promisc": mode != "tun",
            "probe_mode": getattr(config, "probe_mode", "passive"),
        })
    from leetha.capture.engine import _bpf_for_mode
    default_bpf = _bpf_for_mode("ethernet")
    active_bpf = ifaces[0]["bpf_filter"] if ifaces else default_bpf
    return {
        "running": engine.is_running,
        "interfaces": ifaces,
        "default_bpf": default_bpf,
        "scapy_command": f"sniff(iface=[{', '.join(repr(i['name']) for i in ifaces)}], filter='{active_bpf}', prn=callback, store=0)" if ifaces else None,
    }


@fastapi_app.post("/api/capture/restart")
async def api_capture_restart(bpf_filter: str = ""):
    """Restart capture engine with a new BPF filter. Applies immediately."""
    if app_instance is None:
        return {"error": "Backend not initialized"}
    engine = app_instance.capture_engine
    # Stop current capture
    engine.shutdown()
    # Update BPF filter
    if bpf_filter:
        engine.bpf_filter = bpf_filter
        engine._global_filter = bpf_filter
    # Restart
    import asyncio
    loop = asyncio.get_event_loop()
    engine.activate(app_instance.packet_queue, loop)
    return {"status": "restarted", "bpf_filter": bpf_filter or "(default)"}


@fastapi_app.get("/api/capture/export")
async def export_pcap():
    """Export captured packets as PCAP file."""
    from scapy.utils import wrpcap
    from starlette.responses import Response
    import tempfile
    import os

    packets = list(app_instance.capture_engine._packet_buffer)
    if not packets:
        return JSONResponse(status_code=404, content={"error": "No packets captured"})

    # Write to temp file using scapy
    from scapy.all import Ether
    pkts = []
    for raw in packets:
        try:
            pkts.append(Ether(raw))
        except Exception:
            pass

    if not pkts:
        return JSONResponse(status_code=404, content={"error": "No valid packets"})

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        wrpcap(f.name, pkts)
        pcap_path = f.name

    with open(pcap_path, "rb") as f:
        pcap_bytes = f.read()

    os.unlink(pcap_path)

    return Response(
        content=pcap_bytes,
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": "attachment; filename=leetha-capture.pcap"},
    )


@fastapi_app.get("/api/sync/sources")
async def api_sync_sources():
    """Return the list of available fingerprint data sources."""
    from leetha.sync.registry import SourceRegistry
    registry = SourceRegistry()
    return {
        "sources": [
            {
                "name": s.name,
                "display_name": s.display_name,
                "url": s.url,
                "source_type": s.source_type,
                "description": s.description,
            }
            for s in registry.list_sources()
        ]
    }


@fastapi_app.post("/api/sync/{source_name}")
async def api_sync_source(source_name: str):
    from leetha.sync import run_sync
    try:
        await run_sync(source=source_name)
        return {"status": "ok", "source": source_name}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@fastapi_app.post("/api/sync")
async def api_sync_all():
    from leetha.sync import run_sync
    try:
        await run_sync()
        return {"status": "ok"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@fastapi_app.get("/api/sync/{source_name}/stream")
async def api_sync_source_stream(source_name: str):
    """SSE endpoint for syncing a single source with progress."""
    import json as _json
    from fastapi.responses import StreamingResponse
    from leetha.sync import sync_source_with_progress

    async def event_stream():
        async for event in sync_source_with_progress(source_name):
            yield f"data: {_json.dumps(event)}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@fastapi_app.get("/api/sync/stream")
async def api_sync_all_stream():
    """SSE endpoint for syncing all sources with progress."""
    import json as _json
    from fastapi.responses import StreamingResponse
    from leetha.sync import sync_all_with_progress

    async def event_stream():
        async for event in sync_all_with_progress():
            yield f"data: {_json.dumps(event)}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# --- WebSocket ---

@fastapi_app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    if _auth_enabled:
        token = websocket.query_params.get("token")
        if not token:
            await websocket.close(code=1008, reason="Token required")
            return
        from leetha.auth.tokens import hash_token
        token_info = await app_instance.db.validate_token(hash_token(token))
        if token_info is None:
            await websocket.close(code=1008, reason="Invalid token")
            return
    await websocket.accept()
    events = app_instance.subscribe()
    try:
        while True:
            event = await events.get()
            # Pass through import events directly
            if isinstance(event, dict) and event.get("type") in ("import_progress", "import_complete"):
                await websocket.send_json(event)
                continue

            # New pipeline events have {"type": "device_update", "mac": ..., "verdict": {...}}
            if isinstance(event, dict) and event.get("type") == "device_update" and "verdict" in event:
                verdict_data = event["verdict"]
                # Build device-shaped dict for frontend compatibility
                device_dict = {
                    "mac": event.get("mac", verdict_data.get("hw_addr", "")),
                    "manufacturer": verdict_data.get("vendor"),
                    "device_type": verdict_data.get("category"),
                    "os_family": verdict_data.get("platform"),
                    "os_version": verdict_data.get("platform_version"),
                    "hostname": verdict_data.get("hostname"),
                    "confidence": verdict_data.get("certainty", 0),
                    "model": verdict_data.get("model"),
                }
                await websocket.send_json({
                    "type": "device_update",
                    "device": device_dict,
                    "alerts": [],
                    "packet": None,
                    "matches": [],
                })
                continue

            # Legacy event format: {"device": Device, "alerts": [...], ...}
            device = event.get("device")
            alerts_data = event.get("alerts", [])
            packet = event.get("packet")
            matches = event.get("matches", [])

            # Build packet summary for console
            packet_info = None
            if packet:
                packet_info = {
                    "protocol": packet.protocol,
                    "src_mac": packet.src_mac,
                    "src_ip": packet.src_ip,
                    "dst_ip": getattr(packet, "dst_ip", None),
                    "interface": packet.interface,
                    "network": packet.network,
                    "timestamp": packet.timestamp.isoformat() if packet.timestamp else None,
                    "data": {k: str(v) for k, v in (packet.data or {}).items()},
                }

            await websocket.send_json({
                "type": event.get("type", "device_update"),
                "device": device.to_dict() if hasattr(device, 'to_dict') else device,
                "alerts": [
                    {"type": a.alert_type, "severity": a.severity, "message": a.message}
                    for a in alerts_data
                ] if alerts_data else [],
                "packet": packet_info,
                "matches": [
                    {
                        "source": m.source,
                        "confidence": m.confidence,
                        "manufacturer": m.manufacturer,
                        "os_family": m.os_family,
                        "device_type": m.device_type,
                    }
                    for m in matches
                ] if matches else [],
            })
    except (WebSocketDisconnect, Exception):
        app_instance.unsubscribe(events)


@fastapi_app.websocket("/ws/console")
async def websocket_console(websocket: WebSocket):
    """WebSocket for live packet stream (console page)."""
    if _auth_enabled:
        token = websocket.query_params.get("token")
        if not token:
            await websocket.close(code=1008, reason="Token required")
            return
        from leetha.auth.tokens import hash_token
        token_info = await app_instance.db.validate_token(hash_token(token))
        if token_info is None:
            await websocket.close(code=1008, reason="Invalid token")
            return
    await websocket.accept()
    events = app_instance.subscribe()
    try:
        while True:
            event = await events.get()
            # Pass through import events directly
            if isinstance(event, dict) and event.get("type") in ("import_progress", "import_complete"):
                await websocket.send_json(event)
                continue

            # New pipeline events: {"type": "device_update", "mac": ..., "verdict": {...}}
            # Console WS requires packet data — skip verdict-only events
            if isinstance(event, dict) and event.get("type") == "device_update" and "verdict" in event and "packet" not in event:
                continue

            device = event.get("device")
            packet = event.get("packet")
            matches = event.get("matches", [])
            alerts_list = event.get("alerts", [])

            if not packet:
                continue

            # Build device dict — handle both Device objects and Verdict dicts
            if device and hasattr(device, "manufacturer"):
                device_dict = {
                    "manufacturer": device.manufacturer,
                    "device_type": getattr(device, "device_type", None) or getattr(device, "category", None),
                    "os_family": getattr(device, "os_family", None) or getattr(device, "platform", None),
                    "os_version": getattr(device, "os_version", None) or getattr(device, "platform_version", None),
                    "hostname": getattr(device, "hostname", None),
                    "confidence": getattr(device, "confidence", 0) or getattr(device, "certainty", 0),
                    "is_randomized_mac": getattr(device, "is_randomized_mac", False) or getattr(device, "mac_randomized", False),
                    "correlated_mac": getattr(device, "correlated_mac", None) or getattr(device, "real_hw_addr", None),
                }
            elif isinstance(device, dict):
                device_dict = device
            else:
                device_dict = {}

            await websocket.send_json({
                "protocol": packet.protocol,
                "timestamp": packet.timestamp.isoformat() if packet.timestamp else None,
                "src_mac": packet.src_mac,
                "src_ip": packet.src_ip,
                "dst_mac": getattr(packet, "dst_mac", None),
                "dst_ip": getattr(packet, "dst_ip", None),
                "interface": packet.interface,
                "network": packet.network,
                "data": {k: str(v) if not isinstance(v, (str, int, float, bool, type(None))) else v
                         for k, v in (packet.data or {}).items()},
                "device": device_dict,
                "matches": [
                    {
                        "source": m.source,
                        "match_type": m.match_type,
                        "confidence": int(m.confidence * 100),
                        "manufacturer": m.manufacturer,
                        "os_family": m.os_family,
                        "os_version": m.os_version,
                        "device_type": m.device_type,
                        "model": m.model,
                    }
                    for m in matches
                ] if matches else [],
                "alerts": [
                    {
                        "alert_type": str(a.alert_type),
                        "severity": str(a.severity),
                        "message": a.message,
                    }
                    for a in alerts_list
                ] if alerts_list else [],
            })
    except (WebSocketDisconnect, Exception):
        app_instance.unsubscribe(events)



# --- Legacy Routes removed — React SPA serves all pages ---


# --- Entry Point ---

def run_web(interfaces: list | None = None, host: str = "0.0.0.0", port: int = 8080, app: LeethaApp | None = None, force_auth=None):
    """Start the web UI server (blocking — creates its own event loop).

    The LeethaApp is constructed in a background thread to avoid blocking
    uvicorn startup. The web UI is available immediately while fingerprint
    databases load in the background.
    """
    global app_instance, _auth_enabled
    from leetha.auth.middleware import check_auth_required
    _auth_enabled = check_auth_required(host, force_auth)
    if app is not None:
        app_instance = app
    else:
        import threading

        def _init_app():
            global app_instance
            app_instance = LeethaApp(interfaces=interfaces)
            logger.info("LeethaApp constructed — starting capture engine...")
            # Start the app in a new event loop on this thread.
            # The loop must keep running so that async tasks
            # (_process_loop, _analysis_loop, workers) stay alive.
            import asyncio as _aio
            loop = _aio.new_event_loop()
            _aio.set_event_loop(loop)
            try:
                loop.run_until_complete(app_instance.start())
                logger.info("Backend fully initialized — all services ready")
                # Bootstrap admin token if auth is enabled and no admin token exists
                if _auth_enabled:
                    async def _bootstrap_admin():
                        count = await app_instance.db.count_active_admin_tokens()
                        if count == 0:
                            from leetha.auth.tokens import generate_token as _gen, hash_token as _hash, save_admin_token
                            from rich.console import Console as RichConsole
                            raw = _gen()
                            await app_instance.db.create_auth_token(_hash(raw), role="admin", label="auto-generated")
                            save_admin_token(raw)
                            rc = RichConsole()
                            rc.print("\n[bold green]Admin token generated:[/bold green]")
                            rc.print(f"[bold yellow]{raw}[/bold yellow]")
                            rc.print("[dim]Saved to ~/.leetha/admin-token[/dim]\n")
                    loop.run_until_complete(_bootstrap_admin())
                # Keep the event loop running so background tasks continue
                loop.run_forever()
            except Exception as e:
                logger.error(f"Backend start failed: {e}")
            finally:
                loop.close()

        init_thread = threading.Thread(target=_init_app, daemon=True)
        init_thread.start()

    uvicorn.run(_wrapped_app, host=host, port=port, log_level="info")


async def run_web_async(interfaces: list | None = None, host: str = "0.0.0.0", port: int = 8080, app: LeethaApp | None = None, force_auth=None):
    """Start the web UI server within an existing event loop."""
    global app_instance, _auth_enabled
    from leetha.auth.middleware import check_auth_required
    _auth_enabled = check_auth_required(host, force_auth)
    if app is not None:
        app_instance = app
    else:
        app_instance = LeethaApp(interfaces=interfaces)
    config = uvicorn.Config(_wrapped_app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()


# --- React SPA ---

_dist_dir = web_dir / "dist"

if _dist_dir.exists():
    # Serve built React assets (JS, CSS, etc.)
    _dist_assets = _dist_dir / "assets"
    if _dist_assets.exists():
        fastapi_app.mount("/assets", StaticFiles(directory=str(_dist_assets)), name="react-assets")

    # SPA middleware: intercept client-side routes and serve React's index.html.
    # This runs BEFORE FastAPI's router, so /api/* routes still work normally.
    _spa_html_bytes = (_dist_dir / "index.html").read_bytes() if (_dist_dir / "index.html").exists() else None

    _SPA_PATHS = {
        "/", "/login", "/inventory", "/alerts", "/threats", "/detections", "/exposure",
        "/stream", "/feeds", "/rules", "/adapters", "/settings",
        # Legacy routes redirect to new paths via React Router
        "/devices", "/threat-detection", "/attack-surface",
        "/console", "/sync", "/patterns", "/interfaces",
        "/topology",
    }
    _SPA_PREFIXES = ("/docs/", "/info/",)

    from starlette.types import ASGIApp, Receive, Scope, Send
    from starlette.responses import Response as StarletteResponse

    class _SPAFallback:
        """ASGI middleware that serves React SPA for non-API paths.

        Unlike route-based approaches, this intercepts at the ASGI level
        BEFORE FastAPI routing, guaranteeing all client-side routes resolve.
        """

        def __init__(self, app: ASGIApp):
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send):
            if scope["type"] == "http" and _spa_html_bytes:
                path: str = scope.get("path", "")
                # Let API, asset, and WebSocket requests pass through
                if path.startswith(("/api/", "/assets/", "/ws")):
                    await self.app(scope, receive, send)
                    return
                # Serve SPA for known client-side routes
                if path in _SPA_PATHS or any(path.startswith(p) for p in _SPA_PREFIXES):
                    resp = StarletteResponse(
                        content=_spa_html_bytes,
                        media_type="text/html",
                    )
                    await resp(scope, receive, send)
                    return
            await self.app(scope, receive, send)

    # Wrap the entire ASGI app — this ensures the middleware runs FIRST
    _wrapped_app = _SPAFallback(fastapi_app)
else:
    # No dist/ directory — serve API only
    _wrapped_app = fastapi_app
