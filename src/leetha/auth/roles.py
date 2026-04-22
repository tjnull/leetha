"""Role-based access control definitions."""
from __future__ import annotations

ADMIN_ONLY_PREFIXES = (
    "/api/auth/tokens",
    "/api/auth/revoke",
    "/api/capture/restart",
    "/api/settings/db",
    "/api/settings/import",
    "/api/settings/query",
)

# Phase A authorization endpoints — device approval state is a security
# decision and must not be delegated to analyst tokens.
_AUTHORIZATION_SUFFIXES = ("/approve", "/reject", "/revoke")

ADMIN_ONLY_METHODS: dict[str, tuple[str, ...]] = {
    "PUT": ("/api/settings",),
    "DELETE": ("/api/alerts", "/api/trust", "/api/suppressions", "/api/patterns"),
    "POST": (
        "/api/settings/apply",
        "/api/settings/reset",
        # Phase A — baseline operations flip every device; admin-only.
        "/api/baseline/set",
        "/api/baseline/reset",
        # Phase A — bulk authorization (can approve/reject the whole fleet).
        "/api/devices/bulk/authorization",
        # Phase A — inventory imports populate devices and can flood the
        # discovery pipeline; treat as a privileged operation.
        "/api/inventory/",
    ),
}


def requires_admin(method: str, path: str) -> bool:
    """Return True if this method+path combination requires admin role."""
    for prefix in ADMIN_ONLY_PREFIXES:
        if path.startswith(prefix):
            return True
    method_prefixes = ADMIN_ONLY_METHODS.get(method.upper(), ())
    for prefix in method_prefixes:
        if path.startswith(prefix):
            return True
    # Phase A per-device authorization mutations follow the pattern
    # POST /api/devices/{mac}/(approve|reject|revoke) — admin only.
    if method.upper() == "POST" and path.startswith("/api/devices/"):
        for suffix in _AUTHORIZATION_SUFFIXES:
            if path.endswith(suffix):
                return True
    return False
