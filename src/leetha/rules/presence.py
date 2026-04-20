"""Phase A.4 Task 31 — presence rules (offline/online).

These rules are *not* plugged into the standard packet-driven rule engine
because they're driven by the presence sweeper rather than by per-packet
evaluation. Instead, the sweeper's callback calls ``handle_presence_transition``,
which emits findings and auto-resolves stale ones.
"""

from __future__ import annotations

import logging

from leetha.presence.sweeper import PresenceTransition
from leetha.store.models import Finding, FindingRule, AlertSeverity

log = logging.getLogger(__name__)


_OFFLINE_SEVERITY_BY_CRIT = {
    None: AlertSeverity.INFO,
    "low": AlertSeverity.INFO,
    "medium": AlertSeverity.INFO,
    "high": AlertSeverity.WARNING,
    "critical": AlertSeverity.WARNING,
}


def severity_for_offline(criticality: str | None) -> AlertSeverity:
    return _OFFLINE_SEVERITY_BY_CRIT.get(criticality, AlertSeverity.INFO)


async def handle_presence_transition(store, transition: PresenceTransition) -> Finding | None:
    """Emit a Finding for a presence transition, and resolve stale counterparts.

    - ``online → offline`` fires ``device_went_offline`` at a severity that scales
      with the device's criticality.
    - ``offline → online`` fires ``device_came_online`` (always INFO) and resolves
      any unresolved ``device_went_offline`` findings for this MAC.
    """
    if transition.new_state == "offline":
        sev = severity_for_offline(transition.criticality)
        finding = Finding(
            hw_addr=transition.mac,
            rule=FindingRule.DEVICE_WENT_OFFLINE,
            severity=sev,
            message=(
                f"Device {transition.mac} went offline "
                f"(no traffic for > {transition.threshold_seconds}s)"
            ),
        )
        try:
            await store.findings.add(finding)
        except Exception:
            log.exception("failed to persist device_went_offline finding")
        return finding

    if transition.new_state == "online":
        # Resolve any unresolved went_offline findings for this MAC
        try:
            async with store.connection.execute(
                "UPDATE findings SET resolved = 1 "
                "WHERE hw_addr = ? AND rule = ? AND resolved = 0",
                (transition.mac, FindingRule.DEVICE_WENT_OFFLINE.value),
            ) as _:
                await store.connection.commit()
        except Exception:
            log.exception("failed to auto-resolve went_offline findings")
        finding = Finding(
            hw_addr=transition.mac,
            rule=FindingRule.DEVICE_CAME_ONLINE,
            severity=AlertSeverity.INFO,
            message=f"Device {transition.mac} came back online",
        )
        try:
            await store.findings.add(finding)
        except Exception:
            log.exception("failed to persist device_came_online finding")
        return finding

    return None
