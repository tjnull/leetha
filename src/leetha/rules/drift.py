"""Drift detection rules — unexpected identity and address changes."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from leetha.rules.registry import register_rule
from leetha.rules.base import FindingRule as RuleBase
from leetha.store.models import Host, Finding, FindingRule, AlertSeverity
from leetha.evidence.models import Verdict

_MIN_CERTAINTY = 50
_MIN_EVIDENCE_COUNT = 3
_GRACE_PERIOD_SECONDS = 60
_COOLDOWN_SECONDS = 300

_last_fired: dict[str, float] = {}


@register_rule("identity_shift")
class IdentityShiftRule(RuleBase):
    """Detect when a host's fingerprint class changes unexpectedly."""
    severity = "critical"

    async def evaluate(self, host: Host, verdict: Verdict, store) -> Finding | None:
        existing = await store.verdicts.find_by_addr(host.hw_addr)
        if existing is None:
            return None

        if existing.certainty < _MIN_CERTAINTY or verdict.certainty < _MIN_CERTAINTY:
            return None

        if len(existing.evidence_chain) < _MIN_EVIDENCE_COUNT:
            return None

        age = (datetime.now(timezone.utc) - host.discovered_at).total_seconds()
        if age < _GRACE_PERIOD_SECONDS:
            return None

        now = time.monotonic()

        # Prune stale cooldown entries to prevent unbounded growth
        if len(_last_fired) > 10000:
            stale = [k for k, v in _last_fired.items() if now - v > 600]
            for k in stale:
                del _last_fired[k]

        last = _last_fired.get(host.hw_addr, 0)
        if now - last < _COOLDOWN_SECONDS:
            return None

        cat_changed = (existing.category and verdict.category
                       and existing.category != verdict.category)
        vendor_changed = (existing.vendor and verdict.vendor
                          and existing.vendor != verdict.vendor)
        platform_changed = (existing.platform and verdict.platform
                            and existing.platform != verdict.platform)
        version_changed = (existing.platform_version and verdict.platform_version
                           and existing.platform_version != verdict.platform_version)

        if not (cat_changed or vendor_changed or platform_changed or version_changed):
            return None

        if cat_changed or vendor_changed:
            severity = AlertSeverity.CRITICAL
            parts = []
            if cat_changed:
                parts.append(f"category: {existing.category} \u2192 {verdict.category}")
            if vendor_changed:
                parts.append(f"vendor: {existing.vendor} \u2192 {verdict.vendor}")
            if platform_changed:
                parts.append(f"platform: {existing.platform} \u2192 {verdict.platform}")
            detail = ", ".join(parts)
            message = f"Identity shift on {host.hw_addr}: {detail}"
        elif platform_changed:
            severity = AlertSeverity.HIGH
            message = (f"Platform changed on {host.hw_addr}: "
                       f"{existing.platform} \u2192 {verdict.platform}")
        else:
            severity = AlertSeverity.INFO
            message = (f"Platform version changed on {host.hw_addr}: "
                       f"{existing.platform_version} \u2192 {verdict.platform_version}")

        _last_fired[host.hw_addr] = now

        return Finding(
            hw_addr=host.hw_addr,
            rule=FindingRule.IDENTITY_SHIFT,
            severity=severity,
            message=message,
        )


_addr_conflict_last_fired: dict[str, float] = {}
_ADDR_CONFLICT_COOLDOWN = 300  # 5 minutes


@register_rule("addr_conflict")
class AddrConflictRule(RuleBase):
    """Detect multiple MACs claiming the same IP address."""
    severity = "high"

    async def evaluate(self, host: Host, verdict: Verdict, store) -> Finding | None:
        if not host.ip_addr:
            return None

        # In-memory cooldown per MAC
        now = time.monotonic()

        # Prune stale cooldown entries to prevent unbounded growth
        if len(_addr_conflict_last_fired) > 10000:
            stale = [k for k, v in _addr_conflict_last_fired.items() if now - v > 600]
            for k in stale:
                del _addr_conflict_last_fired[k]

        last = _addr_conflict_last_fired.get(host.hw_addr, 0)
        if now - last < _ADDR_CONFLICT_COOLDOWN:
            return None

        # Only consider recently-active hosts to avoid stale conflicts
        cursor = await store.connection.execute(
            "SELECT hw_addr FROM hosts WHERE ip_addr = ? AND hw_addr != ? "
            "AND last_active > datetime('now', '-5 minutes')",
            (host.ip_addr, host.hw_addr),
        )
        conflicts = await cursor.fetchall()
        if not conflicts:
            return None

        # DB-level dedup: skip if an unresolved finding already exists
        dedup_cursor = await store.connection.execute(
            "SELECT COUNT(*) FROM findings WHERE hw_addr = ? AND rule = 'addr_conflict' AND resolved = 0",
            (host.hw_addr,),
        )
        if (await dedup_cursor.fetchone())[0] > 0:
            return None

        _addr_conflict_last_fired[host.hw_addr] = now

        return Finding(
            hw_addr=host.hw_addr,
            rule=FindingRule.ADDR_CONFLICT,
            severity=AlertSeverity.HIGH,
            message=f"Address conflict: {host.ip_addr} claimed by "
                    f"{host.hw_addr} and {conflicts[0][0]}",
        )
