"""MAC randomization detection rules."""
from __future__ import annotations
from datetime import datetime, timedelta
from leetha.rules.registry import register_rule
from leetha.rules.base import FindingRule as RuleBase
from leetha.store.models import Host, Finding, FindingRule, AlertSeverity
from leetha.evidence.models import Verdict

@register_rule("randomized_addr")
class RandomizedAddrRule(RuleBase):
    severity = "info"

    async def evaluate(self, host: Host, verdict: Verdict, store) -> Finding | None:
        if host.mac_randomized:
            hw_addr = host.hw_addr
            # Deduplicate: skip if an unresolved finding already exists for this MAC+rule
            cursor = await store.connection.execute(
                "SELECT COUNT(*) FROM findings WHERE hw_addr = ? AND rule = ? AND resolved = 0",
                (hw_addr, "randomized_addr"),
            )
            existing = (await cursor.fetchone())[0]
            if existing > 0:
                return None

            # Build a descriptive message with device context
            parts = [f"Randomized MAC detected: {hw_addr}"]
            device_label = verdict.vendor or ""
            if verdict.hostname:
                device_label = f"{verdict.hostname} ({verdict.vendor})" if verdict.vendor else verdict.hostname
            elif verdict.vendor:
                device_label = verdict.vendor
            if device_label:
                parts.append(f"identified as {device_label}")
            if verdict.platform:
                parts.append(f"running {verdict.platform}")
            if host.real_hw_addr:
                parts.append(f"real MAC: {host.real_hw_addr}")
            if host.ip_addr:
                parts.append(f"IP: {host.ip_addr}")

            return Finding(
                hw_addr=hw_addr,
                rule=FindingRule.RANDOMIZED_ADDR,
                severity=AlertSeverity.INFO,
                message=" — ".join(parts),
            )
        return None


@register_rule("randomized_addr_collision")
class RandomizedAddrCollisionRule(RuleBase):
    """Detect when a randomized MAC shares a hostname with another active device.

    This catches two scenarios:
    1. Normal MAC rotation — device changed its randomized MAC (benign, if
       the old MAC is now offline).
    2. Possible spoofing — a new MAC appeared with the same identity as a
       device that's still active on a different MAC.
    """
    severity = "warning"

    async def evaluate(self, host: Host, verdict: Verdict, store) -> Finding | None:
        if not host.mac_randomized:
            return None
        if not verdict.hostname:
            return None

        hw_addr = host.hw_addr

        # Deduplicate — check both rule types this rule can produce
        cursor = await store.connection.execute(
            "SELECT COUNT(*) FROM findings WHERE hw_addr = ? "
            "AND rule IN ('behavioral_drift', 'randomized_addr') "
            "AND resolved = 0 "
            "AND message LIKE '%shares hostname%' OR message LIKE '%MAC rotation%'",
            (hw_addr,),
        )
        if (await cursor.fetchone())[0] > 0:
            return None

        # Find other hosts with the same hostname on a different MAC
        cursor = await store.connection.execute(
            "SELECT h.hw_addr, h.ip_addr, h.last_active, v.vendor "
            "FROM hosts h "
            "LEFT JOIN verdicts v ON h.hw_addr = v.hw_addr "
            "WHERE v.hostname = ? AND h.hw_addr != ? "
            "ORDER BY h.last_active DESC LIMIT 5",
            (verdict.hostname, hw_addr),
        )
        matches = await cursor.fetchall()
        if not matches:
            return None

        # Check if any match is still recently active (within 30 minutes)
        active_threshold = datetime.now() - timedelta(minutes=30)
        active_matches = []
        stale_matches = []
        for m in matches:
            try:
                last = datetime.fromisoformat(m[2])
                if last >= active_threshold:
                    active_matches.append(m)
                else:
                    stale_matches.append(m)
            except (TypeError, ValueError):
                stale_matches.append(m)

        if active_matches:
            # Another device with this hostname is still active — suspicious
            other = active_matches[0]
            other_label = f"{other[3]} {other[1]}" if other[3] else other[0]
            return Finding(
                hw_addr=hw_addr,
                rule=FindingRule.BEHAVIORAL_DRIFT,
                severity=AlertSeverity.WARNING,
                message=(
                    f"Randomized MAC {hw_addr} shares hostname \"{verdict.hostname}\" "
                    f"with active device {other_label} ({other[0]}). "
                    f"Possible MAC rotation or spoofing attempt."
                ),
            )

        # Old MAC is offline — likely a normal MAC rotation, informational only
        if stale_matches:
            other = stale_matches[0]
            return Finding(
                hw_addr=hw_addr,
                rule=FindingRule.RANDOMIZED_ADDR,
                severity=AlertSeverity.INFO,
                message=(
                    f"MAC rotation detected: {hw_addr} appears to be the same device "
                    f"as {other[0]} (hostname: \"{verdict.hostname}\"). "
                    f"Previous MAC is now offline."
                ),
            )

        return None
