"""
Alert engine — evaluates devices against alert rules and creates alerts.

Alert types:
- NEW_DEVICE: MAC never seen before
- OS_CHANGE: Known device's OS fingerprint changed
- SPOOFING: MAC/IP mismatch or duplicate MAC on different IPs
- UNCLASSIFIED: Device confidence < 50%
- SOURCE_STALE: Fingerprint database hasn't been updated in > 30 days
"""

from __future__ import annotations

import time

from leetha.store.database import Database
from leetha.store.models import Alert, AlertType, AlertSeverity, Device

_OS_CHANGE_COOLDOWN = 300  # 5 minutes
_INFRA_DEVICE_TYPES = frozenset({
    "router", "switch", "gateway", "access_point", "firewall",
    "load_balancer", "Router", "UniFi Switch", "UniFi AP",
    "mesh_router", "network_device", "wireless_bridge", "cable_modem",
})


class AlertEngine:
    def __init__(self, db: Database) -> None:
        self.db = db
        self._os_change_last_fired: dict[str, float] = {}

    @staticmethod
    def _device_summary(device: Device) -> str:
        """Build a short human-readable identifier for a device."""
        parts = []
        if device.hostname:
            parts.append(device.hostname)
        if device.manufacturer:
            parts.append(device.manufacturer)
        if device.device_type:
            parts.append(device.device_type.replace("_", " "))
        ip = device.ip_v4 or device.ip_v6
        if ip:
            parts.append(ip)
        return " / ".join(parts) if parts else device.mac

    async def evaluate(self, device: Device) -> list[Alert]:
        """Evaluate a device against alert rules. Returns new alerts."""
        # Check which alert types are now handled by FindingRule system
        # to avoid duplicate detections.
        from leetha.rules.registry import get_rule
        _rules_handle_new_device = get_rule("new_host") is not None
        _rules_handle_os_change = get_rule("identity_shift") is not None
        _rules_handle_low_confidence = get_rule("low_certainty") is not None

        alerts: list[Alert] = []
        existing = await self.db.get_device(device.mac)
        summary = self._device_summary(device)

        # Skip alert generation for operator's own device
        if device.alert_status == "self":
            await self.db.upsert_device(device)
            return alerts

        # Rule 1: New device (never seen before)
        # Skip if FindingRule system handles new host detection
        if _rules_handle_new_device:
            pass
        elif existing is None:
            alerts.append(Alert(
                device_mac=device.mac,
                alert_type=AlertType.NEW_DEVICE,
                severity=AlertSeverity.INFO,
                message=f"New device discovered: {summary}",
            ))

        # Rule 2: OS change on known device
        # Skip if FindingRule system handles identity shift detection
        if _rules_handle_os_change:
            pass
        elif existing and existing.alert_status == "known":
            if (
                existing.os_family
                and device.os_family
                and existing.os_family != device.os_family
            ):
                # Skip low-confidence detections
                if device.confidence is not None and device.confidence < 50:
                    pass
                # Skip infrastructure devices (routers, switches, APs)
                elif device.device_type and device.device_type in _INFRA_DEVICE_TYPES:
                    pass
                else:
                    # Per-MAC cooldown (5 minutes)
                    now = time.monotonic()
                    # Prune stale cooldown entries to prevent unbounded growth
                    if len(self._os_change_last_fired) > 10000:
                        stale = [k for k, v in self._os_change_last_fired.items() if now - v > 600]
                        for k in stale:
                            del self._os_change_last_fired[k]
                    last = self._os_change_last_fired.get(device.mac, 0)
                    if now - last >= _OS_CHANGE_COOLDOWN:
                        self._os_change_last_fired[device.mac] = now
                        alerts.append(Alert(
                            device_mac=device.mac,
                            alert_type=AlertType.OS_CHANGE,
                            severity=AlertSeverity.WARNING,
                            message=(
                                f"OS changed on {summary}: "
                                f"{existing.os_family} -> {device.os_family}"
                            ),
                        ))

        # Rule 3: Low confidence (unclassified)
        # Skip if FindingRule system handles low certainty detection
        if _rules_handle_low_confidence:
            pass
        elif (
            device.confidence is not None
            and device.confidence < 50
            and device.alert_status == "known"
        ):
            alerts.append(Alert(
                device_mac=device.mac,
                alert_type=AlertType.UNCLASSIFIED,
                severity=AlertSeverity.LOW,
                message=f"Low confidence ({device.confidence}%) for {summary}",
            ))

        # Rule 4: Randomized MAC detected
        if device.is_randomized_mac and existing is None:
            msg = f"Randomized MAC on {summary}"
            if device.identity_id and device.correlated_mac:
                msg += f" (grouped with {device.correlated_mac})"
            elif device.correlated_mac:
                msg += f" (correlated with {device.correlated_mac})"
            alerts.append(Alert(
                device_mac=device.mac,
                alert_type=AlertType.MAC_RANDOMIZED,
                severity=AlertSeverity.INFO,
                message=msg,
            ))

        # Persist the device so subsequent evaluations can find it
        await self.db.upsert_device(device)

        # Persist alerts
        for alert in alerts:
            await self.db.add_alert(alert)

        return alerts

    async def check_stale_sources(self, data_dir, max_age_days: int = 30) -> list:
        """Check sync source files for staleness and generate alerts."""
        import time
        from pathlib import Path
        alerts = []
        data_dir = Path(data_dir)
        now = time.time()
        max_age_seconds = max_age_days * 86400

        if not data_dir.exists():
            return alerts

        for filepath in data_dir.iterdir():
            if not filepath.is_file():
                continue
            if filepath.suffix not in (".json", ".csv", ".fp", ".txt"):
                continue
            age = now - filepath.stat().st_mtime
            if age > max_age_seconds:
                days_old = int(age / 86400)
                alert = Alert(
                    device_mac="00:00:00:00:00:00",
                    alert_type=AlertType.SOURCE_STALE,
                    severity=AlertSeverity.WARNING,
                    message=f"Fingerprint source {filepath.name} is {days_old} days old (threshold: {max_age_days}d). Run 'leetha sync' to update.",
                )
                await self.db.add_alert(alert)
                alerts.append(alert)
        return alerts

    async def check_infra_offline(self, offline_minutes: int = 5) -> list[Alert]:
        """Check for infrastructure devices (routers, switches, APs) that have gone offline.

        Generates alerts when a router, switch, access point, firewall, or gateway
        hasn't been seen for longer than `offline_minutes`. Gateways get CRITICAL
        severity; other infrastructure gets WARNING.
        """
        from datetime import datetime, timedelta, timezone
        from leetha.topology import _normalize_device_type, _INFRA_TYPES

        alerts: list[Alert] = []
        threshold = datetime.now(timezone.utc) - timedelta(minutes=offline_minutes)

        all_devices = await self.db.list_devices()
        existing_alerts = await self.db.list_alerts(acknowledged=False)
        for device in all_devices:
            if not device.device_type:
                continue
            normalized = _normalize_device_type(device.device_type)
            if normalized not in _INFRA_TYPES:
                continue
            if device.alert_status == "self":
                continue

            # Check last_seen
            last_seen = device.last_seen
            if last_seen is None:
                continue
            if isinstance(last_seen, str):
                try:
                    last_seen = datetime.fromisoformat(last_seen)
                except Exception:
                    continue

            if last_seen >= threshold:
                continue  # Still online

            # Rate-limit: don't re-alert if we already have an active infra_offline
            # alert for this device
            already_alerted = any(
                a.device_mac == device.mac and a.alert_type == AlertType.INFRA_OFFLINE.value
                for a in existing_alerts
            )
            if already_alerted:
                continue

            minutes_ago = int((datetime.now(timezone.utc) - last_seen).total_seconds() / 60)
            summary = self._device_summary(device)
            is_gateway = normalized in ("router", "gateway", "firewall")
            severity = AlertSeverity.CRITICAL if is_gateway else AlertSeverity.WARNING

            alert = Alert(
                device_mac=device.mac,
                alert_type=AlertType.INFRA_OFFLINE,
                severity=severity,
                message=(
                    f"{'Gateway' if is_gateway else 'Infrastructure device'} offline: "
                    f"{summary} — last seen {minutes_ago} minutes ago"
                ),
            )
            await self.db.add_alert(alert)
            alerts.append(alert)

        return alerts

    async def process_dhcp_anomalies(self, anomalies: list[dict]) -> list:
        """Convert DHCP anomaly analysis results into alerts."""
        alerts = []
        for anomaly in anomalies:
            alert = Alert(
                device_mac=anomaly.get("src_mac", "00:00:00:00:00:00"),
                alert_type=AlertType.DHCP_ANOMALY,
                severity=AlertSeverity.WARNING,
                message=f"DHCP anomaly on option '{anomaly.get('option', '?')}': {anomaly.get('reason', 'unknown')}",
            )
            await self.db.add_alert(alert)
            alerts.append(alert)
        return alerts
