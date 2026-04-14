"""
Address verification and ARP integrity analysis.

Capabilities:
- Duplicate IP detection via ARP (multiple MACs on one IP)
- Gateway binding enforcement (trusted association violations)
- Gratuitous ARP burst detection
- MAC oscillation on IPs (rapid address changes)
- Fingerprint shift detection (potential MAC cloning)
- OUI-to-behavior discrepancy checks
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque

from leetha.store.database import Database
from leetha.store.models import Alert, AlertType, AlertSeverity, Device

_log = logging.getLogger(__name__)

# --- Tunables ---
GRATUITOUS_BURST_WINDOW = 60          # seconds
GRATUITOUS_BURST_LIMIT = 20           # packets within window
GRATUITOUS_BURST_LIMIT_INFRA = 50     # higher threshold for infrastructure devices
MAC_OSCILLATION_WINDOW = 300          # seconds
MAC_OSCILLATION_CHANGE_LIMIT = 3      # transitions
RATE_LIMIT_INTERVAL = 300             # seconds between duplicate alerts

_INFRA_TYPES = {"router", "switch", "gateway", "access_point", "firewall",
                "load_balancer", "Router", "UniFi Switch", "UniFi AP"}

# Known-legitimate OUI vendor -> behavioural manufacturer pairings.
# Many devices use NICs made by a different vendor than the device manufacturer.
_KNOWN_OUI_VENDOR_PAIRS: dict[str, set[str]] = {
    "hon hai": {"apple", "apple inc", "dell", "dell inc", "dell technologies", "hp", "hewlett-packard", "hewlett packard", "lenovo", "lenovo group", "cisco"},
    "foxconn": {"apple", "apple inc", "dell", "dell inc", "dell technologies", "hp", "hewlett-packard", "hewlett packard", "lenovo", "lenovo group", "cisco"},
    "murata": {"apple", "apple inc", "sony", "samsung"},
    "intel": {"dell", "dell inc", "dell technologies", "hp", "hewlett-packard", "hewlett packard", "lenovo", "lenovo group", "apple", "apple inc", "microsoft"},
    "broadcom": {"apple", "apple inc", "dell", "dell inc", "dell technologies", "hp", "hewlett-packard", "hewlett packard"},
    "qualcomm": {"samsung", "oneplus", "xiaomi", "oppo"},
    "realtek": {"dell", "dell inc", "dell technologies", "hp", "hewlett-packard", "hewlett packard", "lenovo", "lenovo group", "asus"},
    "quanta": {"dell", "dell inc", "dell technologies", "hp", "hewlett-packard", "hewlett packard", "lenovo", "lenovo group"},
    "pegatron": {"apple", "apple inc", "asus"},
    "wistron": {"dell", "dell inc", "dell technologies", "hp", "hewlett-packard", "hewlett packard", "lenovo", "lenovo group", "acer"},
    "compal": {"dell", "dell inc", "dell technologies", "hp", "hewlett-packard", "hewlett packard", "lenovo", "lenovo group", "toshiba"},
    "lite-on": {"dell", "dell inc", "dell technologies", "hp", "hewlett-packard", "hewlett packard", "lenovo", "lenovo group"},
}


class AddressVerifier:
    """Monitors ARP traffic and device updates to surface spoofing indicators."""

    def __init__(self, db: Database) -> None:
        self._db = db

        # Runtime state -- populated by prepare()
        self._arp_timeline: dict[str, dict] = {}               # ip -> {mac, seen_at}
        self._addr_associations: dict[str, str] = {}            # ip -> pinned mac
        self._mute_rules: list[dict] = []                       # loaded suppression entries
        self._gratuitous_timestamps: dict[str, deque] = defaultdict(deque)  # mac -> deque of timestamps
        self._oscillation_log: dict[str, list[tuple[str, float]]] = defaultdict(list)  # ip -> [(mac, ts)]
        self._rate_limiter: dict[str, float] = {}               # composite key -> last fire time

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def prepare(self) -> None:
        """Load persisted bindings and suppression rules into memory."""
        trusted = await self._db.list_trusted_bindings()
        for entry in trusted:
            self._addr_associations[entry["ip"]] = entry["mac"]
        await self.refresh_mute_rules()

    # Keep legacy name working
    initialize = prepare

    async def refresh_mute_rules(self) -> None:
        """Pull current suppression rules from the database."""
        self._mute_rules = await self._db.list_suppression_rules()

    # Backward-compat alias
    reload_suppressions = refresh_mute_rules

    # ------------------------------------------------------------------
    # Suppression / rate-limiting helpers
    # ------------------------------------------------------------------

    def is_suppressed(self, mac: str, ip: str | None, subtype: str) -> bool:
        """Return True when any active mute rule matches the given alert fields.

        A rule matches only if every non-null field in the rule equals
        the corresponding argument.
        """
        for rule in self._mute_rules:
            if rule["mac"] is not None and rule["mac"] != mac:
                continue
            if rule["ip"] is not None and rule["ip"] != ip:
                continue
            if rule["subtype"] is not None and rule["subtype"] != subtype:
                continue
            return True
        return False

    def _rate_limit_ok(self, composite_key: str) -> bool:
        """Return True if enough time has elapsed since the last alert for this key."""
        now = time.monotonic()
        prev = self._rate_limiter.get(composite_key)
        if prev is not None and (now - prev) < RATE_LIMIT_INTERVAL:
            return False
        self._rate_limiter[composite_key] = now
        return True

    # Keep the old private name available
    _should_alert = _rate_limit_ok

    # ------------------------------------------------------------------
    # Context builder
    # ------------------------------------------------------------------

    async def _describe_host(self, mac: str, ip: str | None = None) -> str:
        """Return a human-readable label: MAC + IP + hostname when available."""
        fragments = [mac]
        record = await self._db.get_device(mac)
        if ip:
            fragments.append(ip)
        elif record and record.ip_v4:
            fragments.append(record.ip_v4)
        if record and record.hostname:
            fragments.append(f"({record.hostname})")
        return " ".join(fragments)

    # Alias retained for any internal callers
    _mac_context = _describe_host

    # ------------------------------------------------------------------
    # ARP inspection
    # ------------------------------------------------------------------

    async def inspect_arp(
        self,
        src_mac: str,
        src_ip: str,
        dst_mac: str,
        dst_ip: str,
        op: int,
        interface: str,
    ) -> list[Alert]:
        """Examine a single ARP packet and yield any resulting alerts."""
        findings: list[Alert] = []
        gratuitous = (op == 2 and src_ip == dst_ip)

        # Persist the observation
        await self._db.upsert_arp_entry(src_mac, src_ip, interface, gratuitous)

        # --- Check 1: trusted binding enforcement (gateway impersonation) ---
        pinned_mac = self._addr_associations.get(src_ip)
        if pinned_mac and pinned_mac != src_mac:
            rl_key = f"gateway_impersonation:{src_ip}:{src_mac}"
            if self._rate_limit_ok(rl_key) and not self.is_suppressed(src_mac, src_ip, "gateway_impersonation"):
                src_label = await self._describe_host(src_mac, src_ip)
                pinned_label = await self._describe_host(pinned_mac, src_ip)
                findings.append(Alert(
                    device_mac=src_mac,
                    alert_type=AlertType.SPOOFING,
                    severity=AlertSeverity.CRITICAL,
                    message=(
                        f"Trusted binding violation: {src_ip} bound to "
                        f"{pinned_label} but {src_label} is claiming it"
                    ),
                ))

        # --- Check 2: IP conflict (only when no trusted binding exists) ---
        prior = self._arp_timeline.get(src_ip)
        if prior and prior["mac"] != src_mac and not pinned_mac:
            rl_key = f"ip_conflict:{src_ip}"
            if self._rate_limit_ok(rl_key) and not self.is_suppressed(src_mac, src_ip, "ip_conflict"):
                src_label = await self._describe_host(src_mac, src_ip)
                prior_label = await self._describe_host(prior["mac"], src_ip)
                findings.append(Alert(
                    device_mac=src_mac,
                    alert_type=AlertType.SPOOFING,
                    severity=AlertSeverity.WARNING,
                    message=(
                        f"IP conflict on {src_ip}: claimed by "
                        f"{prior_label} and {src_label}"
                    ),
                ))

        # --- Check 3: gratuitous ARP burst ---
        if gratuitous:
            mono_now = time.monotonic()
            ts_queue = self._gratuitous_timestamps[src_mac]
            ts_queue.append(mono_now)
            # Evict stale entries from the front
            earliest_valid = mono_now - GRATUITOUS_BURST_WINDOW
            while ts_queue and ts_queue[0] <= earliest_valid:
                ts_queue.popleft()

            # Infrastructure devices (VRRP/HSRP) legitimately send more
            # gratuitous ARPs during failover — use a higher threshold.
            is_infra_device = False
            try:
                dev_record = await self._db.get_device(src_mac)
                if dev_record and dev_record.device_type in _INFRA_TYPES:
                    is_infra_device = True
            except Exception:
                pass
            burst_limit = GRATUITOUS_BURST_LIMIT_INFRA if is_infra_device else GRATUITOUS_BURST_LIMIT

            if len(ts_queue) > burst_limit:
                rl_key = f"grat_flood:{src_mac}"
                if self._rate_limit_ok(rl_key) and not self.is_suppressed(src_mac, src_ip, "grat_flood"):
                    src_label = await self._describe_host(src_mac, src_ip)
                    findings.append(Alert(
                        device_mac=src_mac,
                        alert_type=AlertType.SPOOFING,
                        severity=AlertSeverity.HIGH,
                        message=(
                            f"Gratuitous ARP flood from {src_label}: "
                            f"{len(ts_queue)} in {GRATUITOUS_BURST_WINDOW}s"
                        ),
                    ))

        # --- Check 4: MAC oscillation on this IP ---
        mono_now = time.monotonic()
        osc_entries = self._oscillation_log[src_ip]
        osc_entries.append((src_mac, mono_now))
        # Trim to window
        earliest_valid = mono_now - MAC_OSCILLATION_WINDOW
        self._oscillation_log[src_ip] = [
            pair for pair in osc_entries if pair[1] > earliest_valid
        ]
        # Clean up empty entries
        empty_ips = [ip for ip, entries in self._oscillation_log.items() if not entries]
        for ip in empty_ips:
            del self._oscillation_log[ip]
        # Cap total size
        if len(self._oscillation_log) > 10000:
            oldest = sorted(self._oscillation_log.keys(),
                            key=lambda ip: min(e[1] for e in self._oscillation_log[ip]) if self._oscillation_log[ip] else 0)
            for ip in oldest[:len(self._oscillation_log) - 10000]:
                del self._oscillation_log[ip]
        osc_entries = self._oscillation_log.get(src_ip, [])

        # Tally transitions (consecutive entries with different MACs)
        change_count = sum(
            1 for idx in range(1, len(osc_entries))
            if osc_entries[idx][0] != osc_entries[idx - 1][0]
        )

        if change_count >= MAC_OSCILLATION_CHANGE_LIMIT:
            rl_key = f"flip_flop:{src_ip}"
            if self._rate_limit_ok(rl_key) and not self.is_suppressed(src_mac, src_ip, "flip_flop"):
                seen_macs = {m for m, _ in osc_entries}
                findings.append(Alert(
                    device_mac=src_mac,
                    alert_type=AlertType.SPOOFING,
                    severity=AlertSeverity.HIGH,
                    message=(
                        f"ARP flip-flop on {src_ip}: {change_count} MAC changes "
                        f"in {MAC_OSCILLATION_WINDOW}s between "
                        f"{', '.join(sorted(seen_macs))}"
                    ),
                ))

        # Record latest observation
        self._arp_timeline[src_ip] = {"mac": src_mac, "last_seen": time.monotonic()}

        return findings

    # Legacy name
    process_arp = inspect_arp

    # Alias requested in spec
    analyze_arp = inspect_arp

    # ------------------------------------------------------------------
    # Device-update analysis
    # ------------------------------------------------------------------

    async def process_device_update(
        self,
        device: Device,
        oui_vendor: str | None = None,
        snapshot_reader=None,
        snapshot_writer=None,
    ) -> list[Alert]:
        """Evaluate a device record change for signs of MAC cloning."""
        findings: list[Alert] = []

        # Randomized MACs shift fingerprints routinely -- skip alerting
        if device.is_randomized_mac:
            if snapshot_writer:
                await snapshot_writer(
                    hw_addr=device.mac,
                    os_family=device.os_family,
                    manufacturer=device.manufacturer,
                    device_type=device.device_type,
                    hostname=device.hostname,
                    oui_vendor=oui_vendor,
                )
            else:
                await self._db.add_fingerprint_snapshot(
                    mac=device.mac,
                    os_family=device.os_family,
                    manufacturer=device.manufacturer,
                    device_type=device.device_type,
                    hostname=device.hostname,
                    oui_vendor=oui_vendor,
                )
            return findings

        # --- Check 5: fingerprint shift ---
        is_infra = device.device_type in _INFRA_TYPES

        # Also check the DB record — current packet's device_type may be
        # temporarily wrong (e.g. router handling Windows traffic gets TTL 128)
        if not is_infra:
            try:
                stored = await self._db.get_device(device.mac)
                if stored and stored.device_type in _INFRA_TYPES:
                    is_infra = True
            except Exception:
                pass

        if snapshot_reader:
            prior_snapshots = await snapshot_reader(device.mac, limit=1)
        else:
            prior_snapshots = await self._db.get_fingerprint_history(device.mac, limit=1)
        if prior_snapshots:
            prev = prior_snapshots[0]
            deltas = []
            # Only flag OS drift for non-infrastructure devices
            if not is_infra and prev["os_family"] and device.os_family and prev["os_family"] != device.os_family:
                deltas.append(f"OS: {prev['os_family']} \u2192 {device.os_family}")
            if prev["manufacturer"] and device.manufacturer and prev["manufacturer"] != device.manufacturer:
                deltas.append(f"manufacturer: {prev['manufacturer']} \u2192 {device.manufacturer}")

            if deltas:
                rl_key = f"fp_drift:{device.mac}"
                if self._rate_limit_ok(rl_key) and not self.is_suppressed(device.mac, device.ip_v4, "fp_drift"):
                    id_parts = [device.mac]
                    if device.ip_v4:
                        id_parts.append(device.ip_v4)
                    if device.hostname:
                        id_parts.append(f"({device.hostname})")
                    host_label = " ".join(id_parts)
                    findings.append(Alert(
                        device_mac=device.mac,
                        alert_type=AlertType.SPOOFING,
                        severity=AlertSeverity.WARNING,
                        message=(
                            f"Fingerprint drift on {host_label}: "
                            + ", ".join(deltas)
                        ),
                    ))

        # --- Check 6: OUI vs behavioural manufacturer mismatch ---
        if (
            oui_vendor
            and device.manufacturer
            and device.confidence is not None and device.confidence >= 60
            and not device.is_randomized_mac
        ):
            oui_norm = oui_vendor.lower()
            mfg_norm = device.manufacturer.lower()
            # Check if this is a known-legitimate OUI-to-manufacturer pairing
            # Uses substring matching to handle vendor name variations
            # (e.g. "hewlett-packard" matches "hp" set entry and vice versa)
            is_known_pair = any(
                oui_key in oui_norm and any(mfg in mfg_norm or mfg_norm in mfg for mfg in allowed_mfgs)
                for oui_key, allowed_mfgs in _KNOWN_OUI_VENDOR_PAIRS.items()
            )
            if not is_known_pair and oui_norm not in mfg_norm and mfg_norm not in oui_norm:
                rl_key = f"oui_mismatch:{device.mac}"
                if self._rate_limit_ok(rl_key) and not self.is_suppressed(device.mac, device.ip_v4, "oui_mismatch"):
                    id_parts = [device.mac]
                    if device.ip_v4:
                        id_parts.append(device.ip_v4)
                    if device.hostname:
                        id_parts.append(f"({device.hostname})")
                    host_label = " ".join(id_parts)
                    findings.append(Alert(
                        device_mac=device.mac,
                        alert_type=AlertType.SPOOFING,
                        severity=AlertSeverity.WARNING,
                        message=(
                            f"OUI mismatch on {host_label}: NIC vendor "
                            f"'{oui_vendor}' but identified as '{device.manufacturer}'"
                        ),
                    ))

        # --- Check 7: Explicit MAC spoofing detection ---
        # If a non-randomized MAC has BOTH OUI mismatch AND fingerprint drift,
        # or if the OUI vendor changed entirely (device swap behind same MAC),
        # flag as MAC spoofing — a stronger, dedicated alert.
        if not device.is_randomized_mac and prior_snapshots:
            prev = prior_snapshots[0]
            oui_changed = (
                oui_vendor
                and prev.get("oui_vendor")
                and oui_vendor.lower() != prev["oui_vendor"].lower()
            )
            identity_changed = (
                prev.get("manufacturer")
                and device.manufacturer
                and prev["manufacturer"].lower() != device.manufacturer.lower()
                and prev.get("os_family")
                and device.os_family
                and prev["os_family"].lower() != device.os_family.lower()
            )

            if oui_changed or identity_changed:
                rl_key = f"mac_spoofing:{device.mac}"
                if self._rate_limit_ok(rl_key) and not self.is_suppressed(device.mac, device.ip_v4, "mac_spoofing"):
                    id_parts = [device.mac]
                    if device.ip_v4:
                        id_parts.append(device.ip_v4)
                    if device.hostname:
                        id_parts.append(f"({device.hostname})")
                    host_label = " ".join(id_parts)

                    if oui_changed:
                        detail = f"OUI vendor changed from '{prev['oui_vendor']}' to '{oui_vendor}'"
                    else:
                        detail = (
                            f"Identity changed from {prev['manufacturer']}/{prev['os_family']} "
                            f"to {device.manufacturer}/{device.os_family}"
                        )

                    findings.append(Alert(
                        device_mac=device.mac,
                        alert_type=AlertType.MAC_SPOOFING,
                        severity=AlertSeverity.HIGH,
                        message=(
                            f"Possible MAC spoofing on {host_label}: {detail}. "
                            f"A different device may be using this MAC address."
                        ),
                    ))

        # Persist snapshot
        if snapshot_writer:
            await snapshot_writer(
                hw_addr=device.mac,
                os_family=device.os_family,
                manufacturer=device.manufacturer,
                device_type=device.device_type,
                hostname=device.hostname,
                oui_vendor=oui_vendor,
            )
        else:
            await self._db.add_fingerprint_snapshot(
                mac=device.mac,
                os_family=device.os_family,
                manufacturer=device.manufacturer,
                device_type=device.device_type,
                hostname=device.hostname,
                oui_vendor=oui_vendor,
            )

        return findings

    # ------------------------------------------------------------------
    # Gateway learning
    # ------------------------------------------------------------------

    async def learn_gateway(
        self,
        mac: str,
        ip: str,
        source: str,
        interface: str,
    ) -> None:
        """Record a gateway binding unless a manual pin already exists."""
        current = await self._db.get_trusted_binding_for_ip(ip)
        if current and current["source"] == "manual":
            _log.debug(
                "Skipping auto-learn for %s -- manual pin exists (%s)",
                ip, current["mac"],
            )
            return

        await self._db.add_trusted_binding(mac, ip, source, interface)
        self._addr_associations[ip] = mac
        _log.info("Auto-learned gateway: %s -> %s (%s)", ip, mac, source)


# ---------------------------------------------------------------------------
# Backward-compatibility alias so existing imports keep working
# ---------------------------------------------------------------------------
SpoofingDetector = AddressVerifier
