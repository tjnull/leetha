"""Discovery-related finding rules."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from leetha.rules.registry import register_rule
from leetha.rules.base import FindingRule as RuleBase
from leetha.store.models import Host, Finding, FindingRule, AlertSeverity
from leetha.evidence.models import Verdict

_LOW_CERT_LAST_FIRED: dict[str, datetime] = {}
_LOW_CERT_COOLDOWN = timedelta(hours=1)

_AUTH_SEVERITY = {
    "approved": AlertSeverity.INFO,
    "unapproved": AlertSeverity.WARNING,
    "rejected": AlertSeverity.CRITICAL,
}


async def _device_authorization(store, mac: str) -> str:
    """Look up a device's authorization state. Default: 'unapproved'."""
    try:
        cursor = await store.connection.execute(
            "SELECT authorization FROM devices WHERE mac = ?", (mac,),
        )
        row = await cursor.fetchone()
    except Exception:
        return "unapproved"
    if row is None or row[0] is None:
        return "unapproved"
    return row[0]


async def _device_passively_observed(store, mac: str) -> bool:
    """True if the device has been observed in live capture (or row missing)."""
    try:
        cursor = await store.connection.execute(
            "SELECT passively_observed FROM devices WHERE mac = ?", (mac,),
        )
        row = await cursor.fetchone()
    except Exception:
        return True
    if row is None or row[0] is None:
        return True
    return bool(row[0])


async def _baseline_established(store) -> bool:
    """True once the operator has curated the inventory at all.

    Until at least one device has been explicitly approved or rejected,
    *every* device is 'unapproved' simply because no baseline exists yet —
    so a new unapproved device is just inventory (INFO), not a WARNING.
    Once the operator has started approving/rejecting, a newly-appearing
    unapproved device is genuinely noteworthy.
    """
    try:
        cursor = await store.connection.execute(
            "SELECT 1 FROM devices WHERE authorization IN ('approved','rejected') LIMIT 1",
        )
        return (await cursor.fetchone()) is not None
    except Exception:
        return False


@register_rule("new_host")
class NewHostRule(RuleBase):
    severity = "info"  # graded dynamically; retained for registry-level defaults

    async def evaluate(self, host: Host, verdict: Verdict, store) -> Finding | None:
        # Only fire on truly new hosts (disposition still "new").
        # The pipeline transitions disposition to "known" after rules run,
        # so this will only fire once per host.
        if host.disposition == "new":
            # Suppress new_host while the device is importer-sourced but not
            # yet seen in live capture: an imported row on its own shouldn't
            # trip alerts.
            if not await _device_passively_observed(store, host.hw_addr):
                return None
            auth = await _device_authorization(store, host.hw_addr)
            sev = _AUTH_SEVERITY.get(auth, AlertSeverity.WARNING)
            # Pre-baseline, an unapproved device is just inventory: don't
            # raise a WARNING for every device on first deployment. Rejected
            # devices stay CRITICAL regardless (explicit operator signal).
            if auth == "unapproved" and not await _baseline_established(store):
                sev = AlertSeverity.INFO
            parts = [f"New host discovered: {host.hw_addr}"]
            if verdict.vendor:
                parts.append(verdict.vendor)
            if verdict.category:
                parts.append(verdict.category)
            if host.ip_addr:
                parts.append(host.ip_addr)
            if host.mac_randomized:
                parts.append("randomized MAC")
            if auth != "approved":
                parts.append(f"authorization: {auth}")
            return Finding(
                hw_addr=host.hw_addr,
                rule=FindingRule.NEW_HOST,
                severity=sev,
                message=" — ".join(parts),
            )
        return None

@register_rule("low_certainty")
class LowCertaintyRule(RuleBase):
    severity = "low"

    async def evaluate(self, host: Host, verdict: Verdict, store) -> Finding | None:
        if verdict.certainty < 50 and host.disposition in ("known", "new"):
            hw_addr = host.hw_addr
            # In-memory cooldown: don't fire more than once per hour
            last = _LOW_CERT_LAST_FIRED.get(hw_addr)
            if last and (datetime.now(timezone.utc) - last) < _LOW_CERT_COOLDOWN:
                return None
            # DB dedup: skip if an unresolved finding already exists
            cursor = await store.connection.execute(
                "SELECT COUNT(*) FROM findings WHERE hw_addr = ? AND rule = ? AND resolved = 0",
                (hw_addr, "low_certainty"),
            )
            if (await cursor.fetchone())[0] > 0:
                return None
            _LOW_CERT_LAST_FIRED[hw_addr] = datetime.now(timezone.utc)
            return Finding(
                hw_addr=hw_addr,
                rule=FindingRule.LOW_CERTAINTY,
                severity=AlertSeverity.LOW,
                message=f"Host {hw_addr} has low identification certainty ({verdict.certainty}%)",
            )
        return None
