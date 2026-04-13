"""Discovery-related finding rules."""
from __future__ import annotations
from datetime import datetime, timedelta
from leetha.rules.registry import register_rule
from leetha.rules.base import FindingRule as RuleBase
from leetha.store.models import Host, Finding, FindingRule, AlertSeverity
from leetha.evidence.models import Verdict

_LOW_CERT_LAST_FIRED: dict[str, datetime] = {}
_LOW_CERT_COOLDOWN = timedelta(hours=1)

@register_rule("new_host")
class NewHostRule(RuleBase):
    severity = "info"

    async def evaluate(self, host: Host, verdict: Verdict, store) -> Finding | None:
        # Only fire on truly new hosts (disposition still "new").
        # The pipeline transitions disposition to "known" after rules run,
        # so this will only fire once per host.
        if host.disposition == "new":
            parts = [f"New host discovered: {host.hw_addr}"]
            if verdict.vendor:
                parts.append(verdict.vendor)
            if verdict.category:
                parts.append(verdict.category)
            if host.ip_addr:
                parts.append(host.ip_addr)
            if host.mac_randomized:
                parts.append("randomized MAC")
            return Finding(
                hw_addr=host.hw_addr,
                rule=FindingRule.NEW_HOST,
                severity=AlertSeverity.INFO,
                message=" — ".join(parts),
            )
        return None

@register_rule("low_certainty")
class LowCertaintyRule(RuleBase):
    severity = "low"

    async def evaluate(self, host: Host, verdict: Verdict, store) -> Finding | None:
        if verdict.certainty < 50 and host.disposition == "known":
            hw_addr = host.hw_addr
            # In-memory cooldown: don't fire more than once per hour
            last = _LOW_CERT_LAST_FIRED.get(hw_addr)
            if last and (datetime.now() - last) < _LOW_CERT_COOLDOWN:
                return None
            # DB dedup: skip if an unresolved finding already exists
            cursor = await store.connection.execute(
                "SELECT COUNT(*) FROM findings WHERE hw_addr = ? AND rule = ? AND resolved = 0",
                (hw_addr, "low_certainty"),
            )
            if (await cursor.fetchone())[0] > 0:
                return None
            _LOW_CERT_LAST_FIRED[hw_addr] = datetime.now()
            return Finding(
                hw_addr=hw_addr,
                rule=FindingRule.LOW_CERTAINTY,
                severity=AlertSeverity.LOW,
                message=f"Host {hw_addr} has low identification certainty ({verdict.certainty}%)",
            )
        return None
