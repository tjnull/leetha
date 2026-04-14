"""Notification dispatcher — sends alerts via Apprise."""
from __future__ import annotations

import logging
import time

import apprise

from leetha.store.models import Finding

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"info": 0, "low": 1, "warning": 2, "high": 3, "critical": 4}
_COOLDOWN_SECONDS = 300  # 5 minutes per rule+MAC


class NotificationDispatcher:
    """Sends finding alerts to configured Apprise URLs."""

    def __init__(self, urls: list[str], min_severity: str = "warning"):
        self._urls = urls
        self._min_level = _SEVERITY_ORDER.get(min_severity, 2)
        self._recent: dict[str, float] = {}  # "rule:mac" -> last_sent timestamp
        # Build the Apprise instance once at construction
        self._apprise = apprise.Apprise()
        for url in urls:
            self._apprise.add(url)

    def update_urls(self, urls: list[str]) -> None:
        """Replace notification URLs and rebuild the Apprise instance."""
        self._urls = urls
        self._apprise = apprise.Apprise()
        for url in urls:
            self._apprise.add(url)

    def format(self, finding: Finding) -> tuple[str, str]:
        """Return (title, body) for a finding notification."""
        sev = finding.severity.value.upper() if hasattr(finding.severity, "value") else str(finding.severity).upper()
        rule = finding.rule.value if hasattr(finding.rule, "value") else str(finding.rule)
        title = f"[LEETHA] {sev}: {finding.message}"
        body = (
            f"MAC: {finding.hw_addr}\n"
            f"Rule: {rule}\n"
            f"Severity: {sev}"
        )
        return title, body

    async def send(self, finding: Finding) -> None:
        """Dispatch a notification if severity meets threshold and not rate-limited."""
        if not self._urls:
            return

        sev_str = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        level = _SEVERITY_ORDER.get(sev_str, 0)
        if level < self._min_level:
            return

        # Rate limit: one notification per rule+MAC per cooldown window
        rule_str = finding.rule.value if hasattr(finding.rule, "value") else str(finding.rule)
        dedup_key = f"{rule_str}:{finding.hw_addr}"
        now = time.monotonic()

        # Prune stale entries to prevent unbounded growth
        stale = [k for k, v in self._recent.items() if now - v > _COOLDOWN_SECONDS]
        for k in stale:
            del self._recent[k]

        last = self._recent.get(dedup_key)
        if last is not None and (now - last) < _COOLDOWN_SECONDS:
            return
        self._recent[dedup_key] = now

        title, body = self.format(finding)
        try:
            await self._apprise.async_notify(title=title, body=body)
        except Exception:
            logger.debug("Notification dispatch failed", exc_info=True)
