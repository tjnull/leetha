"""Tests for notification dispatcher."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from leetha.store.models import Finding, FindingRule, AlertSeverity


@pytest.fixture
def finding():
    return Finding(
        hw_addr="aa:bb:cc:dd:ee:ff",
        rule=FindingRule.NEW_HOST,
        severity=AlertSeverity.WARNING,
        message="New device detected on network",
    )


async def test_notify_skips_below_min_severity(finding):
    """Notifications below min severity are silently skipped."""
    from leetha.notifications import NotificationDispatcher
    d = NotificationDispatcher(urls=["json://localhost"], min_severity="high")
    mock_notify = AsyncMock(return_value=True)
    class FakeApprise:
        async_notify = mock_notify
    d._apprise = FakeApprise()
    await d.send(finding)
    mock_notify.assert_not_called()


async def test_notify_sends_above_min_severity(finding):
    """Findings at or above min severity trigger notification."""
    from leetha.notifications import NotificationDispatcher

    # Create dispatcher, then replace the internal apprise with a mock
    d = NotificationDispatcher(urls=["json://localhost"], min_severity="warning")
    mock_notify = AsyncMock(return_value=True)
    # Use a simple object with async_notify to avoid MagicMock attr interference
    class FakeApprise:
        async_notify = mock_notify
    d._apprise = FakeApprise()
    await d.send(finding)
    mock_notify.assert_called_once()


async def test_notify_skips_when_no_urls():
    """No URLs configured = no notification, no error."""
    from leetha.notifications import NotificationDispatcher
    d = NotificationDispatcher(urls=[], min_severity="info")
    finding = Finding(
        hw_addr="aa:bb:cc:dd:ee:ff",
        rule=FindingRule.NEW_HOST,
        severity=AlertSeverity.CRITICAL,
        message="test",
    )
    await d.send(finding)


async def test_notify_rate_limits(finding):
    """Same rule+MAC within cooldown window is suppressed."""
    from leetha.notifications import NotificationDispatcher
    d = NotificationDispatcher(urls=["json://localhost"], min_severity="info")
    mock_notify = AsyncMock(return_value=True)
    class FakeApprise:
        async_notify = mock_notify
    d._apprise = FakeApprise()
    await d.send(finding)
    await d.send(finding)  # duplicate within cooldown
    assert mock_notify.call_count == 1


async def test_format_message(finding):
    """Message includes severity, rule, MAC, and message."""
    from leetha.notifications import NotificationDispatcher
    d = NotificationDispatcher(urls=[], min_severity="info")
    title, body = d.format(finding)
    assert "WARNING" in title
    assert "aa:bb:cc:dd:ee:ff" in body
    assert "new_host" in body
