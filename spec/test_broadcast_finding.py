"""Test that _broadcast_finding pushes finding_created events."""
import asyncio
from unittest.mock import MagicMock
from datetime import datetime

from leetha.app import LeethaApp
from leetha.store.models import Finding, FindingRule, AlertSeverity


def test_broadcast_finding_pushes_to_subscribers():
    """_broadcast_finding must push a finding_created event to all subscribers."""
    app = object.__new__(LeethaApp)
    q = asyncio.Queue(maxsize=10)
    app.event_subscribers = [q]

    finding = Finding(
        hw_addr="aa:bb:cc:dd:ee:ff",
        rule=FindingRule.DHCP_ANOMALY,
        severity=AlertSeverity.WARNING,
        message="Test anomaly detected",
        timestamp=datetime(2026, 4, 5, 12, 0, 0),
    )
    app._broadcast_finding(finding)

    assert not q.empty()
    event = q.get_nowait()
    assert event["type"] == "finding_created"
    assert event["finding"]["hw_addr"] == "aa:bb:cc:dd:ee:ff"
    assert event["finding"]["rule"] == "dhcp_anomaly"
    assert event["finding"]["severity"] == "warning"
    assert event["finding"]["message"] == "Test anomaly detected"
    assert event["finding"]["timestamp"] is not None


def test_broadcast_finding_handles_full_queue():
    """_broadcast_finding must not raise when subscriber queue is full."""
    app = object.__new__(LeethaApp)
    q = asyncio.Queue(maxsize=1)
    q.put_nowait({"type": "old_event"})  # Fill the queue
    app.event_subscribers = [q]

    finding = Finding(
        hw_addr="11:22:33:44:55:66",
        rule=FindingRule.IDENTITY_SHIFT,
        severity=AlertSeverity.HIGH,
        message="Identity shift",
    )
    # Should not raise
    app._broadcast_finding(finding)
    # Queue should have the new event (old one dropped)
    event = q.get_nowait()
    assert event["type"] == "finding_created"
