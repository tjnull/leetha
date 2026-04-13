"""Tests for extended finding model with status, disposition, snooze, notes."""
import pytest
from datetime import datetime, timedelta
from leetha.store.models import Finding, FindingRule, AlertSeverity


def test_finding_has_status_field():
    f = Finding(hw_addr="aa:bb:cc:dd:ee:ff", rule=FindingRule.NEW_HOST,
                severity=AlertSeverity.INFO, message="Test")
    assert f.status == "new"


def test_finding_has_disposition_field():
    f = Finding(hw_addr="aa:bb:cc:dd:ee:ff", rule=FindingRule.NEW_HOST,
                severity=AlertSeverity.INFO, message="Test")
    assert f.disposition is None


def test_finding_has_snoozed_until_field():
    f = Finding(hw_addr="aa:bb:cc:dd:ee:ff", rule=FindingRule.NEW_HOST,
                severity=AlertSeverity.INFO, message="Test")
    assert f.snoozed_until is None


def test_finding_has_notes_field():
    f = Finding(hw_addr="aa:bb:cc:dd:ee:ff", rule=FindingRule.NEW_HOST,
                severity=AlertSeverity.INFO, message="Test")
    assert f.notes is None
