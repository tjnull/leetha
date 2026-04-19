"""Phase A.2 — Device authorization fields + AuthorizationHistory model."""

from datetime import datetime, timezone
from leetha.store.models import Device, AuthorizationHistory


def test_device_default_authorization_is_unapproved():
    d = Device(mac="aa:bb:cc:dd:ee:ff")
    assert d.authorization == "unapproved"
    assert d.authorized_at is None
    assert d.authorized_by is None


def test_device_accepts_authorization_override():
    now = datetime.now(timezone.utc)
    d = Device(
        mac="aa:bb:cc:dd:ee:ff",
        authorization="approved",
        authorized_at=now,
        authorized_by="admin",
    )
    assert d.authorization == "approved"
    assert d.authorized_at == now
    assert d.authorized_by == "admin"


def test_authorization_history_dataclass():
    now = datetime.now(timezone.utc)
    h = AuthorizationHistory(
        mac="aa:bb:cc:dd:ee:ff",
        previous_state="unapproved",
        new_state="approved",
        actor="admin",
        reason="onboarding",
        timestamp=now,
    )
    assert h.mac == "aa:bb:cc:dd:ee:ff"
    assert h.previous_state == "unapproved"
    assert h.new_state == "approved"
    assert h.actor == "admin"
    assert h.id is None
