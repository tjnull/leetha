"""Regression — Phase A authorization endpoints are admin-only.

Live probe caught analyst tokens able to hit ``POST /api/baseline/set`` and
individual approve/reject/revoke. Device authorization is a security decision;
delegating it to analyst tokens is a real privilege-escalation bug.
"""

from leetha.auth.roles import requires_admin


def test_baseline_set_is_admin_only():
    assert requires_admin("POST", "/api/baseline/set") is True


def test_baseline_reset_is_admin_only():
    assert requires_admin("POST", "/api/baseline/reset") is True


def test_bulk_authorization_is_admin_only():
    assert requires_admin("POST", "/api/devices/bulk/authorization") is True


def test_approve_is_admin_only():
    assert requires_admin("POST", "/api/devices/aa:bb:cc:dd:ee:01/approve") is True


def test_reject_is_admin_only():
    assert requires_admin("POST", "/api/devices/aa:bb:cc:dd:ee:01/reject") is True


def test_revoke_is_admin_only():
    assert requires_admin("POST", "/api/devices/aa:bb:cc:dd:ee:01/revoke") is True


def test_baseline_status_is_not_admin_only():
    """Reading status is fine for analysts."""
    assert requires_admin("GET", "/api/baseline/status") is False


def test_patch_custom_props_is_not_admin_only():
    """Analysts can annotate devices (owner, location, notes, tags, criticality,
    presence threshold) — this is curation, not auth."""
    assert requires_admin("PATCH", "/api/devices/aa:bb:cc:dd:ee:01") is False


def test_get_authorization_history_is_not_admin_only():
    """Reading the audit trail is fine for analysts."""
    assert requires_admin(
        "GET", "/api/devices/aa:bb:cc:dd:ee:01/authorization/history"
    ) is False


def test_existing_bulk_disposition_still_admin_by_path_convention():
    """The pre-existing /api/devices/bulk (mark_known/mark_suspicious) was never
    declared admin-only and this fix doesn't upgrade it; verify we didn't
    accidentally block it either."""
    # The old bulk route has no /approve|/reject|/revoke suffix, so analysts
    # can still hit it (unchanged behavior).
    assert requires_admin("POST", "/api/devices/bulk") is False


def test_inventory_upload_is_admin_only():
    """DHCP lease uploads flood the device inventory — admin-only."""
    assert requires_admin("POST", "/api/inventory/dhcp-leases/upload") is True


def test_future_inventory_sources_also_admin():
    """The prefix covers any future importer under /api/inventory/."""
    assert requires_admin("POST", "/api/inventory/unifi/sync") is True
    assert requires_admin("POST", "/api/inventory/pihole/upload") is True


def test_authorization_suffix_match_is_precise():
    """Suffix matching must not over-match random /approve substrings."""
    # Path with /approve in the middle, not at the end — should NOT be admin.
    assert requires_admin(
        "POST", "/api/devices/aa:bb:cc:dd:ee:01/approve-pending/extra"
    ) is False
    # But actual approve IS admin.
    assert requires_admin("POST", "/api/devices/anything/approve") is True
