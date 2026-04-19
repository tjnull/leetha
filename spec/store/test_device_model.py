"""Phase A.1 — Device dataclass custom-property fields."""

import json
from leetha.store.models import Device


def test_device_has_custom_prop_fields():
    d = Device(
        mac="aa:bb:cc:dd:ee:ff",
        owner="alice",
        location="room-101",
        criticality="high",
        tags=["production", "core"],
        notes="edge router",
    )
    assert d.owner == "alice"
    assert d.location == "room-101"
    assert d.criticality == "high"
    assert d.tags == ["production", "core"]
    assert d.notes == "edge router"


def test_device_defaults_for_custom_props():
    d = Device(mac="aa:bb:cc:dd:ee:ff")
    assert d.owner is None
    assert d.location is None
    assert d.criticality is None
    assert d.tags == []
    assert d.notes is None


def test_device_to_dict_encodes_tags_as_list():
    d = Device(mac="aa:bb:cc:dd:ee:ff", tags=["a", "b"])
    out = d.to_dict()
    assert out["tags"] == ["a", "b"]
    assert isinstance(out["tags"], list)


def test_device_to_dict_empty_tags_is_empty_list():
    d = Device(mac="aa:bb:cc:dd:ee:ff")
    out = d.to_dict()
    assert out["tags"] == []


def test_device_from_row_decodes_tags_from_json_string():
    row = {
        "mac": "aa:bb:cc:dd:ee:ff",
        "hostname": None, "manufacturer": None, "device_type": None,
        "os_family": None, "os_version": None, "ip_v4": None, "ip_v6": None,
        "confidence": 0, "alert_status": "new",
        "first_seen": None, "last_seen": None,
        "raw_evidence": "{}", "is_randomized_mac": 0, "correlated_mac": None,
        "identity_id": None, "manual_override": None,
        "owner": "alice", "location": "room-101", "criticality": "high",
        "tags": json.dumps(["prod", "core"]),
        "notes": "edge router",
    }
    d = Device.from_row(row)
    assert d.owner == "alice"
    assert d.location == "room-101"
    assert d.criticality == "high"
    assert d.tags == ["prod", "core"]
    assert d.notes == "edge router"


def test_device_from_row_null_tags_becomes_empty_list():
    row = {
        "mac": "aa:bb:cc:dd:ee:ff",
        "hostname": None, "manufacturer": None, "device_type": None,
        "os_family": None, "os_version": None, "ip_v4": None, "ip_v6": None,
        "confidence": 0, "alert_status": "new",
        "first_seen": None, "last_seen": None,
        "raw_evidence": "{}", "is_randomized_mac": 0, "correlated_mac": None,
        "identity_id": None, "manual_override": None,
        "owner": None, "location": None, "criticality": None,
        "tags": None, "notes": None,
    }
    d = Device.from_row(row)
    assert d.tags == []
    assert d.owner is None


def test_device_from_row_malformed_tags_json_becomes_empty_list():
    row = {
        "mac": "aa:bb:cc:dd:ee:ff",
        "hostname": None, "manufacturer": None, "device_type": None,
        "os_family": None, "os_version": None, "ip_v4": None, "ip_v6": None,
        "confidence": 0, "alert_status": "new",
        "first_seen": None, "last_seen": None,
        "raw_evidence": "{}", "is_randomized_mac": 0, "correlated_mac": None,
        "identity_id": None, "manual_override": None,
        "owner": None, "location": None, "criticality": None,
        "tags": "not-valid-json{",
        "notes": None,
    }
    d = Device.from_row(row)
    assert d.tags == []
