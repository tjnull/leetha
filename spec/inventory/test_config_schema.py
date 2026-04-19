"""Phase A.3 — ConfigField schema validation."""

import pytest

from leetha.inventory.config_schema import ConfigField, validate


def test_missing_required_raises():
    schema = [ConfigField(name="path", type="string", required=True)]
    with pytest.raises(ValueError):
        validate(schema, {})


def test_missing_optional_is_ok():
    schema = [ConfigField(name="path", type="string")]
    validate(schema, {})  # no raise


def test_wrong_type_raises():
    schema = [ConfigField(name="interval", type="int")]
    with pytest.raises(ValueError):
        validate(schema, {"interval": "not-an-int"})


def test_bool_is_not_int():
    schema = [ConfigField(name="interval", type="int")]
    with pytest.raises(ValueError):
        validate(schema, {"interval": True})


def test_valid_int_passes():
    schema = [ConfigField(name="interval", type="int")]
    validate(schema, {"interval": 60})


def test_select_must_match_choices():
    schema = [ConfigField(
        name="flavor", type="select", choices=["isc", "dnsmasq"],
    )]
    with pytest.raises(ValueError):
        validate(schema, {"flavor": "kea"})


def test_select_accepts_valid_choice():
    schema = [ConfigField(
        name="flavor", type="select", choices=["isc", "dnsmasq"],
    )]
    validate(schema, {"flavor": "isc"})


def test_custom_validator_runs():
    def _positive(v):
        if v <= 0:
            raise ValueError("must be positive")

    schema = [ConfigField(name="count", type="int", validator=_positive)]
    with pytest.raises(ValueError, match="must be positive"):
        validate(schema, {"count": 0})


def test_secret_is_string_typed():
    schema = [ConfigField(name="token", type="secret", required=True)]
    validate(schema, {"token": "hunter2"})  # no raise
    with pytest.raises(ValueError):
        validate(schema, {"token": 42})
