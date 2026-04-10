import pytest
from pathlib import Path
from leetha.capture.remote.ca import (
    init_ca,
    issue_cert,
    revoke_cert,
    list_certs,
    load_ca,
    CANotInitialized,
)


@pytest.fixture
def ca_dir(tmp_path):
    return tmp_path / "ca"


def test_init_ca_creates_files(ca_dir):
    init_ca(ca_dir)
    assert (ca_dir / "ca.crt").exists()
    assert (ca_dir / "ca.key").exists()
    assert (ca_dir / "certs.json").exists()


def test_init_ca_twice_raises(ca_dir):
    init_ca(ca_dir)
    with pytest.raises(FileExistsError):
        init_ca(ca_dir)


def test_load_ca_without_init_raises(ca_dir):
    with pytest.raises(CANotInitialized):
        load_ca(ca_dir)


def test_issue_cert(ca_dir):
    init_ca(ca_dir)
    cert_path, key_path = issue_cert(ca_dir, "test-sensor", ca_dir / "out")
    assert cert_path.exists()
    assert key_path.exists()
    assert cert_path.name == "test-sensor.crt"
    assert key_path.name == "test-sensor.key"


def test_issue_duplicate_name_raises(ca_dir):
    init_ca(ca_dir)
    issue_cert(ca_dir, "sensor-a", ca_dir / "out")
    with pytest.raises(ValueError, match="already exists"):
        issue_cert(ca_dir, "sensor-a", ca_dir / "out")


def test_list_certs_empty(ca_dir):
    init_ca(ca_dir)
    certs = list_certs(ca_dir)
    assert certs == []


def test_list_certs_after_issue(ca_dir):
    init_ca(ca_dir)
    issue_cert(ca_dir, "pi-sensor", ca_dir / "out")
    certs = list_certs(ca_dir)
    assert len(certs) == 1
    assert certs[0]["name"] == "pi-sensor"
    assert certs[0]["revoked"] is False


def test_revoke_cert(ca_dir):
    init_ca(ca_dir)
    issue_cert(ca_dir, "bad-sensor", ca_dir / "out")
    revoke_cert(ca_dir, "bad-sensor")
    certs = list_certs(ca_dir)
    assert certs[0]["revoked"] is True


def test_revoke_nonexistent_raises(ca_dir):
    init_ca(ca_dir)
    with pytest.raises(ValueError, match="not found"):
        revoke_cert(ca_dir, "ghost")
