import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from leetha.capture.remote.build import (
    TARGET_MAP,
    generate_embedded_rs,
    check_prerequisites,
    BuildRequest,
)


def test_target_map_has_all_platforms():
    assert "linux-x86_64" in TARGET_MAP
    assert "linux-arm" in TARGET_MAP
    assert "linux-arm64" in TARGET_MAP
    assert "linux-mips" in TARGET_MAP
    assert "windows-x86_64" in TARGET_MAP


def test_target_map_triples():
    assert TARGET_MAP["linux-x86_64"]["triple"] == "x86_64-unknown-linux-musl"
    assert TARGET_MAP["linux-arm"]["triple"] == "armv7-unknown-linux-musleabihf"
    assert TARGET_MAP["linux-arm64"]["triple"] == "aarch64-unknown-linux-musl"
    assert TARGET_MAP["linux-mips"]["triple"] == "mips-unknown-linux-musl"
    assert TARGET_MAP["windows-x86_64"]["triple"] == "x86_64-pc-windows-gnu"


def test_target_map_default_buffers():
    assert TARGET_MAP["linux-x86_64"]["default_buffer_mb"] == 100
    assert TARGET_MAP["linux-arm"]["default_buffer_mb"] == 50
    assert TARGET_MAP["linux-arm64"]["default_buffer_mb"] == 100
    assert TARGET_MAP["linux-mips"]["default_buffer_mb"] == 10
    assert TARGET_MAP["windows-x86_64"]["default_buffer_mb"] == 50


def test_generate_embedded_rs():
    rs = generate_embedded_rs(
        name="test-sensor",
        server="10.0.0.1:8443",
        buffer_mb=25,
        ca_path="../build/ca.crt",
        cert_path="../build/client.crt",
        key_path="../build/client.key",
    )
    assert 'SENSOR_NAME: &str = "test-sensor"' in rs
    assert 'SERVER_ADDR: &str = "10.0.0.1:8443"' in rs
    assert "BUFFER_SIZE_MB: usize = 25" in rs
    assert 'include_bytes!("../build/ca.crt")' in rs
    assert 'include_bytes!("../build/client.crt")' in rs
    assert 'include_bytes!("../build/client.key")' in rs
    # Interface no longer embedded — sensor defaults to "any"
    assert "INTERFACE" not in rs


def test_generate_embedded_rs_escapes_quotes():
    rs = generate_embedded_rs(
        name='sensor"evil',
        server="10.0.0.1:8443",
        buffer_mb=100,
        ca_path="../build/ca.crt",
        cert_path="../build/client.crt",
        key_path="../build/client.key",
    )
    assert '\\"' in rs


def test_build_request_validation():
    req = BuildRequest(
        name="pi-sensor",
        server="10.0.0.5:8443",
        target="linux-arm64",
        buffer_size_mb=50,
    )
    assert req.name == "pi-sensor"
    assert req.target == "linux-arm64"


def test_build_request_invalid_target():
    with pytest.raises(ValueError, match="Unknown target"):
        BuildRequest(
            name="test",
            server="1.2.3.4:8443",
            target="freebsd-arm",
            buffer_size_mb=50,
        )


@patch("shutil.which")
def test_check_prerequisites_cargo_missing(mock_which):
    mock_which.return_value = None
    ok, msg = check_prerequisites("linux-x86_64")
    assert not ok
    assert "rust" in msg.lower() or "rustup" in msg.lower()


@patch("shutil.which")
def test_check_prerequisites_cross_missing_for_cross_target(mock_which):
    import platform

    def which_side_effect(name):
        if name in ("cargo", "rustc"):
            return f"/usr/bin/{name}"
        return None
    mock_which.side_effect = which_side_effect

    if platform.machine() == "x86_64":
        ok, msg = check_prerequisites("linux-arm64")
        assert not ok
        assert "cross" in msg.lower()
