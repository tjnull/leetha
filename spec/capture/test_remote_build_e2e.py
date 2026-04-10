"""End-to-end test for sensor build pipeline.

Tests the full flow: cert generation -> embedded.rs generation ->
verify generated source is correct. Does NOT compile (no Rust in CI).
"""
import pytest
import shutil
from pathlib import Path
from leetha.capture.remote.ca import init_ca, issue_cert
from leetha.capture.remote.build import (
    generate_embedded_rs,
    BuildRequest,
    TARGET_MAP,
)


@pytest.fixture
def ca_dir(tmp_path):
    ca = tmp_path / "ca"
    init_ca(ca)
    return ca


def test_full_embedded_rs_generation(ca_dir, tmp_path):
    """Generate certs and embedded.rs, verify all pieces are correct."""
    build_dir = tmp_path / "build"
    build_dir.mkdir()

    # Issue cert
    cert_path, key_path = issue_cert(ca_dir, "e2e-sensor", build_dir)
    assert cert_path.exists()
    assert key_path.exists()

    # Copy CA cert
    shutil.copy2(ca_dir / "ca.crt", build_dir / "ca.crt")

    # Generate embedded.rs
    rs = generate_embedded_rs(
        name="e2e-sensor",
        server="192.168.1.100:8443",
        interface="br-lan",
        buffer_mb=10,
        ca_path="../build/ca.crt",
        cert_path="../build/e2e-sensor.crt",
        key_path="../build/e2e-sensor.key",
    )

    # Verify content
    assert 'SENSOR_NAME: &str = "e2e-sensor"' in rs
    assert 'SERVER_ADDR: &str = "192.168.1.100:8443"' in rs
    assert 'INTERFACE: &str = "br-lan"' in rs
    assert "BUFFER_SIZE_MB: usize = 10" in rs
    assert "include_bytes!" in rs

    # Write it and verify it's valid Rust syntax (basic check)
    rs_path = tmp_path / "embedded.rs"
    rs_path.write_text(rs)
    content = rs_path.read_text()
    assert content.count("pub const") == 7


def test_all_targets_have_consistent_fields():
    """Verify TARGET_MAP integrity."""
    for target_id, info in TARGET_MAP.items():
        assert "triple" in info, f"{target_id} missing triple"
        assert "default_buffer_mb" in info, f"{target_id} missing default_buffer_mb"
        assert "binary_name" in info, f"{target_id} missing binary_name"
        assert info["default_buffer_mb"] > 0
        assert info["binary_name"].startswith("leetha-sensor")


def test_build_request_all_targets():
    """Verify BuildRequest accepts all valid targets."""
    for target_id in TARGET_MAP:
        req = BuildRequest(
            name="test",
            server="1.2.3.4:8443",
            interface="eth0",
            target=target_id,
            buffer_size_mb=TARGET_MAP[target_id]["default_buffer_mb"],
        )
        assert req.target == target_id
