"""Tests for the watched-ports registry used by passive banner capture."""

import pytest

from leetha.capture.banner.ports import (
    WATCHED_PORTS,
    bpf_fragment,
    service_for_port,
)


# --- service_for_port ---


@pytest.mark.parametrize(
    "port, expected",
    [
        (22, "SSH"),
        (21, "FTP"),
        (23, "Telnet"),
        (25, "SMTP"),
        (465, "SMTP"),
        (587, "SMTP"),
        (110, "POP3"),
        (995, "POP3"),
        (143, "IMAP"),
        (993, "IMAP"),
        (5900, "VNC"),
        (5903, "VNC"),
        (6667, "IRC"),
        (6697, "IRC"),
        (3306, "MySQL"),
        (5432, "PostgreSQL"),
        (1433, "MSSQL"),
        (27017, "MongoDB"),
        (6379, "Redis"),
        (445, "SMB"),
        (139, "SMB"),
        (3389, "RDP"),
        (631, "IPP"),
        (9100, "JetDirect"),
        (515, "LPD"),
    ],
)
def test_known_ports_return_correct_service(port: int, expected: str) -> None:
    assert service_for_port(port) == expected


def test_unknown_port_returns_none() -> None:
    assert service_for_port(12345) is None
    assert service_for_port(0) is None
    assert service_for_port(99999) is None


# --- WATCHED_PORTS validity ---


def test_all_ports_are_valid_integers() -> None:
    for port in WATCHED_PORTS:
        assert isinstance(port, int), f"Port {port!r} is not an int"
        assert 1 <= port <= 65535, f"Port {port} out of valid range"


# --- bpf_fragment ---


def test_bpf_fragment_contains_key_ports() -> None:
    frag = bpf_fragment()
    for port in (22, 21, 3306, 445, 3389, 631):
        assert f"tcp port {port}" in frag


def test_bpf_fragment_parts_joined_with_or() -> None:
    frag = bpf_fragment()
    parts = frag.split(" or ")
    assert len(parts) == len(WATCHED_PORTS)
    for part in parts:
        assert part.startswith("tcp port ")
