"""Capture-start should check privileges BEFORE building an app.

User reported a stray "sensor listener disabled" log line landing on top
of the interactive REPL prompt. Root cause: selecting an interface without
capture privileges built a full LeethaApp (drain thread + async sensor
listener) and then immediately tore it down to re-exec under sudo. The
throwaway listener emitted a spurious log line from a background task.

Fix: check has_capture_privilege() first and re-exec under sudo directly,
without constructing a throwaway app.
"""

from __future__ import annotations

import pytest

from leetha.console import LeethaConsole
from leetha.capture.interfaces import InterfaceConfig


async def test_ensure_capture_reexecs_without_building_app_when_unprivileged(monkeypatch):
    console = LeethaConsole(interfaces=[InterfaceConfig(name="eth0")])
    assert console.app is None

    monkeypatch.setattr("leetha.platform.has_capture_privilege", lambda: False)

    reexec_called: list[bool] = []
    monkeypatch.setattr(
        console, "_reexec_under_sudo", lambda: reexec_called.append(True)
    )

    # Building an app here would be the bug — fail loudly if it happens.
    def _boom(*a, **k):
        raise AssertionError("LeethaApp must not be built when unprivileged")

    monkeypatch.setattr("leetha.console.LeethaApp", _boom)

    result = await console._ensure_capture()

    assert result is False
    assert reexec_called == [True]
    assert console.app is None  # no throwaway app left behind


def test_reexec_under_sudo_preserves_interfaces(monkeypatch):
    console = LeethaConsole(
        interfaces=[InterfaceConfig(name="eth0"), InterfaceConfig(name="wlan0")]
    )

    captured: dict = {}

    def _fake_execvp(file, args):
        captured["file"] = file
        captured["args"] = args

    monkeypatch.setattr("os.execvp", _fake_execvp)

    console._reexec_under_sudo()

    assert captured["file"] == "sudo"
    # Each selected interface is passed through as a -i flag.
    assert captured["args"].count("-i") == 2
    assert "eth0" in captured["args"]
    assert "wlan0" in captured["args"]
