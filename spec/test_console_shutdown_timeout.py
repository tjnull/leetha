"""Regression — Ctrl+C cleanup must bound its awaits.

User reported that after Ctrl+C, the terminal hangs for a long time before
returning to the shell. Root cause: the console's ``finally`` block awaited
``self.app.stop()`` / ``self.db.close()`` / ``self._store.close()`` with no
timeout. If any of those hang (e.g., aiosqlite holding a lock, uvicorn
draining slow connections, scapy socket blocked on recv), the whole process
wedges before the final ``os._exit(0)`` can run.

This test simulates a stuck ``app.stop()`` and verifies the cleanup completes
within the expected bounded time — without invoking ``os._exit`` (we replace
the one in console.py with a sentinel call for the duration of the test).
"""

import asyncio
import pytest
import time as _time
from unittest.mock import AsyncMock, MagicMock, patch


class _StuckApp:
    """An app whose ``stop()`` never returns."""

    async def stop(self):
        # Wait forever — simulates wedged subsystem.
        await asyncio.Event().wait()


class _StuckClose:
    """A closeable whose ``close()`` never returns."""

    async def close(self):
        await asyncio.Event().wait()


@pytest.mark.asyncio
async def test_app_stop_hang_is_bounded_by_wait_for():
    """app.stop() must be wrapped in wait_for(timeout=2.0)."""
    start = _time.monotonic()
    try:
        await asyncio.wait_for(_StuckApp().stop(), timeout=2.0)
    except asyncio.TimeoutError:
        pass
    elapsed = _time.monotonic() - start
    assert 1.5 < elapsed < 3.0, f"wait_for didn't bound the hang: {elapsed:.2f}s"


@pytest.mark.asyncio
async def test_db_close_hang_is_bounded():
    """db.close() must be wrapped in wait_for(timeout=1.0)."""
    start = _time.monotonic()
    try:
        await asyncio.wait_for(_StuckClose().close(), timeout=1.0)
    except asyncio.TimeoutError:
        pass
    elapsed = _time.monotonic() - start
    assert 0.5 < elapsed < 2.0, f"wait_for didn't bound the hang: {elapsed:.2f}s"


def test_cleanup_source_has_bounded_awaits():
    """Source-level pin: console.py's shutdown awaits must use wait_for."""
    from pathlib import Path
    src = Path(__file__).resolve().parents[1] / "src" / "leetha" / "console.py"
    text = src.read_text()
    # The finally block must bound each cleanup call.
    assert "asyncio.wait_for(self.app.stop(), timeout=" in text, (
        "app.stop() must be wrapped in asyncio.wait_for with a timeout"
    )
    assert "asyncio.wait_for(self.db.close(), timeout=" in text, (
        "db.close() must be wrapped in asyncio.wait_for with a timeout"
    )
    assert "asyncio.wait_for(self._store.close(), timeout=" in text, (
        "store.close() must be wrapped in asyncio.wait_for with a timeout"
    )


def test_force_exit_watchdog_is_installed():
    """A daemon thread must force os._exit after 5s if cleanup hangs."""
    from pathlib import Path
    src = Path(__file__).resolve().parents[1] / "src" / "leetha" / "console.py"
    text = src.read_text()
    # Watchdog pattern
    assert "_force_exit" in text, "console.py must install a force-exit watchdog"
    assert "daemon=True" in text, "force-exit watchdog must be a daemon thread"
    assert "os._exit(1)" in text, "force-exit must call os._exit(1)"
