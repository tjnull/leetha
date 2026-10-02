"""Process-wide, event-loop-safe coordination of SQLite writes by database file."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path

_registry_lock = threading.Lock()
_locks: dict[Path, threading.Lock] = {}


class FileWriteLock:
    def __init__(self, lock: threading.Lock):
        self._lock = lock

    async def __aenter__(self):
        # A nonblocking attempt plus an asyncio pause keeps both the web loop
        # and packet worker responsive while another connection is writing.
        while not self._lock.acquire(blocking=False):
            await asyncio.sleep(0.01)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        self._lock.release()


def write_lock_for(path: str | Path) -> FileWriteLock:
    key = Path(path).resolve()
    with _registry_lock:
        lock = _locks.setdefault(key, threading.Lock())
    return FileWriteLock(lock)
