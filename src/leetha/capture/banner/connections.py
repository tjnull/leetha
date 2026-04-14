"""Lightweight connection table for TCP banner deduplication."""

from __future__ import annotations

import enum
import time
from collections import OrderedDict
from dataclasses import dataclass, field

# Key type: (src_ip, src_port, dst_ip, dst_port)
ConnKey = tuple[str, int, str, int]


class ConnState(enum.Enum):
    """Lifecycle states for a tracked TCP connection."""

    SYN_SEEN = "syn_seen"
    ESTABLISHED = "established"
    BANNER_CAPTURED = "banner_captured"
    CLOSED = "closed"


@dataclass
class ConnEntry:
    """Metadata for a single tracked connection."""

    state: ConnState = ConnState.SYN_SEEN
    server_port: int = 0
    first_seen: float = field(default_factory=time.monotonic)
    last_seen: float = field(default_factory=time.monotonic)
    client_bytes: int = 0

    def touch(self) -> None:
        """Update *last_seen* to the current monotonic time."""
        self.last_seen = time.monotonic()


class ConnectionTable:
    """FIFO-evicting table that maps TCP 5-tuples to connection metadata.

    Parameters
    ----------
    max_entries:
        Hard cap on tracked connections. When reached the oldest entry is
        evicted before a new one is inserted.
    ttl_seconds:
        Seconds of inactivity after which an entry is eligible for removal
        by :meth:`sweep`.
    """

    def __init__(self, max_entries: int = 10_000, ttl_seconds: float = 30.0) -> None:
        self._entries: OrderedDict[ConnKey, ConnEntry] = OrderedDict()
        self._max_entries = max_entries
        self._ttl_seconds = ttl_seconds

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_syn(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int
    ) -> ConnEntry:
        """Record a SYN for a new connection, evicting the oldest if full."""
        key: ConnKey = (src_ip, src_port, dst_ip, dst_port)

        # Don't overwrite existing entries
        if key in self._entries:
            return self._entries[key]

        # Evict oldest entry when at capacity.
        if len(self._entries) >= self._max_entries:
            self._entries.popitem(last=False)

        entry = ConnEntry(server_port=dst_port)
        self._entries[key] = entry
        # Move to end so newest entries are always at the tail.
        self._entries.move_to_end(key)
        return entry

    def lookup(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int
    ) -> ConnEntry | None:
        """Return the entry for a connection, or *None* if not tracked."""
        return self._entries.get((src_ip, src_port, dst_ip, dst_port))

    def mark_captured(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int
    ) -> None:
        """Transition a connection to BANNER_CAPTURED."""
        entry = self.lookup(src_ip, src_port, dst_ip, dst_port)
        if entry is not None:
            entry.state = ConnState.BANNER_CAPTURED
            entry.touch()

    def mark_closed(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int
    ) -> None:
        """Transition a connection to CLOSED."""
        entry = self.lookup(src_ip, src_port, dst_ip, dst_port)
        if entry is not None:
            entry.state = ConnState.CLOSED
            entry.touch()

    def is_captured(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int
    ) -> bool:
        """Return *True* if the connection has already captured a banner."""
        entry = self.lookup(src_ip, src_port, dst_ip, dst_port)
        return entry is not None and entry.state is ConnState.BANNER_CAPTURED

    def record_client_data(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, nbytes: int
    ) -> None:
        """Add *nbytes* to the client-data counter for the connection."""
        entry = self.lookup(src_ip, src_port, dst_ip, dst_port)
        if entry is not None:
            entry.client_bytes += nbytes
            entry.touch()

    def sweep(self) -> int:
        """Remove expired and CLOSED entries. Return count removed."""
        now = time.monotonic()
        to_remove: list[ConnKey] = []
        for key, entry in self._entries.items():
            expired = (now - entry.last_seen) > self._ttl_seconds
            if expired or entry.state is ConnState.CLOSED:
                to_remove.append(key)
        for key in to_remove:
            del self._entries[key]
        return len(to_remove)

    def __len__(self) -> int:
        return len(self._entries)
