"""TTL-based deduplication cache with LRU eviction.

Replaces the old set-based dedup that cleared entirely at 50K entries,
losing all state.  This implementation evicts oldest entries one at a
time and expires stale keys after a configurable TTL.
"""

from __future__ import annotations

import time
from collections import OrderedDict


class TTLDedup:
    """Deduplication filter backed by an OrderedDict for LRU ordering.

    Parameters
    ----------
    max_entries:
        Maximum number of keys to retain before evicting the oldest.
    ttl_seconds:
        How long (in seconds) a key is considered "recently seen".
    """

    def __init__(self, max_entries: int = 50_000, ttl_seconds: float = 300.0) -> None:
        self._max = max_entries
        self._ttl = ttl_seconds
        self._store: OrderedDict[tuple, float] = OrderedDict()

    # ------------------------------------------------------------------

    def seen(self, *key_parts) -> bool:
        """Check whether *key_parts* was observed within the TTL window.

        Returns ``True`` if the key is still fresh (duplicate).
        Returns ``False`` if the key is new or expired (first occurrence).
        """
        key = key_parts
        now = time.monotonic()

        if key in self._store:
            ts = self._store[key]
            if now - ts < self._ttl:
                # Still fresh — move to end (most-recently-used) and report dup
                self._store.move_to_end(key)
                return True
            # Expired — remove and treat as new
            del self._store[key]

        # New entry: evict oldest if at capacity
        if len(self._store) >= self._max:
            self._store.popitem(last=False)

        self._store[key] = now
        return False

    # ------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._store)
