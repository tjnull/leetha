"""Phase A.3 Task 20 — per-importer scheduler with jitter + exponential backoff."""

from __future__ import annotations

import asyncio
import logging
import random
from datetime import datetime, timezone
from typing import Awaitable, Callable

from leetha.store.importer_config import ImporterConfig, ImporterConfigRepository

log = logging.getLogger(__name__)

# Exponential backoff ladder (seconds). Cap at 1 hour.
_BACKOFF_SERIES = (60, 120, 240, 480, 960, 1920, 3600)
_JITTER_FRAC = 0.2  # ±20% jitter on the next-sync delay


def _compute_next_delay(interval: int, backoff_level: int, rng: random.Random) -> int:
    """Return the next scheduled delay in seconds, with jitter."""
    if backoff_level > 0:
        base = _BACKOFF_SERIES[min(backoff_level - 1, len(_BACKOFF_SERIES) - 1)]
    else:
        base = interval
    jitter = int(base * _JITTER_FRAC)
    # Symmetric jitter around base: value in [base - jitter, base + jitter]
    return max(1, base + rng.randint(-jitter, jitter))


SyncFn = Callable[[ImporterConfig], Awaitable[int]]


class InventoryScheduler:
    """Fires importer sync callbacks when ``next_sync_at`` <= now.

    The caller supplies a ``sync_fn`` that receives an ``ImporterConfig`` and
    returns the number of devices imported. Failures are caught and recorded
    with exponential backoff.

    Tests can pass a seeded ``random.Random`` and a custom ``now_fn`` to make
    behaviour deterministic.
    """

    def __init__(
        self,
        repo: ImporterConfigRepository,
        sync_fn: SyncFn,
        *,
        poll_interval: float = 30.0,
        rng: random.Random | None = None,
        now_fn: Callable[[], datetime] | None = None,
    ):
        self._repo = repo
        self._sync_fn = sync_fn
        self._poll_interval = poll_interval
        self._rng = rng or random.Random()
        self._now_fn = now_fn or (lambda: datetime.now(timezone.utc))
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None

    async def tick_once(self) -> list[str]:
        """Run one scheduling pass. Returns the list of importer names that fired."""
        now = self._now_fn()
        configs = await self._repo.list_all()
        fired: list[str] = []
        for cfg in configs:
            if not cfg.enabled:
                continue
            # Fire if no schedule yet, or due
            due = cfg.next_sync_at is None or cfg.next_sync_at <= now
            if not due:
                continue
            fired.append(cfg.name)
            try:
                count = await self._sync_fn(cfg)
            except Exception as err:
                log.exception("importer %s failed", cfg.name)
                new_level = min(cfg.backoff_level + 1, len(_BACKOFF_SERIES))
                await self._repo.set_status(cfg.name, "error", error=str(err))
                refreshed = await self._repo.get(cfg.name)
                if refreshed is not None:
                    refreshed.backoff_level = new_level
                    await self._repo.upsert(refreshed)
                delay = _compute_next_delay(cfg.interval_seconds, new_level, self._rng)
                await self._repo.schedule_next_sync(cfg.name, delay_seconds=delay)
                continue
            # Success: reset backoff, mark synced, schedule next
            await self._repo.mark_synced(cfg.name, devices_count=count)
            delay = _compute_next_delay(cfg.interval_seconds, 0, self._rng)
            await self._repo.schedule_next_sync(cfg.name, delay_seconds=delay)
        return fired

    async def run(self) -> None:
        """Main loop. Stops when ``stop()`` is called."""
        while not self._stop.is_set():
            try:
                await self.tick_once()
            except Exception:
                log.exception("scheduler tick failed")
            try:
                await asyncio.wait_for(
                    self._stop.wait(), timeout=self._poll_interval,
                )
            except asyncio.TimeoutError:
                continue

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self.run())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await self._task
            except Exception:
                pass
