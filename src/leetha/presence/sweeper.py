"""Phase A.4 Task 30 — presence sweeper.

Scans the ``devices`` table periodically and flips ``is_online`` based on how
long since the last observed packet. Callers can subscribe to transitions to
drive alerting rules.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable

log = logging.getLogger(__name__)


@dataclass
class PresenceTransition:
    mac: str
    previous_state: str  # 'online' | 'offline'
    new_state: str       # 'online' | 'offline'
    last_seen: datetime | None
    threshold_seconds: int
    criticality: str | None = None


TransitionCallback = Callable[[PresenceTransition], Awaitable[None]]


class PresenceSweeper:
    def __init__(
        self,
        db,
        *,
        period_seconds: float = 60.0,
        on_transition: TransitionCallback | None = None,
        now_fn: Callable[[], datetime] | None = None,
    ):
        self._db = db
        self._period = period_seconds
        self._callback = on_transition
        self._now_fn = now_fn or (lambda: datetime.now(timezone.utc))
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None

    async def sweep_once(self) -> list[PresenceTransition]:
        """Single pass. Returns transitions triggered this pass.

        Drives off the UNION of ``hosts`` (populated by live capture — the
        authoritative freshness source) and ``devices`` (where is_online,
        offline_since, and per-device threshold live). A device that only
        exists in ``hosts`` gets a minimal ``devices`` row inserted on
        demand so that subsequent sweeps and API lookups see consistent
        state.
        """
        assert self._db._conn is not None
        now = self._now_fn()
        async with self._db._conn.execute(
            """
            SELECT COALESCE(h.hw_addr, d.mac) AS mac,
                   COALESCE(h.last_active, d.last_seen) AS effective_last_seen,
                   COALESCE(d.is_online, 1) AS is_online,
                   d.offline_since AS offline_since,
                   COALESCE(d.presence_threshold_seconds, 300) AS threshold,
                   d.criticality AS criticality,
                   (d.mac IS NULL) AS missing_device_row
            FROM hosts h
            FULL OUTER JOIN devices d ON h.hw_addr = d.mac
            """
        ) as cur:
            rows = await cur.fetchall()

        # SQLite doesn't support FULL OUTER JOIN until 3.39. Fall back to a
        # UNION of two LEFT JOINs when that query fails at driver time. The
        # try/except in ``run()`` catches genuine errors; here we just make
        # the sweep resilient on older SQLite builds.
        if not rows:
            rows = await self._sweep_rows_via_union()

        transitions: list[PresenceTransition] = []
        for row in rows:
            mac = row["mac"]
            last_seen_raw = row["effective_last_seen"]
            if not mac or not last_seen_raw:
                continue
            try:
                last_seen = datetime.fromisoformat(last_seen_raw)
            except (ValueError, TypeError):
                continue
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            threshold = int(row["threshold"] or 300)
            age = (now - last_seen).total_seconds()
            currently_online = bool(row["is_online"])
            should_be_online = age < threshold
            missing_row = bool(row["missing_device_row"])

            if currently_online == should_be_online and not missing_row:
                continue

            # Ensure a devices row exists before we mutate state on it
            if missing_row:
                from leetha.store.models import Device
                await self._db.upsert_device(Device(
                    mac=mac,
                    first_seen=last_seen, last_seen=last_seen,
                ))

            if currently_online and not should_be_online:
                await self._db.set_device_offline(mac)
                transitions.append(PresenceTransition(
                    mac=mac, previous_state="online", new_state="offline",
                    last_seen=last_seen, threshold_seconds=threshold,
                    criticality=row["criticality"],
                ))
            elif (not currently_online) and should_be_online:
                await self._db.set_device_online(mac)
                transitions.append(PresenceTransition(
                    mac=mac, previous_state="offline", new_state="online",
                    last_seen=last_seen, threshold_seconds=threshold,
                    criticality=row["criticality"],
                ))

        if self._callback is not None:
            for t in transitions:
                try:
                    await self._callback(t)
                except Exception:
                    log.exception("presence transition callback failed for %s", t.mac)
        return transitions

    async def _sweep_rows_via_union(self):
        """FULL OUTER JOIN fallback for older SQLite — build the same shape
        from two LEFT JOINs unioned together."""
        assert self._db._conn is not None
        async with self._db._conn.execute(
            """
            SELECT h.hw_addr AS mac,
                   COALESCE(h.last_active, d.last_seen) AS effective_last_seen,
                   COALESCE(d.is_online, 1) AS is_online,
                   d.offline_since AS offline_since,
                   COALESCE(d.presence_threshold_seconds, 300) AS threshold,
                   d.criticality AS criticality,
                   (d.mac IS NULL) AS missing_device_row
            FROM hosts h LEFT JOIN devices d ON h.hw_addr = d.mac
            UNION
            SELECT d.mac AS mac,
                   COALESCE(h.last_active, d.last_seen) AS effective_last_seen,
                   d.is_online,
                   d.offline_since,
                   COALESCE(d.presence_threshold_seconds, 300) AS threshold,
                   d.criticality,
                   0 AS missing_device_row
            FROM devices d LEFT JOIN hosts h ON h.hw_addr = d.mac
            WHERE h.hw_addr IS NULL
            """
        ) as cur:
            return await cur.fetchall()

    async def run(self) -> None:
        while not self._stop.is_set():
            try:
                await self.sweep_once()
            except Exception:
                log.exception("presence sweep failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._period)
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
