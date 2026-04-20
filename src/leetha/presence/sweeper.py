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
        """Single pass. Returns transitions triggered this pass."""
        assert self._db._conn is not None
        now = self._now_fn()
        async with self._db._conn.execute(
            "SELECT mac, last_seen, is_online, offline_since, "
            "presence_threshold_seconds, criticality "
            "FROM devices"
        ) as cur:
            rows = await cur.fetchall()

        transitions: list[PresenceTransition] = []
        for row in rows:
            mac = row["mac"]
            last_seen_raw = row["last_seen"]
            if not last_seen_raw:
                continue
            try:
                last_seen = datetime.fromisoformat(last_seen_raw)
            except (ValueError, TypeError):
                continue
            # Normalize both to aware UTC for comparison
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            threshold = int(row["presence_threshold_seconds"] or 300)
            age = (now - last_seen).total_seconds()
            currently_online = bool(row["is_online"])
            should_be_online = age < threshold

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
