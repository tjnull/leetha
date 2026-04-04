"""Packet dispatch and batched persistence pipeline.

Provides a sharded processing model where incoming packets are
distributed across worker queues by MAC-hash, and database mutations
are collected and flushed in batched transactions.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

from leetha.capture.protocols import ParsedPacket
from leetha.store.database import Database
from leetha.store.models import Observation, Device, Alert

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Packet distribution
# ---------------------------------------------------------------------------


class PacketDispatcher:
    """Distributes packets across N worker queues keyed by source MAC hash.

    Each worker queue is an ``asyncio.Queue`` that a dedicated coroutine
    drains independently, ensuring packets from the same device always
    land on the same shard.
    """

    def __init__(self, shard_count: int = 4, num_workers: int | None = None, max_queue_size: int = 10_000):
        if num_workers is not None:
            shard_count = num_workers
        self.shard_count = shard_count
        self.dropped_count = 0
        self.workers: list[asyncio.Queue[ParsedPacket]] = [
            asyncio.Queue(maxsize=max_queue_size) for _ in range(shard_count)
        ]

    # -- kept as ``num_workers`` property so existing code that reads
    #    ``router.num_workers`` still works.
    @property
    def num_workers(self) -> int:  # noqa: D401
        return self.shard_count

    def shard_for(self, pkt: ParsedPacket) -> int:
        """Compute the target shard index for *pkt*."""
        return hash(pkt.src_mac) % self.shard_count

    def route(self, pkt: ParsedPacket) -> None:
        """Enqueue *pkt* onto its designated shard queue."""
        idx = self.shard_for(pkt)
        try:
            self.workers[idx].put_nowait(pkt)
        except asyncio.QueueFull:
            self.dropped_count += 1


# Backward-compat alias -- app.py imports ``PacketRouter``
PacketRouter = PacketDispatcher


# ---------------------------------------------------------------------------
# Batched store operations
# ---------------------------------------------------------------------------


class StoreOp(ABC):
    """Unit of work that can be executed against the database."""

    @abstractmethod
    async def execute(self, db: Database) -> None: ...


# Backward-compat alias
WriteOp = StoreOp


@dataclass
class RecordSighting(StoreOp):
    """Persist a single observation row without committing."""

    obs: Observation

    async def execute(self, db: Database) -> None:
        await db.add_observation_no_commit(self.obs)


# Backward-compat alias
AddObservation = RecordSighting


@dataclass
class UpdateHost(StoreOp):
    """Upsert a device row without committing."""

    device: Device

    async def execute(self, db: Database) -> None:
        await db.upsert_device_no_commit(self.device)


# Backward-compat alias
UpsertDevice = UpdateHost


@dataclass
class RecordFinding(StoreOp):
    """Insert an alert row without committing."""

    alert: Alert

    async def execute(self, db: Database) -> None:
        await db.add_alert_no_commit(self.alert)


# Backward-compat alias
AddAlert = RecordFinding


# ---------------------------------------------------------------------------
# Batch committer
# ---------------------------------------------------------------------------


class BatchCommitter:
    """Accumulates ``StoreOp`` items and flushes them in grouped transactions.

    The committer runs an infinite loop that collects operations from its
    internal queue and writes them inside a single ``BEGIN IMMEDIATE`` /
    ``COMMIT`` block, amortising per-write overhead.
    """

    def __init__(
        self,
        db: Database,
        flush_interval: float = 0.1,
        max_batch: int = 50,
    ):
        self.db = db
        self._pending: asyncio.Queue[StoreOp] = asyncio.Queue()
        self._interval = flush_interval
        self._batch_cap = max_batch

    def enqueue(self, *operations: StoreOp) -> None:
        """Submit one or more operations for batched writing."""
        for op in operations:
            self._pending.put_nowait(op)

    async def run(self) -> None:
        """Main loop -- collect and execute batches until cancelled."""
        try:
            while True:
                batch = await self._collect_batch()
                if not batch:
                    continue
                try:
                    async with self.db.transaction():
                        for op in batch:
                            await op.execute(self.db)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    _log.error("Batch commit failed", exc_info=True)
        except asyncio.CancelledError:
            return

    async def flush(self) -> None:
        """Drain whatever is pending and write it -- used during shutdown."""
        remaining: list[StoreOp] = []
        while not self._pending.empty():
            try:
                remaining.append(self._pending.get_nowait())
            except asyncio.QueueEmpty:
                break
        if remaining:
            try:
                async with self.db.transaction():
                    for op in remaining:
                        await op.execute(self.db)
            except Exception:
                _log.debug("Flush on shutdown failed", exc_info=True)

    async def _collect_batch(self) -> list[StoreOp]:
        """Wait for the first item, then greedily drain up to *_batch_cap*."""
        collected: list[StoreOp] = []

        # Block until at least one item arrives (or timeout)
        try:
            head = await asyncio.wait_for(
                self._pending.get(), timeout=self._interval,
            )
            collected.append(head)
        except asyncio.TimeoutError:
            return collected

        # Greedily pull more items within the time budget
        loop = asyncio.get_event_loop()
        cutoff = loop.time() + self._interval
        while len(collected) < self._batch_cap:
            budget = cutoff - loop.time()
            if budget <= 0:
                break
            try:
                item = await asyncio.wait_for(
                    self._pending.get(), timeout=budget,
                )
                collected.append(item)
            except asyncio.TimeoutError:
                break
        return collected


# Backward-compat alias -- app.py imports ``BatchWriter``
BatchWriter = BatchCommitter
