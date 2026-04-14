# src/leetha/probe/scheduler.py
"""ProbeScheduler — async wrapper that integrates ProbeEngine into leetha.

Responsibilities:
- Queue probe targets from passive observations
- Dedup by MAC+port+cooldown
- Rate limit concurrent probes
- Execute probes in a thread pool (blocking socket ops)
- Map ProbeResult -> FingerprintMatch for evidence aggregation
"""

from __future__ import annotations

import asyncio
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from leetha.fingerprint.evidence import FingerprintMatch
from leetha.probe.engine import ProbeEngine
from leetha.probe.result import ProbeResult

logger = logging.getLogger(__name__)


class ProbeScheduler:
    """Async scheduler that wraps the synchronous ProbeEngine."""

    def __init__(
        self,
        db,
        engine: ProbeEngine | None = None,
        max_concurrent: int = 10,
        cooldown_seconds: int = 3600,
        per_host_delay: float = 1.0,
    ) -> None:
        self.db = db
        self.engine = engine or ProbeEngine()
        self.max_concurrent = max_concurrent
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self.per_host_delay = per_host_delay
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._executor = ThreadPoolExecutor(max_workers=max_concurrent)
        self._host_locks: dict[str, float] = {}

    async def schedule(
        self, mac: str, ip: str, port: int, protocol: str = "tcp",
        on_result=None,
    ) -> None:
        """Schedule a probe if not within cooldown.

        If *on_result* is provided it must be an async callable with
        signature ``(mac: str, match: FingerprintMatch) -> None``.  When
        the probe completes successfully the callback is invoked with the
        resulting :class:`FingerprintMatch`.
        """
        targets = await self.db.list_probe_targets(mac=mac)
        for t in targets:
            if t["port"] == port and t["protocol"] == protocol:
                last = t.get("last_probed")
                if last:
                    last_dt = datetime.fromisoformat(last)
                    if last_dt.tzinfo is None:
                        last_dt = last_dt.replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) - last_dt < self.cooldown:
                        logger.debug("Skipping %s:%d (within cooldown)", mac, port)
                        return

        await self.db.upsert_probe_target(mac, ip, port, protocol)

        if on_result is not None and ip:
            asyncio.ensure_future(
                self._probe_and_callback(mac, ip, port, protocol, on_result)
            )

    async def _probe_and_callback(
        self, mac: str, ip: str, port: int, protocol: str, on_result,
    ) -> None:
        """Run the probe and invoke the callback with the result."""
        try:
            result = await self.probe_target(mac, ip, port, protocol)
            if result:
                match = self.result_to_match(result)
                await on_result(mac, match)
        except Exception as exc:
            logger.debug("Probe callback failed for %s:%d: %s", ip, port, exc)

    async def _run_probe(
        self, host: str, port: int, protocol: str = "tcp",
    ) -> ProbeResult | None:
        """Run a probe in the thread pool."""
        loop = asyncio.get_running_loop()
        async with self._semaphore:
            result = await loop.run_in_executor(
                self._executor,
                lambda: self.engine.scan_service(host, port, protocol=protocol),
            )
            return result

    async def probe_target(
        self, mac: str, ip: str, port: int, protocol: str = "tcp",
    ) -> ProbeResult | None:
        """Probe a target and store the result."""
        await self.db.update_probe_result(mac, port, protocol, "probing")
        try:
            result = await self._run_probe(ip, port, protocol)
            if result:
                await self.db.update_probe_result(
                    mac, port, protocol, "completed",
                    json.dumps(result.to_dict()),
                )
            else:
                await self.db.update_probe_result(mac, port, protocol, "failed")
            return result
        except Exception as exc:
            logger.error("Probe failed for %s:%d: %s", ip, port, exc)
            await self.db.update_probe_result(mac, port, protocol, "failed")
            return None

    @staticmethod
    def result_to_match(result: ProbeResult) -> FingerprintMatch:
        """Convert a ProbeResult to a FingerprintMatch for evidence aggregation."""
        return FingerprintMatch(
            source="active_probe",
            match_type="exact",
            confidence=result.confidence / 100.0,
            device_type=result.metadata.get("device_type"),
            manufacturer=result.metadata.get("vendor") or result.metadata.get("manufacturer"),
            os_family=result.metadata.get("os_hint") or result.metadata.get("os_family"),
            os_version=result.version,
            raw_data={
                "service": result.service,
                "version": result.version,
                "banner": result.banner,
                "tls": result.tls,
                "metadata": result.metadata,
            },
        )

    def shutdown(self) -> None:
        """Shut down the thread pool."""
        self._executor.shutdown(wait=False)
