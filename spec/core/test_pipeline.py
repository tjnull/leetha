"""Tests for the new processing pipeline."""
import pytest
from unittest.mock import AsyncMock, MagicMock
from leetha.core.pipeline import Pipeline
from leetha.capture.packets import CapturedPacket
from leetha.evidence.engine import VerdictEngine
from leetha.store.store import Store
from leetha.pipeline import PacketDispatcher


@pytest.fixture
async def pipeline():
    """Create a pipeline with in-memory store."""
    store = Store(":memory:")
    await store.initialize()
    # Need to import processors to register them
    import leetha.processors.network
    import leetha.processors.services
    import leetha.processors.names
    import leetha.processors.infrastructure
    import leetha.processors.iot_scada
    import leetha.processors.passive
    import leetha.processors.active
    # Need to import rules to register them
    import importlib
    import leetha.rules.discovery
    import leetha.rules.drift
    import leetha.rules.anomaly
    import leetha.rules.randomization
    importlib.reload(leetha.rules.discovery)
    importlib.reload(leetha.rules.drift)
    importlib.reload(leetha.rules.anomaly)
    importlib.reload(leetha.rules.randomization)

    p = Pipeline(store=store)
    yield p
    await store.close()


@pytest.mark.asyncio
async def test_pipeline_processes_arp(pipeline):
    pkt = CapturedPacket(
        protocol="arp", hw_addr="aa:bb:cc:dd:ee:ff",
        ip_addr="192.168.1.100", fields={"op": 1},
    )
    await pipeline.process(pkt)
    # Host should be stored
    host = await pipeline.store.hosts.find_by_addr("aa:bb:cc:dd:ee:ff")
    assert host is not None
    assert host.ip_addr == "192.168.1.100"


@pytest.mark.asyncio
async def test_pipeline_stores_verdict(pipeline):
    pkt = CapturedPacket(
        protocol="arp", hw_addr="aa:bb:cc:dd:ee:ff",
        ip_addr="192.168.1.100", fields={"op": 1},
    )
    await pipeline.process(pkt)
    verdict = await pipeline.store.verdicts.find_by_addr("aa:bb:cc:dd:ee:ff")
    assert verdict is not None
    assert len(verdict.evidence_chain) >= 1


@pytest.mark.asyncio
async def test_pipeline_records_sighting(pipeline):
    pkt = CapturedPacket(
        protocol="dhcpv4", hw_addr="aa:bb:cc:dd:ee:ff",
        ip_addr="192.168.1.100",
        fields={"hostname": "DESKTOP-ABC", "opt55": "1,3,6,15"},
    )
    await pipeline.process(pkt)
    sightings = await pipeline.store.sightings.for_host("aa:bb:cc:dd:ee:ff")
    assert len(sightings) >= 1
    assert sightings[0].source == "dhcpv4"


@pytest.mark.asyncio
async def test_pipeline_generates_finding_for_new_host(pipeline):
    pkt = CapturedPacket(
        protocol="arp", hw_addr="aa:bb:cc:dd:ee:ff",
        ip_addr="192.168.1.100", fields={"op": 1},
    )
    await pipeline.process(pkt)
    findings = await pipeline.store.findings.list_active()
    # Should have a new_host finding
    assert any(f.rule.value == "new_host" for f in findings)


@pytest.mark.asyncio
async def test_pipeline_handles_unknown_protocol(pipeline):
    pkt = CapturedPacket(
        protocol="unknown_xyz", hw_addr="aa:bb:cc:dd:ee:ff",
        ip_addr="192.168.1.100", fields={},
    )
    await pipeline.process(pkt)  # Should not crash
    host = await pipeline.store.hosts.find_by_addr("aa:bb:cc:dd:ee:ff")
    assert host is None  # No processor matched, nothing stored


@pytest.mark.asyncio
async def test_pipeline_multiple_packets_same_host(pipeline):
    for i in range(3):
        pkt = CapturedPacket(
            protocol="arp", hw_addr="aa:bb:cc:dd:ee:ff",
            ip_addr="192.168.1.100", fields={"op": 1},
        )
        await pipeline.process(pkt)

    # Should still be one host
    count = await pipeline.store.hosts.count()
    assert count == 1

    # Verdict should accumulate evidence
    verdict = await pipeline.store.verdicts.find_by_addr("aa:bb:cc:dd:ee:ff")
    assert len(verdict.evidence_chain) == 3


class TestPacketDispatcherBackpressure:
    def test_queue_has_maxsize(self):
        dispatcher = PacketDispatcher(shard_count=2, max_queue_size=10)
        assert dispatcher.workers[0].maxsize == 10

    def test_default_maxsize(self):
        dispatcher = PacketDispatcher(shard_count=2)
        assert dispatcher.workers[0].maxsize == 10_000

    def test_route_drops_when_full(self):
        dispatcher = PacketDispatcher(shard_count=1, max_queue_size=2)
        for i in range(3):
            pkt = MagicMock()
            pkt.src_mac = "aa:bb:cc:dd:ee:ff"
            dispatcher.route(pkt)
        assert dispatcher.workers[0].qsize() == 2
        assert dispatcher.dropped_count == 1
