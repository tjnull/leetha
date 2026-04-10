"""Integration tests: packet -> processor -> evidence -> verdict -> store."""
import asyncio

import leetha.processors  # trigger auto-discovery
import leetha.rules.discovery  # trigger rule auto-discovery

from leetha.core.pipeline import Pipeline
from leetha.store.store import Store
from leetha.capture.packets import CapturedPacket


class TestPipelineIntegration:
    def setup_method(self):
        self.loop = asyncio.new_event_loop()

    def teardown_method(self):
        self.loop.close()

    def _run(self, coro):
        return self.loop.run_until_complete(coro)

    async def _make_pipeline(self):
        store = Store(":memory:")
        await store.initialize()
        return store, Pipeline(store)

    def test_arp_creates_host_and_verdict(self):
        async def _test():
            store, pipeline = await self._make_pipeline()
            await pipeline.process(CapturedPacket(
                protocol="arp", hw_addr="aa:bb:cc:dd:ee:ff",
                ip_addr="192.168.1.1", fields={"op": 1}))
            host = await store.hosts.find_by_addr("aa:bb:cc:dd:ee:ff")
            assert host is not None
            assert host.ip_addr == "192.168.1.1"
            verdict = await store.verdicts.find_by_addr("aa:bb:cc:dd:ee:ff")
            assert verdict is not None
            await store.close()
        self._run(_test())

    def test_dhcp_produces_hostname_verdict(self):
        async def _test():
            store, pipeline = await self._make_pipeline()
            await pipeline.process(CapturedPacket(
                protocol="dhcpv4", hw_addr="aa:bb:cc:dd:ee:ff",
                ip_addr="192.168.1.100",
                fields={"hostname": "DESKTOP-ABC123", "opt55": "1,3,6,15",
                         "opt60": "MSFT 5.0"}))
            verdict = await store.verdicts.find_by_addr("aa:bb:cc:dd:ee:ff")
            assert verdict is not None
            assert verdict.certainty > 0
            assert verdict.hostname == "DESKTOP-ABC123"
            await store.close()
        self._run(_test())

    def test_banner_identifies_service(self):
        async def _test():
            store, pipeline = await self._make_pipeline()
            await pipeline.process(CapturedPacket(
                protocol="service_banner", hw_addr="aa:bb:cc:dd:ee:ff",
                ip_addr="192.168.1.10",
                fields={"service": "ssh", "software": "OpenSSH_9.2p1",
                         "version": "9.2p1", "server_port": 22}))
            verdict = await store.verdicts.find_by_addr("aa:bb:cc:dd:ee:ff")
            assert verdict is not None
            assert verdict.vendor is not None
            await store.close()
        self._run(_test())

    def test_new_host_finding_fires(self):
        async def _test():
            store, pipeline = await self._make_pipeline()
            await pipeline.process(CapturedPacket(
                protocol="arp", hw_addr="aa:bb:cc:dd:ee:ff",
                ip_addr="192.168.1.1", fields={"op": 1}))
            findings = await store.findings.list_active()
            # new_host rule should fire for first-seen device
            new_host_findings = [f for f in findings if f.rule.value == "new_host"]
            assert len(new_host_findings) >= 1
            await store.close()
        self._run(_test())

    def test_multiple_protocols_increase_certainty(self):
        async def _test():
            store, pipeline = await self._make_pipeline()
            # ARP only
            await pipeline.process(CapturedPacket(
                protocol="arp", hw_addr="aa:bb:cc:dd:ee:ff",
                ip_addr="192.168.1.100", fields={"op": 1}))
            v1 = await store.verdicts.find_by_addr("aa:bb:cc:dd:ee:ff")
            c1 = v1.certainty if v1 else 0
            # Add DHCP
            await pipeline.process(CapturedPacket(
                protocol="dhcpv4", hw_addr="aa:bb:cc:dd:ee:ff",
                ip_addr="192.168.1.100",
                fields={"hostname": "test-device", "opt55": "1,3,6,15"}))
            v2 = await store.verdicts.find_by_addr("aa:bb:cc:dd:ee:ff")
            assert v2.certainty >= c1
            await store.close()
        self._run(_test())

    def test_sighting_recorded(self):
        async def _test():
            store, pipeline = await self._make_pipeline()
            await pipeline.process(CapturedPacket(
                protocol="arp", hw_addr="aa:bb:cc:dd:ee:ff",
                ip_addr="192.168.1.1", fields={"op": 1}))
            sightings = await store.sightings.for_host("aa:bb:cc:dd:ee:ff")
            assert len(sightings) >= 1
            await store.close()
        self._run(_test())

    def test_unknown_protocol_does_not_crash(self):
        async def _test():
            store, pipeline = await self._make_pipeline()
            await pipeline.process(CapturedPacket(
                protocol="unknown_proto", hw_addr="aa:bb:cc:dd:ee:ff",
                ip_addr="192.168.1.1", fields={}))
            # Should not crash; host must ALWAYS be stored even without
            # a matching processor so every MAC appears in the inventory.
            host = await store.hosts.find_by_addr("aa:bb:cc:dd:ee:ff")
            assert host is not None
            assert host.hw_addr == "aa:bb:cc:dd:ee:ff"
            await store.close()
        self._run(_test())

    def test_iot_scada_protocol_creates_verdict(self):
        async def _test():
            store, pipeline = await self._make_pipeline()
            await pipeline.process(CapturedPacket(
                protocol="modbus", hw_addr="aa:bb:cc:dd:ee:ff",
                ip_addr="10.0.0.50",
                fields={"unit_id": 1, "function_code": 3}))
            verdict = await store.verdicts.find_by_addr("aa:bb:cc:dd:ee:ff")
            assert verdict is not None
            assert verdict.category is not None  # should be ics_device or similar
            await store.close()
        self._run(_test())
