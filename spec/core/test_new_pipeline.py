"""Tests for enhanced Pipeline with side effect hooks."""
import asyncio
from unittest.mock import AsyncMock, MagicMock
from leetha.core.pipeline import Pipeline
from leetha.capture.packets import CapturedPacket


class TestPipelineHooks:
    def setup_method(self):
        self.loop = asyncio.new_event_loop()

    def teardown_method(self):
        self.loop.close()

    def _make_mock_store(self):
        store = MagicMock()
        store.sightings = AsyncMock()
        store.hosts = AsyncMock()
        store.verdicts = AsyncMock()
        store.findings = AsyncMock()
        return store

    def test_on_arp_callback_fires(self):
        async def _test():
            import leetha.processors
            store = self._make_mock_store()
            arp_cb = AsyncMock()
            pipeline = Pipeline(store, on_arp=arp_cb)
            pkt = CapturedPacket(
                protocol="arp", hw_addr="aa:bb:cc:dd:ee:ff",
                ip_addr="192.168.1.1", fields={"op": 1})
            await pipeline.process(pkt)
            arp_cb.assert_called_once()
        self.loop.run_until_complete(_test())

    def test_on_dhcp_callback_fires(self):
        async def _test():
            import leetha.processors
            store = self._make_mock_store()
            dhcp_cb = MagicMock()
            pipeline = Pipeline(store, on_dhcp=dhcp_cb)
            pkt = CapturedPacket(
                protocol="dhcpv4", hw_addr="aa:bb:cc:dd:ee:ff",
                ip_addr="192.168.1.100",
                fields={"hostname": "test", "opt55": "1,3,6"})
            await pipeline.process(pkt)
            dhcp_cb.assert_called_once()
        self.loop.run_until_complete(_test())

    def test_no_callbacks_still_works(self):
        async def _test():
            import leetha.processors
            store = self._make_mock_store()
            pipeline = Pipeline(store)
            pkt = CapturedPacket(
                protocol="arp", hw_addr="aa:bb:cc:dd:ee:ff",
                ip_addr="192.168.1.1", fields={"op": 1})
            await pipeline.process(pkt)
            # Should not crash
        self.loop.run_until_complete(_test())

    def test_changed_dhcp_signature_is_looked_up(self):
        async def _test():
            import leetha.processors
            pipeline = Pipeline(self._make_mock_store())
            pipeline._fingerprint_lookup = MagicMock(return_value=[])
            for opt55 in ("1,3,6", "1,3,6", "1,3,6,15"):
                await pipeline.process(CapturedPacket(
                    protocol="dhcpv4", hw_addr="aa:bb:cc:dd:ee:ff",
                    ip_addr="192.168.1.100", fields={"opt55": opt55}))
            assert pipeline._fingerprint_lookup.call_count == 2
        self.loop.run_until_complete(_test())

    def test_distinct_mdns_models_have_distinct_lookup_keys(self):
        first = Pipeline._lookup_signature("mdns", {
            "service_type": "_device-info._tcp", "txt_records": {"model": "iPhone15,2"}})
        second = Pipeline._lookup_signature("mdns", {
            "service_type": "_device-info._tcp", "txt_records": {"model": "iPhone16,1"}})
        assert first != second
