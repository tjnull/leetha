"""DHCP server / ICMPv6 RA emit strong router Evidence.

Real-world bug: the AmpliFi router at 192.168.1.1 was classified as
``iot_device @ 90%`` because reflected IoT mDNS polluted its evidence
buffer. Once the reflection guards plug that leak, we *also* want a
positive signal — a MAC that answers DHCP DISCOVER with OFFER/ACK or
sends ICMPv6 Router Advertisements IS a router. Emit that as an
``Evidence`` record so the verdict engine has strong router signal to
offset any remaining pollution (HTTP banners, DHCP fingerprints, etc.).
"""

import asyncio
import pytest

from leetha.capture.packets import CapturedPacket
from leetha.core.pipeline import Pipeline


class _FakeStore:
    async def initialize(self): pass
    async def close(self): pass
    async def upsert_host_and_sighting(self, *a, **k): pass
    async def flush_batch(self, *a, **k): pass
    hosts = findings = verdicts = None


@pytest.mark.asyncio
async def test_dhcp_offer_emits_router_evidence_for_source_mac():
    """A DHCP OFFER from MAC X must add a router-class Evidence to X's
    buffer so the verdict engine knows X is a router even if other
    signals (reflected mDNS, noisy HTTP banners) want to call it an
    IoT device or smart speaker."""
    pipeline = Pipeline(store=_FakeStore())
    pkt = CapturedPacket(
        protocol="dhcpv4",
        hw_addr="d2:21:f9:78:d4:08",
        ip_addr="192.168.1.1",
        fields={"raw_options": {"message-type": 2}},  # 2 = OFFER
    )
    await pipeline.process(pkt)
    buf = pipeline._evidence_buffer.get("d2:21:f9:78:d4:08", [])
    dhcp_server_evs = [e for e in buf if e.source == "dhcp_server"]
    assert dhcp_server_evs, (
        f"DHCP OFFER from MAC must emit dhcp_server Evidence. Buffer: "
        f"{[(e.source, e.category, e.certainty) for e in buf]}"
    )
    e = dhcp_server_evs[0]
    assert e.category == "router", (
        f"dhcp_server Evidence must have category=router; got {e.category!r}"
    )
    assert e.certainty >= 0.85


@pytest.mark.asyncio
async def test_dhcp_ack_also_emits_router_evidence():
    pipeline = Pipeline(store=_FakeStore())
    pkt = CapturedPacket(
        protocol="dhcpv4",
        hw_addr="aa:bb:cc:11:22:33",
        ip_addr="10.0.0.1",
        fields={"raw_options": {"message-type": 5}},  # 5 = ACK
    )
    await pipeline.process(pkt)
    buf = pipeline._evidence_buffer.get("aa:bb:cc:11:22:33", [])
    assert any(e.source == "dhcp_server" and e.category == "router" for e in buf)


@pytest.mark.asyncio
async def test_icmpv6_router_advertisement_emits_router_evidence():
    pipeline = Pipeline(store=_FakeStore())
    pkt = CapturedPacket(
        protocol="icmpv6",
        hw_addr="aa:bb:cc:ff:ee:dd",
        ip_addr="fe80::1",
        fields={"icmpv6_type": "router_advertisement"},
    )
    await pipeline.process(pkt)
    buf = pipeline._evidence_buffer.get("aa:bb:cc:ff:ee:dd", [])
    router_evs = [e for e in buf if e.category == "router"]
    assert router_evs, (
        f"ICMPv6 RA must emit router Evidence; got {[(e.source, e.category) for e in buf]}"
    )


@pytest.mark.asyncio
async def test_dhcp_discover_does_not_emit_router_evidence():
    """DHCP DISCOVER is sent by CLIENTS, not servers — must not mark
    the sender as a router."""
    pipeline = Pipeline(store=_FakeStore())
    pkt = CapturedPacket(
        protocol="dhcpv4",
        hw_addr="aa:bb:cc:cl:ie:nt",
        ip_addr="0.0.0.0",
        fields={"raw_options": {"message-type": 1}},  # 1 = DISCOVER
    )
    # Note: invalid MAC "cl:ie:nt" will be rejected by _is_valid_mac, so use valid
    pkt = CapturedPacket(
        protocol="dhcpv4",
        hw_addr="aa:bb:cc:11:22:33",
        ip_addr="0.0.0.0",
        fields={"raw_options": {"message-type": 1}},  # 1 = DISCOVER
    )
    await pipeline.process(pkt)
    buf = pipeline._evidence_buffer.get("aa:bb:cc:11:22:33", [])
    dhcp_server_evs = [e for e in buf if e.source == "dhcp_server"]
    assert not dhcp_server_evs, "DHCP DISCOVER must not emit router evidence"
