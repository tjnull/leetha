"""Regression coverage for remote capture backlog and router attribution."""

from queue import Queue
from types import SimpleNamespace

import pytest

from leetha.capture.engine import PacketCapture
from leetha.capture.packets import CapturedPacket
from leetha.core.pipeline import Pipeline
from leetha.evidence.models import Evidence


class _Store:
    hosts = findings = verdicts = None


def _packet(protocol, ip, *, ttl=None):
    fields = {} if ttl is None else {"ttl": ttl}
    return CapturedPacket(protocol=protocol, hw_addr="c4:4f:d5:41:83:ef",
                          ip_addr=ip, fields=fields)


def test_capture_queue_counts_drops_and_releases_raw_frame():
    capture = PacketCapture()
    queue = Queue(maxsize=1)
    capture._output = queue
    first = _packet("arp", "192.168.1.1")
    first.raw = b"full frame"
    capture._enqueue(first)
    capture._enqueue(_packet("arp", "192.168.1.2"))
    assert queue.qsize() == 1
    assert queue.get_nowait().raw is None
    assert capture.dropped_packets == 1


@pytest.mark.asyncio
async def test_gateway_offer_still_gets_oui_evidence():
    match = SimpleNamespace(source="oui", match_type="exact", confidence=.95,
                            device_type="router", category="router",
                            manufacturer="Vantiva", vendor="Vantiva",
                            os_family=None, os_version=None, model=None, raw_data={})
    lookup = SimpleNamespace(match_mac=lambda mac: [match])
    pipeline = Pipeline(_Store(), lookup=lookup)
    pipeline._fingerprint_lookup = lambda protocol, packet: []
    pkt = _packet("dhcpv4", "192.168.1.1")
    pkt.fields["raw_options"] = {"message-type": 2}
    await pipeline.process(pkt)
    assert pipeline._oui_vendors[pkt.hw_addr] == "Vantiva"
    assert any(ev.source == "oui" for ev in pipeline._evidence_buffer[pkt.hw_addr])


def test_gateway_rejects_routed_host_fingerprints():
    pipeline = Pipeline(_Store())
    mac = "c4:4f:d5:41:83:ef"
    pipeline._gateway_macs.add(mac)
    pipeline._gateway_ips[mac].add("192.168.1.1")
    assert pipeline._is_forwarded_identity(_packet("tcp_syn", "8.8.8.8", ttl=43))
    assert pipeline._is_forwarded_identity(_packet("tls", "192.168.1.22"))
    assert pipeline._is_forwarded_identity(_packet("tcp_syn", "192.168.1.1", ttl=108))
    assert not pipeline._is_forwarded_identity(_packet("tcp_syn", "192.168.1.1", ttl=64))


@pytest.mark.asyncio
async def test_forwarded_tcp_evidence_never_enters_gateway_verdict():
    pipeline = Pipeline(_Store())
    mac = "c4:4f:d5:41:83:ef"
    pipeline._gateway_macs.add(mac)
    pipeline._gateway_ips[mac].add("192.168.1.1")
    pipeline._processor_instances["tcp_syn"] = SimpleNamespace(
        analyze=lambda packet: [Evidence(source="tcp_syn_sig", method="pattern",
                                         certainty=.9, vendor="MikroTik")]
    )
    pipeline._fingerprint_lookup = lambda protocol, packet: []
    await pipeline.process(_packet("tcp_syn", "8.8.8.8", ttl=43))
    assert not pipeline._evidence_buffer.get(mac)
