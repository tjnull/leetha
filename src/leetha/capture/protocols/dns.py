"""DNS protocol parsers (queries and answers)."""
from __future__ import annotations

from leetha.capture.packets import CapturedPacket


def parse_dns(packet) -> CapturedPacket | None:
    """Extract DNS query info from scapy DNS packet on port 53.

    Captures DNS queries for fingerprinting based on domain patterns.
    Only processes queries (qr=0), not responses.
    """
    try:
        from scapy.layers.inet import IP, UDP
        from scapy.layers.dns import DNS, DNSQR
    except ImportError:
        return None

    if not packet.haslayer(DNS) or not packet.haslayer(UDP):
        return None

    udp = packet[UDP]
    if udp.dport != 53 and udp.sport != 53:
        return None

    dns = packet[DNS]

    # Process queries (qr=0) for client fingerprinting,
    # and responses (qr=1) to identify DNS servers/resolvers.
    if dns.qr == 1:
        # DNS response — attribute to the responder (DNS server/resolver)
        src_ip = packet[IP].src if packet.haslayer(IP) else "0.0.0.0"
        src_mac = packet.src.lower() if hasattr(packet, "src") else ""
        return CapturedPacket(
            protocol="dns_server",
            hw_addr=src_mac,
            ip_addr=src_ip,
            fields={
                "role": "dns_server",
                "answer_count": dns.ancount or 0,
            },
            raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
        )

    if not dns.qd:
        return None

    try:
        query = dns.qd[0]
        qname = query.qname.decode() if isinstance(query.qname, bytes) else str(query.qname)
        qtype = query.qtype

        qtype_names = {
            1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
            15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"
        }
        qtype_name = qtype_names.get(qtype, f"TYPE{qtype}")

    except (IndexError, AttributeError):
        return None

    src_ip = packet[IP].src if packet.haslayer(IP) else "0.0.0.0"

    src_mac = packet.src.lower() if hasattr(packet, "src") and packet.src else ""
    if not src_mac:
        return None

    return CapturedPacket(
        protocol="dns",
        hw_addr=src_mac,
        ip_addr=src_ip,
        target_ip=packet[IP].dst if packet.haslayer(IP) else None,
        fields={
            "query_name": qname.rstrip('.'),
            "query_type": qtype,
            "query_type_name": qtype_name,
        },
        raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )


def parse_dns_answer(packet) -> list[CapturedPacket]:
    """Extract hostname-to-IP mappings from DNS response records.

    Returns a list because a single DNS response can contain multiple
    answer records, each revealing a different device.
    """
    from scapy.all import IP, DNS, DNSRR

    if DNS not in packet or not packet[DNS].qr:
        return []
    if IP not in packet:
        return []

    # Re-parse from bytes so scapy computes ancount and builds proper lists
    try:
        raw_bytes = bytes(packet)
        from scapy.all import Ether
        packet = Ether(raw_bytes)
        dns = packet[DNS]
    except Exception:
        dns = packet[DNS]

    src_mac = packet.src if hasattr(packet, "src") else ""
    results = []

    type_map = {1: "A", 28: "AAAA", 12: "PTR", 33: "SRV", 5: "CNAME"}

    if not dns.an:
        return []

    for rr in dns.an:
        try:
            if not hasattr(rr, 'rrname'):
                continue

            rrname = rr.rrname.decode() if isinstance(rr.rrname, bytes) else str(rr.rrname)
            rrname = rrname.rstrip(".")
            rdata = rr.rdata.decode() if isinstance(rr.rdata, bytes) else str(rr.rdata)
            rdata = rdata.rstrip(".")

            record_type = type_map.get(rr.type, str(rr.type))

            fields = {
                "query_name": rrname,
                "record_type": record_type,
                "ttl": rr.ttl,
            }

            if record_type in ("A", "AAAA"):
                fields["answer_ip"] = rdata
                results.append(CapturedPacket(
                    protocol="dns_answer",
                    hw_addr=src_mac,
                    ip_addr=packet[IP].src,
                    target_ip=rdata,
                    fields=fields,
                ))
            elif record_type == "PTR":
                fields["hostname"] = rdata
                results.append(CapturedPacket(
                    protocol="dns_answer",
                    hw_addr=src_mac,
                    ip_addr=packet[IP].src,
                    target_ip=packet[IP].dst,
                    fields=fields,
                ))
        except Exception:
            continue

    return results
