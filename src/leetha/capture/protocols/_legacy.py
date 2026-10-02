"""Backward-compatibility shim for the old monolithic protocols module.

Re-exports ParsedPacket and all legacy parser functions so that existing
code importing from ``leetha.capture.protocols`` keeps working during
the bridge period.

DO NOT add new code here -- use the split parser modules instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ParsedPacket:
    """Normalized packet data for the fingerprint engine."""
    protocol: str      # "tcp_syn", "dhcpv4", "dhcpv6", "mdns", "arp", "banner"
    src_mac: str
    src_ip: str
    dst_ip: str | None = None
    dst_mac: str | None = None
    data: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    raw_bytes: bytes | None = None   # for --decode mode
    interface: str | None = None    # source capture interface
    network: str | None = None      # CIDR network derived from src_ip + interface


def parse_tcp_syn(packet) -> ParsedPacket | None:
    """Extract TCP SYN fingerprint data from scapy packet."""
    try:
        from scapy.layers.inet import IP, TCP
    except ImportError:
        return None

    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return None

    tcp = packet[TCP]
    ip = packet[IP]

    if not (tcp.flags & 0x02) or (tcp.flags & 0x10):
        return None

    options = []
    mss = None
    window_scale = None
    for opt_name, opt_val in tcp.options:
        if opt_name == "MSS":
            mss = opt_val
            options.append("M")
        elif opt_name == "NOP":
            options.append("N")
        elif opt_name == "WScale":
            window_scale = opt_val
            options.append("W")
        elif opt_name == "Timestamp":
            options.append("T")
        elif opt_name == "SAckOK":
            options.append("S")
        elif opt_name == "EOL":
            options.append("E")
        else:
            options.append("?")

    return ParsedPacket(
        protocol="tcp_syn",
        src_mac=packet.src,
        src_ip=ip.src,
        dst_ip=ip.dst,
        dst_mac=packet.dst,
        data={
            "ttl": ip.ttl,
            "window_size": tcp.window,
            "mss": mss,
            "tcp_options": ",".join(options),
            "window_scale": window_scale,
        },
        raw_bytes=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )


def parse_dhcpv4(packet) -> ParsedPacket | None:
    """Extract DHCPv4 options from scapy BOOTP/DHCP packet."""
    try:
        from scapy.layers.inet import IP, UDP
        from scapy.layers.dhcp import DHCP, BOOTP
    except ImportError:
        return None

    if not packet.haslayer(DHCP):
        return None

    dhcp = packet[DHCP]
    bootp = packet[BOOTP]

    opt55 = None
    opt60 = None
    hostname = None
    msg_type = None
    requested_addr = None
    client_id = None
    raw_options = {}

    for opt in dhcp.options:
        if isinstance(opt, tuple) and len(opt) >= 2:
            name, value = opt[0], opt[1]
            raw_options[name] = value
            if name == "param_req_list":
                opt55 = ",".join(str(x) for x in value)
            elif name == "vendor_class_id":
                opt60 = value.decode() if isinstance(value, bytes) else str(value)
            elif name == "hostname":
                hostname = value.decode() if isinstance(value, bytes) else str(value)
            elif name == "message-type":
                msg_type = value
            elif name == "requested_addr":
                requested_addr = value if isinstance(value, str) else str(value)
            elif name == "client_id":
                if isinstance(value, bytes) and len(value) == 7 and value[0] == 1:
                    client_id = value[1:].hex(":")
                elif isinstance(value, bytes) and len(value) == 6:
                    client_id = value.hex(":")

    client_mac = bootp.chaddr[:6].hex(":")

    client_ip = "0.0.0.0"
    yiaddr = getattr(bootp, "yiaddr", "0.0.0.0") or "0.0.0.0"
    ciaddr = getattr(bootp, "ciaddr", "0.0.0.0") or "0.0.0.0"
    if yiaddr != "0.0.0.0":
        client_ip = yiaddr
    elif ciaddr != "0.0.0.0":
        client_ip = ciaddr
    elif requested_addr and requested_addr != "0.0.0.0":
        client_ip = requested_addr
    else:
        ip_src = packet[IP].src if packet.haslayer(IP) else "0.0.0.0"
        if ip_src != "0.0.0.0":
            client_ip = ip_src

    return ParsedPacket(
        protocol="dhcpv4",
        src_mac=client_mac,
        src_ip=client_ip,
        data={
            "opt55": opt55,
            "opt60": opt60,
            "hostname": hostname,
            "message_type": msg_type,
            "client_id": client_id,
            "raw_options": raw_options,
        },
        raw_bytes=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )


def parse_dhcpv6(packet) -> ParsedPacket | None:
    """Extract DHCPv6 fields from scapy packet (UDP 546/547)."""
    try:
        from scapy.layers.inet6 import IPv6, UDP
        from scapy.layers.dhcp6 import (
            DHCP6_Solicit, DHCP6_Request, DHCP6_InfoRequest,
            DHCP6OptOptReq, DHCP6OptClientId, DHCP6OptVendorClass,
            DHCP6OptClientFQDN,
        )
    except ImportError:
        return None

    dhcpv6_types = (DHCP6_Solicit, DHCP6_Request, DHCP6_InfoRequest)
    dhcpv6_layer = None
    for dtype in dhcpv6_types:
        if packet.haslayer(dtype):
            dhcpv6_layer = packet[dtype]
            break

    if dhcpv6_layer is None:
        return None

    oro = None
    if packet.haslayer(DHCP6OptOptReq):
        oro_layer = packet[DHCP6OptOptReq]
        if hasattr(oro_layer, 'reqopts'):
            oro = ",".join(str(x) for x in oro_layer.reqopts)

    duid = None
    if packet.haslayer(DHCP6OptClientId):
        client_id = packet[DHCP6OptClientId]
        if hasattr(client_id, 'duid') and client_id.duid:
            duid = client_id.duid.hex() if isinstance(client_id.duid, bytes) else str(client_id.duid)

    vendor_class = None
    enterprise_id = None
    if packet.haslayer(DHCP6OptVendorClass):
        vc = packet[DHCP6OptVendorClass]
        enterprise_id = getattr(vc, 'enterprisenum', None)
        if hasattr(vc, 'vcdata'):
            vendor_class = vc.vcdata.decode() if isinstance(vc.vcdata, bytes) else str(vc.vcdata)

    fqdn = None
    if packet.haslayer(DHCP6OptClientFQDN):
        fqdn_opt = packet[DHCP6OptClientFQDN]
        fqdn = getattr(fqdn_opt, 'fqdn', None)

    src_ip = packet[IPv6].src if packet.haslayer(IPv6) else "::"

    return ParsedPacket(
        protocol="dhcpv6",
        src_mac=packet.src,
        src_ip=src_ip,
        data={
            "oro": oro,
            "duid": duid,
            "vendor_class": vendor_class,
            "enterprise_id": enterprise_id,
            "fqdn": fqdn,
        },
        raw_bytes=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )


def parse_mdns(packet) -> ParsedPacket | None:
    """Extract mDNS service info from scapy DNS packet on port 5353."""
    try:
        from scapy.layers.inet import IP, UDP
        from scapy.layers.dns import DNS, DNSQR, DNSRR
    except ImportError:
        return None

    if not packet.haslayer(DNS) or not packet.haslayer(UDP):
        return None

    udp = packet[UDP]
    if udp.dport != 5353 and udp.sport != 5353:
        return None

    dns = packet[DNS]
    service_type = None
    name = None

    if dns.qd:
        qd_count = dns.qdcount if dns.qdcount is not None else len(dns.qd) if hasattr(dns.qd, '__len__') else 1
        for i in range(qd_count):
            try:
                qname = dns.qd[i].qname.decode() if isinstance(dns.qd[i].qname, bytes) else str(dns.qd[i].qname)
                if "._tcp." in qname or "._udp." in qname:
                    parts = qname.rstrip(".").split(".")
                    for j, part in enumerate(parts):
                        if part.startswith("_") and j + 1 < len(parts) and parts[j+1] in ("_tcp", "_udp"):
                            service_type = f"{part}.{parts[j+1]}"
                            break
            except (IndexError, AttributeError):
                continue

    txt_records = {}
    if dns.an:
        an_count = dns.ancount if dns.ancount is not None else len(dns.an) if hasattr(dns.an, '__len__') else 0
        for i in range(an_count):
            try:
                rr = dns.an[i] if hasattr(dns, 'an') and dns.an else None
                if rr is None:
                    break
                rrname = rr.rrname.decode() if isinstance(rr.rrname, bytes) else str(rr.rrname)

                if hasattr(rr, 'rdata'):
                    if hasattr(rr, 'type') and rr.type == 16:
                        rdata = rr.rdata
                        if isinstance(rdata, (bytes, bytearray)):
                            pos = 0
                            while pos < len(rdata):
                                length = rdata[pos]
                                pos += 1
                                if length == 0 or pos + length > len(rdata):
                                    break
                                txt_field = rdata[pos:pos + length].decode('utf-8', errors='replace')
                                pos += length
                                if '=' in txt_field:
                                    key, _, val = txt_field.partition('=')
                                    txt_records[key.strip().lower()] = val.strip()
                        elif isinstance(rdata, list):
                            for item in rdata:
                                s = item.decode('utf-8', errors='replace') if isinstance(item, bytes) else str(item)
                                if '=' in s:
                                    key, _, val = s.partition('=')
                                    txt_records[key.strip().lower()] = val.strip()
                    else:
                        rdata = rr.rdata.decode() if isinstance(rr.rdata, bytes) else str(rr.rdata)
                        if "._tcp." in rrname or "._udp." in rrname:
                            name = rdata
            except (IndexError, AttributeError):
                continue

    if service_type is None:
        return None

    src_ip = packet[IP].src if packet.haslayer(IP) else "0.0.0.0"

    clean_name = name
    if clean_name:
        import re as _re
        if "._tcp." in clean_name or "._udp." in clean_name:
            clean_name = clean_name.split("._")[0]
        clean_name = _re.sub(r'-[0-9a-f]{12,}$', '', clean_name, flags=_re.IGNORECASE)
        if clean_name.endswith(".local"):
            clean_name = clean_name[:-6]
        clean_name = clean_name.rstrip(".") or name

    data = {
        "service_type": service_type,
        "name": clean_name,
    }

    if txt_records:
        data['txt_records'] = txt_records
        if 'md' in txt_records:
            data['model'] = txt_records['md']
        if 'fn' in txt_records:
            data['friendly_name'] = txt_records['fn']
        if 'am' in txt_records:
            data['apple_model'] = txt_records['am']
        if 'manufacturer' in txt_records:
            data['txt_manufacturer'] = txt_records['manufacturer']

    return ParsedPacket(
        protocol="mdns",
        src_mac=packet.src,
        src_ip=src_ip,
        dst_ip="224.0.0.251",
        data=data,
        raw_bytes=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )


def parse_arp(packet) -> ParsedPacket | None:
    """Extract ARP src MAC/IP mapping."""
    try:
        from scapy.layers.l2 import ARP
    except ImportError:
        return None

    if not packet.haslayer(ARP):
        return None

    arp = packet[ARP]

    if arp.op not in (1, 2):
        return None

    return ParsedPacket(
        protocol="arp",
        src_mac=arp.hwsrc,
        src_ip=arp.psrc,
        dst_ip=arp.pdst,
        dst_mac=arp.hwdst,
        data={
            "op": arp.op,
            "src_mac": arp.hwsrc,
            "src_ip": arp.psrc,
            "dst_mac": arp.hwdst,
            "dst_ip": arp.pdst,
        },
        raw_bytes=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )


def parse_ssdp(packet) -> ParsedPacket | None:
    """Extract SSDP/UPnP fields from UDP port 1900 packets."""
    try:
        from scapy.layers.inet import IP, UDP
    except ImportError:
        return None
    if not packet.haslayer(UDP) or not packet.haslayer(IP):
        return None
    udp = packet[UDP]
    if udp.dport != 1900 and udp.sport != 1900:
        return None
    try:
        payload = bytes(udp.payload).decode("utf-8", errors="ignore")
    except Exception:
        return None
    if not payload:
        return None
    headers: dict[str, str] = {}
    for line in payload.split("\r\n"):
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().upper()] = value.strip()
    ssdp_type = None
    if payload.startswith("NOTIFY"):
        ssdp_type = "notify"
    elif payload.startswith("HTTP/"):
        ssdp_type = "response"
    elif payload.startswith("M-SEARCH"):
        return None
    if ssdp_type is None:
        return None
    server = headers.get("SERVER")
    st = headers.get("ST") or headers.get("NT")
    usn = headers.get("USN")
    location = headers.get("LOCATION")
    if not server and not st:
        return None
    return ParsedPacket(
        protocol="ssdp",
        src_mac=packet.src,
        src_ip=packet[IP].src,
        dst_ip=packet[IP].dst,
        data={"ssdp_type": ssdp_type, "server": server, "st": st, "usn": usn, "location": location},
        raw_bytes=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )


def parse_llmnr_netbios(packet) -> ParsedPacket | None:
    """Extract LLMNR (UDP 5355) or NetBIOS Name Service (UDP 137) data."""
    try:
        from scapy.layers.inet import IP, UDP
    except ImportError:
        return None
    if not packet.haslayer(UDP) or not packet.haslayer(IP):
        return None
    udp = packet[UDP]
    ip = packet[IP]
    if udp.dport == 5355 or udp.sport == 5355:
        try:
            from scapy.layers.dns import DNS
        except ImportError:
            return None
        if not packet.haslayer(DNS):
            return None
        dns = packet[DNS]
        query_name = None
        if dns.qd:
            try:
                qname = dns.qd[0].qname
                query_name = qname.decode().rstrip(".") if isinstance(qname, bytes) else str(qname).rstrip(".")
            except (AttributeError, UnicodeDecodeError):
                pass
        if not query_name:
            return None
        return ParsedPacket(
            protocol="netbios", src_mac=packet.src, src_ip=ip.src, dst_ip=ip.dst,
            data={"query_name": query_name, "query_type": "llmnr"},
            raw_bytes=bytes(packet) if hasattr(packet, '__bytes__') else None,
        )
    elif udp.dport == 137 or udp.sport == 137:
        try:
            payload = bytes(udp.payload)
        except Exception:
            return None
        if len(payload) < 12:
            return None
        query_name = None
        netbios_suffix = None
        try:
            name_start = 12 + 1
            if name_start + 32 <= len(payload):
                encoded = payload[name_start:name_start + 32]
                decoded_chars = []
                for j in range(0, 32, 2):
                    ch = ((encoded[j] - 0x41) << 4) | (encoded[j + 1] - 0x41)
                    decoded_chars.append(ch)
                netbios_suffix = decoded_chars[-1]
                query_name = bytes(decoded_chars[:15]).decode("ascii", errors="ignore").rstrip()
        except (IndexError, ValueError):
            pass
        if not query_name:
            return None
        data = {"query_name": query_name, "query_type": "netbios"}
        if netbios_suffix is not None:
            data["netbios_suffix"] = netbios_suffix
        return ParsedPacket(
            protocol="netbios", src_mac=packet.src, src_ip=ip.src, dst_ip=ip.dst,
            data=data, raw_bytes=bytes(packet) if hasattr(packet, '__bytes__') else None,
        )
    return None


def parse_tls_client_hello(packet) -> ParsedPacket | None:
    """Extract TLS Client Hello from TCP payload on port 443."""
    try:
        from scapy.layers.inet import IP, TCP
    except ImportError:
        return None

    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return None

    tcp = packet[TCP]
    ip = packet[IP]

    if tcp.dport != 443:
        return None

    payload = bytes(tcp.payload)
    if len(payload) < 6:
        return None

    from leetha.capture.tls_parser import parse_client_hello
    from leetha.patterns.tls import compute_ja3, compute_ja4

    fields = parse_client_hello(payload)
    if fields is None:
        return None

    ja3_hash, ja3_full = compute_ja3(
        tls_version=fields.tls_version,
        ciphers=fields.ciphers,
        extensions=fields.extensions,
        elliptic_curves=fields.elliptic_curves,
        ec_point_formats=fields.ec_point_formats,
    )

    ja4 = compute_ja4(
        tls_version=fields.tls_version,
        ciphers=fields.ciphers,
        extensions=fields.extensions,
        sni=fields.sni,
        alpn=fields.alpn,
        supported_versions=fields.supported_versions,
        signature_algorithms=fields.signature_algorithms,
        sni_present=0 in fields.extensions,
    )

    return ParsedPacket(
        protocol="tls",
        src_mac=packet.src,
        src_ip=ip.src,
        dst_ip=ip.dst,
        dst_mac=packet.dst,
        data={
            "ja3_hash": ja3_hash,
            "ja3_full": ja3_full,
            "ja4": ja4,
            "sni": fields.sni,
            "tls_version": fields.tls_version,
        },
        raw_bytes=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )


def parse_dns(packet) -> ParsedPacket | None:
    """Extract DNS query info from scapy DNS packet on port 53."""
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

    if dns.qr == 1:
        return None

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

    return ParsedPacket(
        protocol="dns",
        src_mac=packet.src.lower(),
        src_ip=src_ip,
        dst_ip=packet[IP].dst if packet.haslayer(IP) else None,
        data={
            "query_name": qname.rstrip('.'),
            "query_type": qtype,
            "query_type_name": qtype_name,
        },
        raw_bytes=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )


def parse_icmpv6(packet) -> ParsedPacket | None:
    """Extract ICMPv6 Router/Neighbor Discovery info."""
    try:
        from scapy.all import IPv6
        from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA
    except ImportError:
        return None

    if not packet.haslayer(IPv6):
        return None

    icmp_type = None
    data = {}

    if packet.haslayer(ICMPv6ND_RA):
        icmp_type = "router_advertisement"
        ra = packet[ICMPv6ND_RA]
        data = {
            "hop_limit": getattr(ra, 'chlim', None),
            "managed": getattr(ra, 'M', None),
            "other": getattr(ra, 'O', None),
        }
    elif packet.haslayer(ICMPv6ND_NS):
        icmp_type = "neighbor_solicitation"
        ns = packet[ICMPv6ND_NS]
        data = {
            "target": getattr(ns, 'tgt', None),
        }
    elif packet.haslayer(ICMPv6ND_NA):
        icmp_type = "neighbor_advertisement"
        na = packet[ICMPv6ND_NA]
        data = {
            "target": getattr(na, 'tgt', None),
            "router": getattr(na, 'R', None),
            "solicited": getattr(na, 'S', None),
            "override": getattr(na, 'O', None),
        }

    if not icmp_type:
        return None

    ipv6 = packet[IPv6]

    return ParsedPacket(
        protocol="icmpv6",
        src_mac=packet.src,
        src_ip=ipv6.src,
        dst_ip=ipv6.dst,
        dst_mac=packet.dst,
        data={
            "icmpv6_type": icmp_type,
            **data,
        },
        raw_bytes=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )


def _guess_initial_ttl(ttl: int) -> tuple[int, str]:
    """Guess the initial TTL and broad OS hint from observed TTL."""
    if ttl <= 64:
        return 64, ""  # ambiguous — no OS guess
    if ttl <= 128:
        return 128, "windows"
    return 255, "network_device"


def parse_ip_observed(packet) -> ParsedPacket | None:
    """Fallback parser: extract basic IP-level info from any IP packet."""
    from scapy.all import IP, TCP, UDP

    if IP not in packet:
        return None

    ip = packet[IP]
    src_mac = packet.src if hasattr(packet, "src") else ""

    ttl_initial, ttl_hint = _guess_initial_ttl(ip.ttl)
    ttl_hops = ttl_initial - ip.ttl

    data = {
        "proto": ip.proto,
        "ttl": ip.ttl,
        "ttl_initial_guess": ttl_initial,
        "ttl_os_hint": ttl_hint,
        "ttl_hops": ttl_hops,
        "src_port": None,
        "dst_port": None,
    }

    if TCP in packet:
        data["src_port"] = packet[TCP].sport
        data["dst_port"] = packet[TCP].dport
    elif UDP in packet:
        data["src_port"] = packet[UDP].sport
        data["dst_port"] = packet[UDP].dport

    return ParsedPacket(
        protocol="ip_observed",
        src_mac=src_mac,
        src_ip=ip.src,
        dst_ip=ip.dst,
        data=data,
    )


def parse_dns_answer(packet) -> list[ParsedPacket]:
    """Extract hostname-to-IP mappings from DNS response records."""
    from scapy.all import IP, DNS, DNSRR

    if DNS not in packet or not packet[DNS].qr:
        return []
    if IP not in packet:
        return []

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

            data = {
                "query_name": rrname,
                "record_type": record_type,
                "ttl": rr.ttl,
            }

            if record_type in ("A", "AAAA"):
                data["answer_ip"] = rdata
                results.append(ParsedPacket(
                    protocol="dns_answer",
                    src_mac=src_mac,
                    src_ip=packet[IP].src,
                    dst_ip=rdata,
                    data=data,
                ))
            elif record_type == "PTR":
                data["hostname"] = rdata
                results.append(ParsedPacket(
                    protocol="dns_answer",
                    src_mac=src_mac,
                    src_ip=packet[IP].src,
                    dst_ip=packet[IP].dst,
                    data=data,
                ))
        except Exception:
            continue

    return results


def parse_http_useragent(packet) -> ParsedPacket | None:
    """Extract User-Agent from unencrypted HTTP requests."""
    from scapy.all import IP, TCP, Raw

    if TCP not in packet or Raw not in packet or IP not in packet:
        return None

    try:
        payload = bytes(packet[Raw].load)
        text = payload[:2048].decode("utf-8", errors="ignore")
    except Exception:
        return None

    if not text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "PATCH ", "OPTIONS ")):
        return None

    first_line = text.split("\r\n", 1)[0]
    parts = first_line.split(" ", 2)
    if len(parts) < 2:
        return None
    method, path = parts[0], parts[1]

    user_agent = None
    host = None
    for line in text.split("\r\n")[1:]:
        if not line:
            break
        lower = line.lower()
        if lower.startswith("user-agent:"):
            user_agent = line.split(":", 1)[1].strip()
        elif lower.startswith("host:"):
            host = line.split(":", 1)[1].strip()

    if not user_agent:
        return None

    src_mac = packet.src if hasattr(packet, "src") else ""

    return ParsedPacket(
        protocol="http_useragent",
        src_mac=src_mac,
        src_ip=packet[IP].src,
        dst_ip=packet[IP].dst,
        data={
            "user_agent": user_agent,
            "host": host,
            "method": method,
            "path": path,
        },
    )
