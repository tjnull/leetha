"""Discovery protocol parsers (mDNS, SSDP, LLMNR/NetBIOS)."""
from __future__ import annotations

from leetha.capture.packets import CapturedPacket


def parse_mdns(packet) -> CapturedPacket | None:
    """Extract mDNS service info from scapy DNS packet on port 5353.

    Looks for service types (_airplay._tcp, _http._tcp, etc.) and device names.
    """
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

    # Check queries
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

    # Check answers for service names and TXT records
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

    # Clean mDNS instance names at the parser level
    clean_name = name
    if clean_name:
        import re as _re
        if "._tcp." in clean_name or "._udp." in clean_name:
            clean_name = clean_name.split("._")[0]
        clean_name = _re.sub(r'-[0-9a-f]{12,}$', '', clean_name, flags=_re.IGNORECASE)
        if clean_name.endswith(".local"):
            clean_name = clean_name[:-6]
        clean_name = clean_name.rstrip(".") or name

    fields = {
        "service_type": service_type,
        "name": clean_name,
    }

    if txt_records:
        fields['txt_records'] = txt_records
        if 'md' in txt_records:
            fields['model'] = txt_records['md']
        if 'fn' in txt_records:
            fields['friendly_name'] = txt_records['fn']
        if 'am' in txt_records:
            fields['apple_model'] = txt_records['am']
        if 'manufacturer' in txt_records:
            fields['txt_manufacturer'] = txt_records['manufacturer']

    return CapturedPacket(
        protocol="mdns",
        hw_addr=packet.src,
        ip_addr=src_ip,
        target_ip="224.0.0.251",
        fields=fields,
        raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )


def parse_ssdp(packet) -> CapturedPacket | None:
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
    return CapturedPacket(
        protocol="ssdp",
        hw_addr=packet.src,
        ip_addr=packet[IP].src,
        target_ip=packet[IP].dst,
        fields={"ssdp_type": ssdp_type, "server": server, "st": st, "usn": usn, "location": location},
        raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )


def parse_llmnr_netbios(packet) -> CapturedPacket | None:
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
        return CapturedPacket(
            protocol="netbios", hw_addr=packet.src, ip_addr=ip.src, target_ip=ip.dst,
            fields={"query_name": query_name, "query_type": "llmnr"},
            raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
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
        fields = {"query_name": query_name, "query_type": "netbios"}
        if netbios_suffix is not None:
            fields["netbios_suffix"] = netbios_suffix
        return CapturedPacket(
            protocol="netbios", hw_addr=packet.src, ip_addr=ip.src, target_ip=ip.dst,
            fields=fields, raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
        )
    return None


def parse_upnp(packet) -> CapturedPacket | None:
    """Detect UPnP device description requests on common ports."""
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.packet import Raw
    except ImportError:
        return None

    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return None

    tcp = packet[TCP]
    upnp_ports = {2869, 5000, 49152, 49153, 49154, 49155, 8008, 8443, 8080}
    if tcp.dport not in upnp_ports and tcp.sport not in upnp_ports:
        return None

    # Look for UPnP HTTP requests/responses
    if not packet.haslayer(Raw):
        return None
    try:
        payload = bytes(packet[Raw]).decode('utf-8', errors='replace')[:500]
    except Exception:
        return None

    # Check for UPnP XML or HTTP headers
    upnp_indicators = ("upnp", "urn:schemas-upnp-org", "rootdevice",
                       "WANIPConnection", "WANPPPConnection", "InternetGateway",
                       "MediaRenderer", "MediaServer", "ContentDirectory")
    if not any(ind.lower() in payload.lower() for ind in upnp_indicators):
        return None

    return CapturedPacket(
        protocol="upnp",
        hw_addr=packet.src,
        ip_addr=packet[IP].src,
        target_ip=packet[IP].dst,
        fields={
            "dst_port": tcp.dport,
            "payload_preview": payload[:200],
        },
    )
