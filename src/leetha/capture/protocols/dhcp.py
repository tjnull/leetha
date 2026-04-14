"""DHCP protocol parsers (v4 and v6)."""
from __future__ import annotations

from leetha.capture.packets import CapturedPacket


def parse_dhcpv4(packet) -> CapturedPacket | None:
    """Extract DHCPv4 options from scapy BOOTP/DHCP packet.

    Captures Option 55 (Parameter Request List) and Option 60 (Vendor Class)
    for fingerprinting, plus all raw options for anomaly analysis.
    """
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

    if len(bootp.chaddr) < 6:
        return None
    client_mac = bootp.chaddr[:6].hex(":")

    # Determine the client's actual IP address.
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

    return CapturedPacket(
        protocol="dhcpv4",
        hw_addr=client_mac,
        ip_addr=client_ip,
        fields={
            "opt55": opt55,
            "opt60": opt60,
            "hostname": hostname,
            "message_type": msg_type,
            "client_id": client_id,
            "raw_options": raw_options,
        },
        raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )


def parse_dhcp_server(packet) -> CapturedPacket | None:
    """Extract DHCP server identity from OFFER/ACK packets.

    When a DHCP server sends an OFFER or ACK, the packet reveals the
    server's MAC and IP — critical for identifying gateways/routers.
    """
    try:
        from scapy.layers.inet import IP
        from scapy.layers.dhcp import DHCP, BOOTP
    except ImportError:
        return None

    if not packet.haslayer(DHCP):
        return None

    dhcp = packet[DHCP]
    bootp = packet[BOOTP]

    # Extract message type
    msg_type = None
    for opt in dhcp.options:
        if isinstance(opt, tuple) and len(opt) >= 2 and opt[0] == "message-type":
            msg_type = opt[1]
            break

    # Only OFFER (2) and ACK (5) are server-to-client
    if msg_type not in (2, 5):
        return None

    server_mac = packet.src if hasattr(packet, "src") else ""
    if not server_mac:
        return None

    siaddr = getattr(bootp, "siaddr", "0.0.0.0") or "0.0.0.0"
    server_ip = siaddr if siaddr != "0.0.0.0" else (
        packet[IP].src if packet.haslayer(IP) else "0.0.0.0"
    )
    if server_ip == "0.0.0.0":
        return None

    if len(bootp.chaddr) < 6:
        client_mac = ""
    else:
        client_mac = bootp.chaddr[:6].hex(":")
    yiaddr = getattr(bootp, "yiaddr", "0.0.0.0") or "0.0.0.0"

    return CapturedPacket(
        protocol="dhcp_server",
        hw_addr=server_mac,
        ip_addr=server_ip,
        fields={
            "message_type": msg_type,
            "role": "dhcp_server",
            "client_mac": client_mac,
            "offered_ip": yiaddr,
        },
        raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )


def parse_dhcpv6(packet) -> CapturedPacket | None:
    """Extract DHCPv6 fields from scapy packet (UDP 546/547).

    Extracts: message type, DUID, ORO (option 6), Vendor Class (option 16),
    Enterprise ID, Client FQDN (option 39).
    """
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

    from scapy.layers.l2 import Ether
    hw_addr = packet[Ether].src if Ether in packet else None
    if hw_addr is None:
        return None

    return CapturedPacket(
        protocol="dhcpv6",
        hw_addr=hw_addr,
        ip_addr=src_ip,
        fields={
            "oro": oro,
            "duid": duid,
            "vendor_class": vendor_class,
            "enterprise_id": enterprise_id,
            "fqdn": fqdn,
        },
        raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )
