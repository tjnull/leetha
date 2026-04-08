"""Tests for topology graph builder logic."""
import pytest
from leetha.topology import build_topology_graph


def test_empty_network():
    result = build_topology_graph(devices=[], gateways=[], arp_entries=[], lldp_neighbors=[])
    # Empty network still has the internet node
    internet_nodes = [n for n in result["nodes"] if n["id"] == "internet"]
    assert len(internet_nodes) == 1
    assert result["subnets"] == []


def test_single_gateway():
    devices = [{"mac": "aa:bb:cc:dd:ee:ff", "hostname": "router", "ip_v4": "192.168.1.1",
                "device_type": "router", "manufacturer": "Ubiquiti", "confidence": 90,
                "os_family": "Linux", "last_seen": "2026-04-01T12:00:00"}]
    gateways = [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.1", "source": "dhcp_server"}]
    result = build_topology_graph(devices=devices, gateways=gateways, arp_entries=[], lldp_neighbors=[])
    gw_nodes = [n for n in result["nodes"] if n.get("tier") == "gateway"]
    assert len(gw_nodes) == 1
    # Should have internet → gateway edge
    wan_edges = [e for e in result["edges"] if e["type"] == "wan_link"]
    assert len(wan_edges) == 1


def test_no_subnet_group_nodes():
    """Subnet group nodes were removed — topology has no vlan-tier nodes."""
    devices = [
        {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "router", "ip_v4": "192.168.1.1",
         "device_type": "router", "manufacturer": "Ubiquiti", "confidence": 90,
         "os_family": "Linux", "last_seen": "2026-04-01T12:00:00"},
        {"mac": "11:22:33:44:55:66", "hostname": "laptop", "ip_v4": "192.168.1.50",
         "device_type": "laptop", "manufacturer": "Dell", "confidence": 75,
         "os_family": "Windows", "last_seen": "2026-04-01T12:00:00"},
    ]
    gateways = [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.1", "source": "dhcp_server"}]
    result = build_topology_graph(devices=devices, gateways=gateways, arp_entries=[], lldp_neighbors=[])
    vlan_nodes = [n for n in result["nodes"] if n.get("tier") == "vlan"]
    assert len(vlan_nodes) == 0


def test_core_switch_detected():
    """The switch with the most ARP traffic becomes the core switch."""
    devices = [
        {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "router", "ip_v4": "192.168.1.1",
         "device_type": "router", "manufacturer": "Ubiquiti", "confidence": 90,
         "os_family": "Linux", "last_seen": "2026-04-01T12:00:00"},
        {"mac": "11:22:33:44:55:66", "hostname": "core-switch", "ip_v4": "192.168.1.2",
         "device_type": "switch", "manufacturer": "Cisco", "confidence": 95,
         "os_family": None, "last_seen": "2026-04-01T12:00:00"},
        {"mac": "22:33:44:55:66:77", "hostname": "edge-switch", "ip_v4": "192.168.1.3",
         "device_type": "switch", "manufacturer": "Cisco", "confidence": 95,
         "os_family": None, "last_seen": "2026-04-01T12:00:00"},
    ]
    gateways = [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.1", "source": "dhcp_server"}]
    arp_entries = [
        {"mac": "11:22:33:44:55:66", "ip": "192.168.1.2", "packet_count": 5000},
        {"mac": "22:33:44:55:66:77", "ip": "192.168.1.3", "packet_count": 200},
    ]
    result = build_topology_graph(devices=devices, gateways=gateways, arp_entries=arp_entries, lldp_neighbors=[])

    # Core switch should have is_core_switch flag
    core = [n for n in result["nodes"] if n.get("is_core_switch")]
    assert len(core) == 1
    assert core[0]["id"] == "11:22:33:44:55:66"

    # Gateway → core switch trunk link should exist
    trunk_edges = [e for e in result["edges"] if e["type"] == "trunk_link"]
    assert any(e["source"] == "aa:bb:cc:dd:ee:ff" and e["target"] == "11:22:33:44:55:66" for e in trunk_edges)

    # Core switch → edge switch trunk link
    assert any(e["source"] == "11:22:33:44:55:66" and e["target"] == "22:33:44:55:66:77" for e in trunk_edges)


def test_wireless_client_through_ap():
    """Wireless clients should route through APs."""
    devices = [
        {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "router", "ip_v4": "192.168.1.1",
         "device_type": "router", "manufacturer": "Ubiquiti", "confidence": 90,
         "os_family": "Linux", "last_seen": "2026-04-01T12:00:00"},
        {"mac": "11:22:33:44:55:66", "hostname": "ap", "ip_v4": "192.168.1.4",
         "device_type": "access_point", "manufacturer": "Ubiquiti", "confidence": 90,
         "os_family": None, "last_seen": "2026-04-01T12:00:00"},
        {"mac": "33:44:55:66:77:88", "hostname": "phone", "ip_v4": "192.168.1.50",
         "device_type": "smartphone", "manufacturer": "Apple", "confidence": 80,
         "os_family": "iOS", "last_seen": "2026-04-01T12:00:00",
         "connection_type": "wireless"},
    ]
    gateways = [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.1", "source": "dhcp_server"}]
    result = build_topology_graph(devices=devices, gateways=gateways, arp_entries=[], lldp_neighbors=[])

    wireless_edges = [e for e in result["edges"] if e["type"] == "wireless_link"]
    assert len(wireless_edges) >= 1
    phone_edge = [e for e in wireless_edges if e["target"] == "33:44:55:66:77:88"]
    assert len(phone_edge) == 1
    assert phone_edge[0]["source"] == "11:22:33:44:55:66"  # connected through AP


def test_lldp_neighbor_edge():
    devices = [
        {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "switch1", "ip_v4": "192.168.1.2",
         "device_type": "switch", "manufacturer": "Cisco", "confidence": 95,
         "os_family": None, "last_seen": "2026-04-01T12:00:00"},
        {"mac": "11:22:33:44:55:66", "hostname": "switch2", "ip_v4": "192.168.1.3",
         "device_type": "switch", "manufacturer": "Cisco", "confidence": 95,
         "os_family": None, "last_seen": "2026-04-01T12:00:00"},
    ]
    lldp_neighbors = [{"device_mac": "aa:bb:cc:dd:ee:ff", "neighbor_mac": "11:22:33:44:55:66",
                        "port_id": "Gi0/1"}]
    result = build_topology_graph(devices=devices, gateways=[], arp_entries=[], lldp_neighbors=lldp_neighbors)
    # With no gateway, core switch detection picks the first one, and trunk_link covers the connection
    # The LLDP edge may be absorbed into trunk_link — check for either
    infra_edges = [e for e in result["edges"] if e["type"] in ("lldp", "trunk_link")]
    assert len(infra_edges) >= 1


def test_device_tiers():
    devices = [
        {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "router", "ip_v4": "192.168.1.1",
         "device_type": "router", "manufacturer": "Ubiquiti", "confidence": 90,
         "os_family": "Linux", "last_seen": "2026-04-01T12:00:00"},
        {"mac": "11:22:33:44:55:66", "hostname": "core-switch", "ip_v4": "192.168.1.2",
         "device_type": "switch", "manufacturer": "Cisco", "confidence": 95,
         "os_family": None, "last_seen": "2026-04-01T12:00:00"},
        {"mac": "33:44:55:66:77:88", "hostname": "laptop", "ip_v4": "192.168.1.50",
         "device_type": "laptop", "manufacturer": "Dell", "confidence": 75,
         "os_family": "Windows", "last_seen": "2026-04-01T12:00:00"},
    ]
    gateways = [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.1", "source": "dhcp_server"}]
    result = build_topology_graph(devices=devices, gateways=gateways, arp_entries=[], lldp_neighbors=[])

    tiers = {n["id"]: n["tier"] for n in result["nodes"] if "tier" in n and n["id"] not in ("internet",) and not n["id"].startswith("subnet:")}
    assert tiers["aa:bb:cc:dd:ee:ff"] == "gateway"
    assert tiers["11:22:33:44:55:66"] == "infrastructure"
    assert tiers["33:44:55:66:77:88"] == "client"


def test_wireless_clients_fallback_to_gateway():
    """Wireless clients must connect to gateway when no APs or switches exist."""
    devices = [
        {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "router", "ip_v4": "192.168.1.1",
         "device_type": "router", "manufacturer": "Google", "confidence": 90,
         "os_family": "Linux", "last_seen": "2026-04-01T12:00:00"},
        {"mac": "11:22:33:44:55:66", "hostname": "phone", "ip_v4": "192.168.1.50",
         "device_type": "phone", "manufacturer": "Apple", "confidence": 75,
         "os_family": "iOS", "last_seen": "2026-04-01T12:00:00",
         "connection_type": "wireless"},
        {"mac": "22:33:44:55:66:77", "hostname": "iot-sensor", "ip_v4": "192.168.1.60",
         "device_type": "iot", "manufacturer": "Expressif", "confidence": 60,
         "os_family": None, "last_seen": "2026-04-01T12:00:00",
         "connection_type": "wireless"},
    ]
    gateways = [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.1", "source": "dhcp_server"}]
    result = build_topology_graph(devices=devices, gateways=gateways, arp_entries=[], lldp_neighbors=[])

    # Both wireless clients must have edges to the gateway
    client_edges = [e for e in result["edges"] if e["target"] in ("11:22:33:44:55:66", "22:33:44:55:66:77")]
    assert len(client_edges) == 2
    for edge in client_edges:
        assert edge["source"] == "aa:bb:cc:dd:ee:ff"


def test_internet_node_always_present():
    result = build_topology_graph(devices=[], gateways=[], arp_entries=[], lldp_neighbors=[])
    internet = [n for n in result["nodes"] if n["id"] == "internet"]
    assert len(internet) == 1
    assert internet[0]["type"] == "internet"
    assert internet[0]["tier"] == "internet"
