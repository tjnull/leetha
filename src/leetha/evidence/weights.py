"""Canonical source-reliability weights shared across the fingerprint engine.

Every module that needs to look up how much to trust a particular evidence
source should import SOURCE_WEIGHTS from here.  This avoids the two-dict
divergence problem that previously existed between fingerprint/evidence.py
and evidence/engine.py.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Source reliability weights -- how much we trust each evidence source.
# Grouped by tier for readability but merged into a single dict at the end.
# ---------------------------------------------------------------------------

_TRUST_TIER_1 = {
    # Curated databases with broad coverage and high precision
    "mdns_exclusive": 0.90,
    "dhcp_server": 0.85,
    "huginn_device": 0.85,
    "active_probe": 0.85,
    "oui": 0.90,
    "dns_server": 0.50,
    "huginn_dhcp": 0.80,
    "huginn_mac": 0.85,
}

_TRUST_TIER_2 = {
    # Validated protocol-specific analysers
    "icmpv6": 0.60,
    "tcp": 0.65,
    "banner": 0.75,
    "banner_cache": 0.70,
    "http_useragent": 0.75,
    "dhcpv6": 0.75,
    "mdns": 0.70,
    "ssdp": 0.65,
    "ws_discovery": 0.85,
    "huginn_dhcp_vendor": 0.80,
    "ja4": 0.75,
    "tls_ja4": 0.75,
    "dns": 0.50,
    "dhcp_vendor": 0.80,
    "ja3": 0.75,
    "tls_ja3": 0.75,
}

_TRUST_TIER_3 = {
    # Complementary / lower-fidelity signals
    "mdns_txt": 0.75,
    "huginn_dhcpv6": 0.75,
    "huginn_dhcpv6_enterprise": 0.75,
    "mdns_service": 0.65,
    "netbios": 0.60,
    "hostname": 0.65,
    "dhcp": 0.80,
    "mdns_name": 0.60,
}

_TRUST_AI = {
    "ai_dns": 0.85,
    "ai_http_path": 0.80,
    "ai_port_hint": 0.55,
}

_TRUST_TIER_4 = {
    "tls_sni": 0.50,
    "ttl": 0.15,
    "ntp": 0.55,
    "dns_ntp_hint": 0.55,
    "tcp_syn_sig": 0.65,
    "ip_observed_port": 0.30,
    "tcp_syn_ttl": 0.50,
    "ip_observed_ttl": 0.35,
}

_TRUST_INFRASTRUCTURE = {
    "lldp": 0.95,
    "cdp": 0.95,
    "snmp": 0.90,
    "dhcpv4": 0.85,
    "dhcpv4_vendor": 0.85,
    "dhcpv4_fingerprint": 0.80,
    "dhcpv6_vendor": 0.85,
    "dhcpv6_oro": 0.75,
    "probe": 0.85,
    "tcp_syn": 0.70,
    "tls": 0.70,
    "dns_vendor": 0.55,
    "dns_behavioral": 0.60,
    "icmpv6_ra": 0.60,
    "stp": 0.50,
    "arp": 0.30,
    "ip_observed": 0.30,
    "http_host": 0.40,
    "dns_query": 0.45,
    "dns_answer": 0.50,
    "passive_banner": 0.85,
    "ssdp_server": 0.65,
    "ssdp_upnp": 0.65,
    "mdns_service_map": 0.70,
    "mdns_srv": 0.85,
}

_TRUST_IOT_SCADA = {
    "modbus": 0.60,
    "bacnet": 0.65,
    "coap": 0.50,
    "mqtt": 0.55,
    "enip": 0.65,
    "dnp3": 0.75,
    "s7comm": 0.80,
    "opcua": 0.75,
    "goose": 0.85,
    "profinet": 0.80,
    "umas": 0.85,
}

_TRUST_NEW_PROTOCOLS = {
    "igmp": 0.35,
    "eap": 0.60,
    "stun": 0.45,
    "quic_sni": 0.60,
    "radius": 0.65,
    "upnp": 0.55,
    "apple_model": 0.90,
    "mdns_apple_model": 0.90,
    "manual": 0.99,
}

# Merged lookup -- public so other modules can inspect source weights
SOURCE_WEIGHTS: dict[str, float] = {
    **_TRUST_TIER_1,
    **_TRUST_TIER_2,
    **_TRUST_TIER_3,
    **_TRUST_AI,
    **_TRUST_TIER_4,
    **_TRUST_INFRASTRUCTURE,
    **_TRUST_IOT_SCADA,
    **_TRUST_NEW_PROTOCOLS,
}

FALLBACK_TRUST = 0.50
