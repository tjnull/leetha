"""Split protocol parsers returning CapturedPacket.

Each module handles a logical group of protocols. The PARSER_CHAIN
defines the order in which parsers are tried -- most specific first,
fallback last. A packet can match multiple parsers.

Backward-compatibility: this package also re-exports the old ParsedPacket
dataclass and all legacy parser functions so existing code that imports
from ``leetha.capture.protocols`` keeps working during the bridge period.
"""
# --- New CapturedPacket-returning parsers (used by PARSER_CHAIN) ---
from leetha.capture.protocols.arp import parse_arp as _new_parse_arp
from leetha.capture.protocols.dhcp import parse_dhcpv4 as _new_parse_dhcpv4
from leetha.capture.protocols.dhcp import parse_dhcpv6 as _new_parse_dhcpv6
from leetha.capture.protocols.dhcp import parse_dhcp_server as _new_parse_dhcp_server
from leetha.capture.protocols.dns import parse_dns as _new_parse_dns
from leetha.capture.protocols.dns import parse_dns_answer as _new_parse_dns_answer
from leetha.capture.protocols.tls import parse_tls_client_hello as _new_parse_tls_client_hello
from leetha.capture.protocols.http import parse_http_useragent as _new_parse_http_useragent
from leetha.capture.protocols.discovery import parse_mdns as _new_parse_mdns
from leetha.capture.protocols.discovery import parse_ssdp as _new_parse_ssdp
from leetha.capture.protocols.discovery import parse_llmnr_netbios as _new_parse_llmnr_netbios
from leetha.capture.protocols.infrastructure import parse_lldp as _new_parse_lldp
from leetha.capture.protocols.infrastructure import parse_cdp as _new_parse_cdp
from leetha.capture.protocols.infrastructure import parse_stp as _new_parse_stp
from leetha.capture.protocols.infrastructure import parse_snmp as _new_parse_snmp
from leetha.capture.protocols.fallback import parse_ip_observed as _new_parse_ip_observed
from leetha.capture.protocols.icmpv6 import parse_icmpv6 as _new_parse_icmpv6
from leetha.capture.protocols.ws_discovery import parse_ws_discovery as _new_parse_ws_discovery
from leetha.capture.protocols.ntp import parse_ntp as _new_parse_ntp
from leetha.capture.protocols.iot_scada import parse_modbus as _new_parse_modbus
from leetha.capture.protocols.iot_scada import parse_bacnet as _new_parse_bacnet
from leetha.capture.protocols.iot_scada import parse_coap as _new_parse_coap
from leetha.capture.protocols.iot_scada import parse_mqtt as _new_parse_mqtt
from leetha.capture.protocols.iot_scada import parse_enip as _new_parse_enip
from leetha.capture.protocols.tcp_syn import parse_tcp_syn as _new_parse_tcp_syn
from leetha.capture.protocols.banner import parse_service_banner as _new_parse_service_banner
from leetha.capture.protocols.igmp import parse_igmp as _new_parse_igmp
from leetha.capture.protocols.stun import parse_stun as _new_parse_stun
from leetha.capture.protocols.quic import parse_quic as _new_parse_quic
from leetha.capture.protocols.eap import parse_eap as _new_parse_eap
from leetha.capture.protocols.radius import parse_radius as _new_parse_radius
from leetha.capture.protocols.discovery import parse_upnp as _new_parse_upnp

# Ordered parser chain -- most specific first, fallback last
PARSER_CHAIN = [
    _new_parse_lldp, _new_parse_cdp, _new_parse_stp,
    _new_parse_eap,
    _new_parse_arp,
    _new_parse_dhcp_server, _new_parse_dhcpv4, _new_parse_dhcpv6,
    _new_parse_tcp_syn, _new_parse_tls_client_hello, _new_parse_quic,
    _new_parse_http_useragent,
    _new_parse_dns, _new_parse_dns_answer,
    _new_parse_mdns, _new_parse_ssdp, _new_parse_llmnr_netbios,
    _new_parse_ws_discovery,
    _new_parse_snmp,
    _new_parse_icmpv6,
    _new_parse_igmp,
    _new_parse_ntp,
    _new_parse_modbus, _new_parse_bacnet, _new_parse_coap,
    _new_parse_mqtt, _new_parse_enip,
    _new_parse_stun, _new_parse_radius, _new_parse_upnp,
    _new_parse_service_banner,
    _new_parse_ip_observed,
]

# ---------------------------------------------------------------------------
# Backward-compatibility re-exports from the old monolithic protocols.py
# These return ParsedPacket and are used by existing code and tests.
# ---------------------------------------------------------------------------
from leetha.capture.protocols._legacy import (  # noqa: F401, E402
    ParsedPacket,
    parse_tcp_syn,
    parse_dhcpv4,
    parse_dhcpv6,
    parse_mdns,
    parse_arp,
    parse_ssdp,
    parse_llmnr_netbios,
    parse_tls_client_hello,
    parse_dns,
    parse_dns_answer,
    parse_icmpv6,
    parse_ip_observed,
    parse_http_useragent,
    _guess_initial_ttl,
)
