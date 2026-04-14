"""Maps well-known TCP service ports to service names.

Used by the passive banner capture engine to decide which connections
to watch and to label captured banners with their service type.
"""

from __future__ import annotations

# Service name → list of ports
_SERVICE_PORTS: dict[str, list[int]] = {
    # Server-speaks-first
    "SSH": [22],
    "FTP": [21],
    "Telnet": [23],
    "SMTP": [25, 587],
    "POP3": [110],
    "IMAP": [143],
    "VNC": [5900, 5901, 5902, 5903],
    "IRC": [6667, 6697],
    # Databases
    "MySQL": [3306],
    "PostgreSQL": [5432],
    "MSSQL": [1433],
    "MongoDB": [27017],
    "Redis": [6379],
    # SMB / RDP
    "SMB": [445, 139],
    "RDP": [3389],
    # Printers
    "IPP": [631],
    "JetDirect": [9100],
    "LPD": [515],
    # IoT / Messaging
    "MQTT": [1883, 8883],
    "AMQP": [5672],
    # VoIP / Streaming
    "SIP": [5060, 5061],
    "RTSP": [554, 7447, 8554],
    # UniFi Protect
    "UniFiProtect": [7443, 7444],
    # Directory
    "LDAP": [389, 636],
    # Databases
    "Cassandra": [9042],
    "Elasticsearch": [9200],
    # Security-relevant
    "DockerAPI": [2375, 2376],
    "KubernetesAPI": [6443],
    "SOCKS": [1080, 1081],
    "BGP": [179],
    "PPTP": [1723],
}

# Inverted index: port → service name
_PORT_TO_SERVICE: dict[int, str] = {}
for _svc, _ports in _SERVICE_PORTS.items():
    for _p in _ports:
        _PORT_TO_SERVICE[_p] = _svc

#: Set of all watched ports (for iteration / membership checks).
WATCHED_PORTS: frozenset[int] = frozenset(_PORT_TO_SERVICE)


def service_for_port(port: int) -> str | None:
    """Return the service name for *port*, or ``None`` if not watched."""
    return _PORT_TO_SERVICE.get(port)


def bpf_fragment() -> str:
    """Return a BPF filter fragment matching all watched ports.

    Example output: ``"tcp port 22 or tcp port 21 or ..."``
    """
    return " or ".join(f"tcp port {p}" for p in sorted(WATCHED_PORTS))
