# Active Probing

Leetha can optionally transmit a small number of standard protocol messages to discover devices that do not generate enough passive traffic to be fingerprinted. These messages are crafted to look identical to what any ordinary workstation or phone emits when it joins a network -- no port scans, no vulnerability checks, no banner pulls.

**Probing is disabled by default.** You must opt in per adapter, acknowledging the operational security implications.

---

## Operational Security Impact

Activating probes causes Leetha to:

- Emit packets **using your adapter's source MAC and IP**
- Appear on the wire as routine device-to-network activity (ARP requests, mDNS service queries, DHCP discovers)
- Produce traffic volumes consistent with a single device performing normal network operations

Nothing about probed traffic resembles aggressive scanning. Network monitoring tools will not flag it as anomalous.

---

## ServiceProbe Architecture

Beyond the lightweight discovery probes listed below, Leetha includes 300+ `ServiceProbe` plugins for deep service identification. Each plugin implements a common interface:

```python
class ServiceProbe:
    def identify(self, conn: ServiceConnection) -> ServiceIdentity:
        ...
```

When probing is enabled and a host/port pair is discovered, Leetha:

1. Opens a `ServiceConnection` to the target endpoint
2. Selects the appropriate `ServiceProbe` plugin via auto-discovery (protocol detection based on port and initial handshake)
3. Calls `identify(conn)` which performs the minimum protocol exchange needed to extract identity information
4. Returns a `ServiceIdentity` containing service name, version string, and protocol-specific metadata (e.g. SSH host key type, SMB signing status, HTTP server header)

`ServiceConnection` wraps the raw socket with timeouts, TLS negotiation support, and connection lifecycle management. It provides three primary helper methods:

- `read()` -- Read data from the connection with a configurable timeout
- `write()` -- Send data to the target endpoint
- `exchange()` -- Send data and read the response in a single call (write + read)

Probes are rate-limited with a configurable cooldown between repeat visits to the same endpoint.

### Auto-Discovery

ServiceProbe plugins are automatically loaded from the plugins directory at startup -- no manual registration is needed. Each plugin declares the ports and protocols it handles, and the probe engine selects the appropriate plugin based on the target port and initial handshake bytes.

---

## Discovery Probes

These lightweight probes use standard broadcast/multicast protocols to flush out devices that have not yet generated passive traffic:

| Name | Protocol | Action | Needs Layer 2? |
|------|----------|--------|-----------------|
| `arp_sweep` | ARP | Transmits ARP who-has for every IP in the local subnet | Yes |
| `mdns_query` | mDNS | Sends a PTR query for `_services._dns-sd._udp.local` to 224.0.0.251 | Yes |
| `dhcp_discover` | DHCP | Broadcasts a DHCP Discover frame | Yes |
| `ssdp_search` | SSDP | Sends an M-SEARCH to 239.255.255.250:1900 | No |
| `netbios_query` | NetBIOS | Broadcasts a wildcard `*` name query | Yes |

### Adapter Compatibility

- **Physical and tap adapters**: All five probes are available (full Layer 2 access).
- **Tun adapters**: Only `ssdp_search` works (Layer 3 multicast only; no broadcast framing).

---

## Enabling and Running Probes

### From the Console

```
probe list                             # enumerate available probes
probe status                           # show per-adapter probe state
probe enable tap0                      # activate probing (prints OPSEC warning)
probe disable tap0                     # revert to passive-only
probe run tap0 mdns_query              # execute one probe
probe run tap0 all                     # execute every compatible probe
```

### From the React Dashboard

1. Navigate to the **Interfaces** view.
2. Select an adapter that is actively capturing.
3. Switch its mode from "Passive" to "Probe".
4. Open the probe selector and choose individual probes or "Run All".

### Via the REST API

```bash
# Switch an adapter to probe mode
curl -k -X PUT https://localhost/api/interfaces/tap0/probe-mode \
  -H 'Content-Type: application/json' \
  -d '{"mode": "probe-enabled"}'

# Query which probes are supported on an adapter
curl -k https://localhost/api/interfaces/tap0/probe-status

# Trigger specific probes
curl -k -X POST https://localhost/api/interfaces/tap0/probe \
  -H 'Content-Type: application/json' \
  -d '{"probes": ["arp_sweep", "ssdp_search"]}'

# Trigger every compatible probe
curl -k -X POST https://localhost/api/interfaces/tap0/probe \
  -H 'Content-Type: application/json' \
  -d '{"probes": ["all"]}'
```

---

## Response Processing

Replies to discovery probes arrive as ordinary network frames and flow through the same `PARSER_CHAIN` and `ProcessorRegistry` as passively captured traffic:

- ARP replies enter `parse_arp` -> OUI processor -> new host in HostRepository
- mDNS answers enter `parse_mdns` -> service classifier -> Evidence emitted
- DHCP Offers enter `parse_dhcpv4` -> Option 55/60 matchers -> OS/vendor Evidence
- SSDP responses enter `parse_ssdp` -> server header parser -> device type Evidence
- NetBIOS answers enter `parse_llmnr_netbios` -> hostname extractor -> Evidence

There is no separate ingestion path for probe responses. The probes simply inject stimulus that causes devices to reply, and those replies are handled by the standard pipeline.

---

## ServiceProbe Plugin Coverage

The 315 ServiceProbe plugins span the following protocol categories:

| Category | Examples |
|----------|----------|
| Remote access | SSH, Telnet, RDP, VNC |
| Web | HTTP, HTTPS, WebSocket |
| Databases | MySQL, PostgreSQL, MongoDB, Redis, Cassandra, Elasticsearch |
| Mail | SMTP, IMAP, POP3 |
| File transfer | FTP, SFTP, SCP, NFS, SMB/CIFS |
| DNS | DNS, mDNS, DoH, DoT |
| Directory | LDAP, Active Directory |
| Industrial / SCADA | Modbus, BACnet, EtherNet/IP, DNP3, S7comm |
| IoT | MQTT, CoAP, Zigbee gateways, UPnP |
| Containers | Docker API, Kubernetes API, container registries |
| Monitoring | SNMP, Prometheus, Zabbix, Nagios NRPE |
| Message queues | RabbitMQ, Kafka, ActiveMQ, ZeroMQ |
| VPN | OpenVPN, WireGuard, IPSec IKE |
| Printing | IPP, LPD, JetDirect |
| VoIP | SIP, H.323, MGCP |
| Remote desktop | X11, XDMCP, Citrix ICA |
| Network management | SNMP, NETCONF, RESTCONF |
| Time | NTP, PTP |
| Cache | Memcached, Redis, Varnish |
| Streaming | RTSP, RTMP, HLS |

Each plugin performs the minimum protocol exchange necessary to extract service identity. No vulnerability checks or exploitation attempts are made.
