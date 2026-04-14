import { useState, useEffect, useRef, memo, useCallback, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { authHeaders, importPcap, fetchStats, fetchProtocolStats, fetchTopConnections } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import {
  Pause, Play, Trash2, Terminal, Radio, Copy, Activity,
  Filter, Settings2, Download, Upload, Loader2,
} from "lucide-react";
import { toast } from "sonner";

// ═══════════════════════════════════════════
//  Types
// ═══════════════════════════════════════════

interface DeviceInfo {
  hostname?: string; manufacturer?: string; device_type?: string;
  os_family?: string; os_version?: string; confidence?: number;
  is_randomized_mac?: boolean; correlated_mac?: string;
}

interface ConsolePacket {
  protocol: string; timestamp: string; src_mac: string;
  src_ip: string | null; dst_mac: string | null; dst_ip: string | null;
  interface: string; network: string;
  data: Record<string, string | number | boolean | null>;
  device: DeviceInfo;
  matches: Array<Record<string, unknown>>;
  alerts: Array<{ alert_type: string; severity: string; message: string }>;
}

interface CaptureStatus {
  running: boolean;
  interfaces: Array<{ name: string; capture_mode: string; bpf_filter: string; promisc: boolean; probe_mode: string }>;
  default_bpf: string;
  scapy_command: string | null;
}

// ═══════════════════════════════════════════
//  Constants — MAX_VISIBLE controls how many
//  packets are rendered. The rest are kept in
//  memory for stats but NOT in the DOM.
// ═══════════════════════════════════════════

const PROTO_COLORS: Record<string, string> = {
  arp: "#00e5ff", tcp_syn: "#448aff", dhcpv4: "#69f0ae", dhcpv6: "#4caf50",
  mdns: "#ffd740", dns: "#ffca28", dns_answer: "#ffca28", ssdp: "#ea80fc",
  netbios: "#ff9100", tls: "#ce93d8", icmpv6: "#26c6da", banner: "#bdbdbd",
  http_useragent: "#f5f5f5", ip_observed: "#78909c", lldp: "#4dd0e1",
  cdp: "#4dd0e1", stp: "#80cbc4", snmp: "#a5d6a7",
};
const PROTO_LIST = ["tcp_syn", "dhcpv4", "dhcpv6", "mdns", "ssdp", "netbios", "tls", "arp", "dns", "icmpv6", "lldp", "http_useragent", "ip_observed"];
const MAX_PACKETS = 200;   // kept in memory for rendering
const MAX_VISIBLE = 50;    // rendered in DOM at once

// ── Module-level state: survives component unmount/remount ──
// The WebSocket and packet buffer persist when navigating away and back.
let _consoleWs: WebSocket | null = null;
let _consolePackets: ConsolePacket[] = [];
let _consoleTotalCount = 0;
let _consoleListeners = new Set<() => void>();

function _notifyConsoleListeners() {
  _consoleListeners.forEach((fn) => { try { fn(); } catch {} });
}

function _ensureConsoleWs() {
  if (_consoleWs && (_consoleWs.readyState === WebSocket.OPEN || _consoleWs.readyState === WebSocket.CONNECTING)) return;
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const token = localStorage.getItem("leetha_token");
  const wsUrl = `${proto}//${window.location.host}/ws/console`;
  const ws = token
    ? new WebSocket(wsUrl, [`auth.${token}`, "leetha-v1"])
    : new WebSocket(wsUrl);
  _consoleWs = ws;

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === "import_progress" || data.type === "import_complete" || data.type === "finding_created") return;
      if (!data.protocol) return;
      _consoleTotalCount += 1;
      _consolePackets.push(data);
      if (_consolePackets.length > MAX_PACKETS) _consolePackets = _consolePackets.slice(-MAX_PACKETS);
      _notifyConsoleListeners();
    } catch {}
  };

  ws.onclose = () => {
    _consoleWs = null;
    // Reconnect after 3s if there are active listeners
    setTimeout(() => { if (_consoleListeners.size > 0) _ensureConsoleWs(); }, 3000);
  };
}

const BPF_PRESETS: Array<{ name: string; description: string; filter: string }> = [
  { name: "Default (All Protocols)", description: "Capture all supported protocols", filter: "" },
  { name: "Web Traffic Only", description: "HTTP + HTTPS + DNS", filter: "tcp port 80 or tcp port 443 or udp port 53" },
  { name: "ARP Only", description: "ARP requests and replies", filter: "arp" },
  { name: "DHCP Only", description: "DHCPv4 + DHCPv6", filter: "udp port 67 or udp port 68 or udp port 546 or udp port 547" },
  { name: "DNS Only", description: "DNS + mDNS + LLMNR", filter: "udp port 53 or udp port 5353 or udp port 5355" },
  { name: "TLS Handshakes", description: "TLS Client Hello for fingerprinting", filter: "tcp port 443" },
  { name: "Discovery Protocols", description: "mDNS + SSDP + NetBIOS", filter: "udp port 5353 or udp port 1900 or udp port 137" },
  { name: "No ARP", description: "Everything except ARP", filter: "not arp" },
  { name: "Specific Host", description: "Traffic to/from a single IP", filter: "host 192.168.1.1" },
  { name: "Specific Subnet", description: "Traffic within a subnet", filter: "net 192.168.1.0/24" },
];

// ═══════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════

function esc(s: unknown): string { return s == null ? "" : String(s); }
function confClass(c: number): string { return c >= 80 ? "text-green-400" : c >= 50 ? "text-yellow-400" : "text-red-400"; }
function formatTime(ts: string): string { try { return new Date(ts).toTimeString().split(" ")[0] ?? ts; } catch { return ts; } }

function formatProtoDetails(protocol: string, data: Record<string, string | number | boolean | null>): Array<[string, string]> {
  if (!data) return [];
  const r: Array<[string, string]> = [];
  const d = (l: string, v: unknown) => { if (v !== undefined && v !== null && v !== "") r.push([l, esc(v)]); };
  switch (protocol) {
    case "arp": d("Op", data.op == 1 ? "Request" : data.op == 2 ? "Reply" : esc(data.op)); d("Target", data.dst_ip ?? data.target_ip); break;
    case "tcp_syn": d("TTL", data.ttl); d("Window", data.window_size); d("MSS", data.mss); d("Port", data.dst_port); break;
    case "dhcpv4": d("Type", data.message_type); d("Hostname", data.hostname); d("Opt55", data.opt55); d("Vendor", data.opt60); break;
    case "dhcpv6": d("Type", data.message_type); d("ORO", data.oro); d("DUID", data.duid); break;
    case "dns": d("Query", data.query_name); d("Type", data.query_type_name ?? data.query_type); break;
    case "mdns": d("Service", data.service_type); d("Name", data.name); break;
    case "ssdp": d("Server", data.server); d("ST", data.st); break;
    case "netbios": d(esc(data.query_type).toUpperCase() || "Query", data.query_name); break;
    case "tls": d("JA3", data.ja3_hash); d("JA4", data.ja4); d("SNI", data.sni); break;
    case "icmpv6": d("Type", esc(data.icmpv6_type).replace(/_/g, " ")); d("Target", data.target); break;
    case "banner": if (data.banner) d("Banner", esc(data.banner).substring(0, 80)); break;
  }
  return r;
}

// ═══════════════════════════════════════════
//  PacketEntry — memoized, lightweight
// ═══════════════════════════════════════════

const PacketEntry = memo(function PacketEntry({ packet }: { packet: ConsolePacket }) {
  const color = PROTO_COLORS[packet.protocol] ?? "#9ca3af";
  const dev = packet.device ?? ({} as DeviceInfo);
  const details = formatProtoDetails(packet.protocol, packet.data);
  const hasVerdict = dev.device_type || dev.manufacturer;
  const matches = packet.matches ?? [];

  return (
    <div className="px-3 py-2.5 border-b border-border/30 hover:bg-secondary/20 text-[13px]" style={{ borderLeftWidth: 3, borderLeftColor: color }}>
      {/* Row 1: Time + Protocol + Source → Destination + Verdict */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-muted-foreground font-mono text-xs w-[68px] shrink-0">{formatTime(packet.timestamp)}</span>
        <span className="font-semibold uppercase px-2 py-0.5 rounded text-[11px] tracking-wide min-w-[80px] text-center" style={{ background: color + "20", color, border: `1px solid ${color}40` }}>
          {packet.protocol.replace("_", " ")}
        </span>
        <span className="font-mono text-blue-400 text-xs">{packet.src_mac}</span>
        {packet.src_ip && <span className="text-foreground text-xs">{packet.src_ip}</span>}
        <span className="text-muted-foreground text-xs">&rarr;</span>
        {packet.dst_mac && packet.dst_mac !== "ff:ff:ff:ff:ff:ff" ? (
          <span className="font-mono text-blue-400/70 text-xs">{packet.dst_mac}</span>
        ) : null}
        {packet.dst_ip ? <span className="text-foreground text-xs">{packet.dst_ip}</span> : <span className="text-muted-foreground/50 text-xs">broadcast</span>}
        {/* Inline verdict badge */}
        {hasVerdict && (
          <span className="ml-auto flex items-center gap-1.5 text-xs">
            <span className="font-semibold text-foreground">{dev.device_type || "?"}</span>
            <span className="text-muted-foreground">|</span>
            <span className="text-foreground/80">{dev.manufacturer || "?"}</span>
            <span className="text-muted-foreground">|</span>
            <span className="text-foreground/80">{dev.os_family || "—"}</span>
            <span className={cn("font-mono font-semibold", confClass(dev.confidence ?? 0))}>{dev.confidence ?? 0}%</span>
          </span>
        )}
      </div>

      {/* Row 2: Hostname + Protocol details */}
      <div className="pl-[76px] mt-1 flex items-start gap-4 flex-wrap text-xs">
        {dev.hostname && (
          <span className="text-cyan-400 font-medium">{dev.hostname}</span>
        )}
        {details.length > 0 && (
          <div className="text-muted-foreground">
            {details.map(([l, v], i) => (
              <span key={i} className="mr-3">
                <span className="text-yellow-500/80">{l}:</span>{" "}
                <span className="text-foreground/90">{v}</span>
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Row 3: Evidence matches (if any, collapsed by default for common protocols) */}
      {matches.length > 0 && (
        <div className="pl-[76px] mt-1 text-xs text-muted-foreground">
          {matches.slice(0, 4).map((m: Record<string, unknown>, i: number) => (
            <span key={i} className="mr-3">
              <span className="text-cyan-500/70">{String(m.source || "?")}:</span>{" "}
              {m.manufacturer && <span>vendor=<span className="text-foreground/80">{String(m.manufacturer)}</span> </span>}
              {m.os_family && <span>os=<span className="text-foreground/80">{String(m.os_family)}</span> </span>}
              {m.device_type && <span>type=<span className="text-foreground/80">{String(m.device_type)}</span> </span>}
              <span className={confClass(Number(m.confidence ?? 0) > 1 ? Number(m.confidence) : Number(m.confidence ?? 0) * 100)}>({Math.round(Number(m.confidence ?? 0) > 1 ? Number(m.confidence) : Number(m.confidence ?? 0) * 100)}%)</span>
            </span>
          ))}
          {matches.length > 4 && <span className="text-muted-foreground/50">+{matches.length - 4} more</span>}
        </div>
      )}

      {/* Row 4: Alerts */}
      {(packet.alerts?.length ?? 0) > 0 && packet.alerts.map((a, i) => (
        <div key={i} className={cn("pl-[76px] mt-1 text-xs font-medium", a.severity === "critical" || a.severity === "high" ? "text-red-400" : "text-yellow-400")}>
          <span className="uppercase mr-1">▲ {a.severity}</span> {a.alert_type}: {a.message}
        </div>
      ))}

      {/* MAC randomization indicator */}
      {dev.is_randomized_mac && (
        <div className="pl-[76px] mt-0.5 text-xs text-purple-400">
          ⓡ Randomized MAC{dev.correlated_mac ? ` → real: ${dev.correlated_mac}` : ""}
        </div>
      )}
    </div>
  );
});

// ═══════════════════════════════════════════
//  Tab: Live Stream
// ═══════════════════════════════════════════

function LiveStreamTab({ packets, paused, setPaused, autoScroll, setAutoScroll, protocolFilter, setProtocolFilter, macFilter, setMacFilter, ipFilter, setIpFilter, textFilter, setTextFilter, onClear }: {
  packets: ConsolePacket[]; paused: boolean; setPaused: (v: boolean) => void;
  autoScroll: boolean; setAutoScroll: (v: boolean) => void;
  protocolFilter: string; setProtocolFilter: (v: string) => void;
  macFilter: string; setMacFilter: (v: string) => void;
  ipFilter: string; setIpFilter: (v: string) => void;
  textFilter: string; setTextFilter: (v: string) => void;
  onClear: () => void;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoScroll && scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [packets.length, autoScroll]);

  // Filter then take only last MAX_VISIBLE
  const visible = useMemo(() => {
    let p = packets;
    if (protocolFilter) p = p.filter((pk) => pk.protocol === protocolFilter);
    if (macFilter.trim()) { const q = macFilter.toLowerCase(); p = p.filter((pk) => pk.src_mac.toLowerCase().includes(q) || (pk.dst_mac?.toLowerCase().includes(q) ?? false)); }
    if (ipFilter.trim()) { const q = ipFilter.toLowerCase(); p = p.filter((pk) => (pk.src_ip?.includes(q) ?? false) || (pk.dst_ip?.includes(q) ?? false)); }
    if (textFilter.trim()) { const q = textFilter.toLowerCase(); p = p.filter((pk) => pk.protocol.includes(q) || pk.src_mac.toLowerCase().includes(q) || (pk.src_ip?.includes(q) ?? false) || Object.values(pk.data).some((v) => v != null && String(v).toLowerCase().includes(q))); }
    // Only render last N packets
    return p.slice(-MAX_VISIBLE);
  }, [packets, protocolFilter, macFilter, ipFilter, textFilter]);

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <div className="flex items-center gap-3 px-4 py-2 bg-card border border-border rounded-lg mb-2 flex-wrap shrink-0">
        <div className="flex items-center gap-2">
          <label className="text-xs text-muted-foreground">Protocol:</label>
          <select value={protocolFilter} onChange={(e) => setProtocolFilter(e.target.value)} className="bg-background border border-border text-foreground text-xs font-mono rounded px-2 py-1.5 focus:outline-none focus:border-primary">
            <option value="">All</option>
            {PROTO_LIST.map((p) => <option key={p} value={p}>{p.toUpperCase().replace("_", " ")}</option>)}
          </select>
        </div>
        <Input value={macFilter} onChange={(e) => setMacFilter(e.target.value)} placeholder="MAC..." className="w-[130px] h-7 text-xs font-mono bg-background" />
        <Input value={ipFilter} onChange={(e) => setIpFilter(e.target.value)} placeholder="IP..." className="w-[110px] h-7 text-xs font-mono bg-background" />
        <Input value={textFilter} onChange={(e) => setTextFilter(e.target.value)} placeholder="Search..." className="w-[120px] h-7 text-xs bg-background" />
        <label className="flex items-center gap-1.5 text-xs text-muted-foreground cursor-pointer"><input type="checkbox" checked={autoScroll} onChange={(e) => setAutoScroll(e.target.checked)} /> Auto-scroll</label>
        <div className="flex gap-2 ml-auto">
          <Button variant={paused ? "default" : "outline"} size="sm" className="h-7 text-xs" onClick={() => setPaused(!paused)}>
            {paused ? <Play size={12} className="mr-1" /> : <Pause size={12} className="mr-1" />}{paused ? "Resume" : "Pause"}
          </Button>
          <Button variant="outline" size="sm" className="h-7 text-xs" onClick={onClear}><Trash2 size={12} className="mr-1" /> Clear</Button>
        </div>
      </div>
      <div className="flex items-center justify-between px-1 mb-1 shrink-0">
        <div className="flex items-center gap-2">
          <Terminal size={12} className="text-muted-foreground" />
          <span className="text-xs text-muted-foreground">{visible.length} shown / {packets.length} total</span>
          {paused && <Badge variant="secondary" className="text-[10px]">PAUSED</Badge>}
        </div>
        <ProtocolStats packets={packets} />
      </div>
      <div ref={scrollRef} className="flex-1 overflow-y-auto bg-background rounded-lg border border-border font-mono text-[13px] min-h-0">
        {visible.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-muted-foreground"><Terminal size={28} className="mb-2 opacity-40" /><p className="text-sm">{packets.length === 0 ? "Waiting for packets..." : "No packets match filters"}</p></div>
        ) : visible.map((pkt, i) => <PacketEntry key={`${pkt.timestamp}-${i}`} packet={pkt} />)}
      </div>
    </div>
  );
}

const ProtocolStats = memo(function ProtocolStats({ packets }: { packets: ConsolePacket[] }) {
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const p of packets) c[p.protocol] = (c[p.protocol] ?? 0) + 1;
    return Object.entries(c).sort((a, b) => b[1] - a[1]);
  }, [packets]);
  if (counts.length === 0) return null;
  return (
    <div className="flex items-center gap-2 flex-wrap">
      {counts.map(([proto, count]) => (<div key={proto} className="flex items-center gap-1"><span className="w-2 h-2 rounded-full" style={{ background: PROTO_COLORS[proto] ?? "#9ca3af" }} /><span className="text-[10px] text-muted-foreground uppercase">{proto.replace("_", " ")}</span><span className="text-[10px] font-semibold" style={{ color: PROTO_COLORS[proto] ?? "#9ca3af" }}>{count}</span></div>))}
    </div>
  );
});

// ═══════════════════════════════════════════
//  Tab: Network Overview
// ═══════════════════════════════════════════

function NetworkOverviewTab({ packets, sessionPackets }: { packets: ConsolePacket[]; sessionPackets: number }) {
  const { data: statsData } = useQuery({
    queryKey: ["console-stats"], queryFn: fetchStats,
    staleTime: 10000, refetchInterval: 15000,
  });
  const { data: protoData } = useQuery({
    queryKey: ["console-protocols"], queryFn: fetchProtocolStats,
    staleTime: 10000, refetchInterval: 15000,
  });
  const { data: connData } = useQuery({
    queryKey: ["console-connections"], queryFn: fetchTopConnections,
    staleTime: 15000, refetchInterval: 30000,
  });

  const sessionStats = useMemo(() => {
    const srcIps: Record<string, number> = {};
    const dstIps: Record<string, number> = {};
    const srcMacs: Record<string, number> = {};
    const names: Record<string, string> = {};
    for (const p of packets) {
      srcMacs[p.src_mac] = (srcMacs[p.src_mac] ?? 0) + 1;
      if (p.src_ip) srcIps[p.src_ip] = (srcIps[p.src_ip] ?? 0) + 1;
      if (p.dst_ip) dstIps[p.dst_ip] = (dstIps[p.dst_ip] ?? 0) + 1;
      if (p.device?.hostname) names[p.src_mac] = p.device.hostname;
    }
    return {
      srcIps: Object.entries(srcIps).sort((a, b) => b[1] - a[1]).slice(0, 10),
      dstIps: Object.entries(dstIps).sort((a, b) => b[1] - a[1]).slice(0, 10),
      srcMacs: Object.entries(srcMacs).sort((a, b) => b[1] - a[1]).slice(0, 10),
      names,
    };
  }, [packets]);

  const protocols = protoData?.protocols ?? [];
  const totalSightings = protocols.reduce((s, p) => s + p.count, 0);
  const connections = connData?.connections ?? [];

  return (
    <div className="flex-1 overflow-y-auto p-1 space-y-4">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {([
          ["Packets (session)", sessionPackets, false],
          ["Total Sightings", totalSightings, false],
          ["Unique Hosts", statsData?.device_count ?? 0, false],
          ["Protocols", protocols.length, false],
        ] as const).map(([l, v, warn]) => (
          <div key={l} className="rounded-lg bg-card border border-border p-3">
            <div className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">{l}</div>
            <div className={cn("text-2xl font-bold mt-1", warn && (v as number) > 0 ? "text-destructive" : "")}>{v}</div>
          </div>
        ))}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <StatsCard title="Protocol Breakdown">{protocols.map((entry) => {
          const pct = totalSightings > 0 ? (entry.count / totalSightings) * 100 : 0;
          return (<div key={entry.protocol} className="flex items-center gap-3 mb-1.5"><span className="text-xs font-mono uppercase w-16" style={{ color: PROTO_COLORS[entry.protocol] ?? "#999" }}>{entry.protocol.replace("_", " ")}</span><div className="flex-1 h-1.5 bg-muted rounded-full"><div className="h-full rounded-full" style={{ width: `${pct}%`, background: PROTO_COLORS[entry.protocol] ?? "#999" }} /></div><span className="text-xs w-10 text-right">{entry.count}</span></div>);
        })}</StatsCard>
        <StatsCard title="Top Connections">{connections.length > 0 ? connections.map((c, i) => (<div key={i} className="flex justify-between text-xs mb-1 gap-2"><span className="font-data truncate">{c.src} &rarr; {c.dst}</span><span className="text-muted-foreground shrink-0">{c.count}</span></div>)) : <span className="text-xs text-muted-foreground">No connection data yet</span>}</StatsCard>
        <StatsCard title="Top Source IPs (session)">{sessionStats.srcIps.length > 0 ? sessionStats.srcIps.map(([ip, c]) => (<div key={ip} className="flex justify-between text-xs mb-1"><span className="font-data">{ip}</span><span className="text-muted-foreground">{c}</span></div>)) : <span className="text-xs text-muted-foreground">No packets captured this session</span>}</StatsCard>
        <StatsCard title="Top Destination IPs (session)">{sessionStats.dstIps.length > 0 ? sessionStats.dstIps.map(([ip, c]) => (<div key={ip} className="flex justify-between text-xs mb-1"><span className="font-data">{ip}</span><span className="text-muted-foreground">{c}</span></div>)) : <span className="text-xs text-muted-foreground">No packets captured this session</span>}</StatsCard>
        <StatsCard title="Top Source MACs (session)">{sessionStats.srcMacs.map(([mac, c]) => (<div key={mac} className="flex justify-between text-xs mb-1 gap-2"><div><span className="font-data">{mac}</span>{sessionStats.names[mac] && <span className="text-cyan-400 ml-2 text-[10px]">{sessionStats.names[mac]}</span>}</div><span className="text-muted-foreground shrink-0">{c}</span></div>))}</StatsCard>
      </div>
    </div>
  );
}

function StatsCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (<div className="rounded-lg bg-card border border-border p-4"><h3 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3">{title}</h3>{children}</div>);
}

// ═══════════════════════════════════════════
//  Tab: Filter Builder
// ═══════════════════════════════════════════

function FilterBuilderTab({ captureStatus }: { captureStatus: CaptureStatus | undefined }) {
  const currentBpf = captureStatus?.interfaces[0]?.bpf_filter ?? captureStatus?.default_bpf ?? "";
  const [draft, setDraft] = useState(currentBpf);

  const saveBpf = async () => {
    try {
      // Save to settings AND restart capture immediately
      await fetch("/api/settings", { method: "PUT", headers: authHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ bpf_filter: draft }) });
      const res = await fetch("/api/capture/restart", { method: "POST", headers: authHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ bpf_filter: draft }) });
      const data = await res.json();
      if (data.status === "restarted") {
        toast.success(`Filter applied: ${data.bpf_filter}`);
      } else {
        toast.success("Filter saved. Restart capture to apply.");
      }
    } catch { toast.error("Failed to apply filter"); }
  };

  return (
    <div className="flex-1 overflow-y-auto p-1 space-y-5">
      <div className="rounded-lg bg-card border border-border p-5">
        <h3 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3">Current Active Filter</h3>
        <div className="flex flex-wrap gap-1.5 mb-3">
          {(currentBpf || "none").split(/ or /i).map((t, i) => (<span key={i} className="text-[11px] font-mono px-2 py-1 rounded bg-yellow-400/10 text-yellow-400 border border-yellow-400/20">{t.trim()}</span>))}
        </div>
        <Button variant="outline" size="sm" className="text-xs gap-1" onClick={() => { navigator.clipboard.writeText(currentBpf); toast.success("Copied"); }}><Copy size={12} /> Copy</Button>
      </div>
      <div className="rounded-lg bg-card border border-border p-5">
        <h3 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3">Edit Filter</h3>
        <textarea value={draft} onChange={(e) => setDraft(e.target.value)} rows={3} className="w-full rounded border border-border bg-background px-3 py-2 text-sm font-mono text-yellow-400 focus:outline-none focus:ring-1 focus:ring-primary resize-vertical mb-3" placeholder="e.g. tcp port 443 or arp" />
        <div className="flex items-center gap-3">
          <Button size="sm" className="text-xs" onClick={saveBpf}>Save &amp; Apply on Restart</Button>
          <Button variant="outline" size="sm" className="text-xs" onClick={() => setDraft(currentBpf)}>Reset</Button>
        </div>
      </div>
      <div className="rounded-lg bg-card border border-border p-5">
        <h3 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3">Presets</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {BPF_PRESETS.map((p) => (<button key={p.name} onClick={() => setDraft(p.filter || captureStatus?.default_bpf || "")} className="text-left rounded-lg bg-secondary/30 border border-border hover:border-primary/50 p-3 transition-colors"><div className="text-sm font-medium">{p.name}</div><div className="text-[11px] text-muted-foreground mt-0.5">{p.description}</div><code className="text-[10px] font-mono text-yellow-400/70 mt-1 block truncate">{p.filter || "(default)"}</code></button>))}
        </div>
      </div>
      <div className="rounded-lg bg-card border border-border p-5">
        <h3 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3">BPF Reference</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-1.5 text-xs">
          {[["host 1.2.3.4", "Traffic to/from IP"], ["net 10.0.0.0/8", "Subnet"], ["port 443", "Port"], ["tcp port 80", "TCP only"], ["udp port 53", "UDP only"], ["src host 1.2.3.4", "Source only"], ["dst port 22", "Dest port"], ["ether host aa:bb:...", "MAC filter"], ["arp", "ARP only"], ["not port 22", "Exclude"], ["icmp or icmp6", "ICMP"], ["tcp[tcpflags] & tcp-syn != 0", "SYN packets"]].map(([e, d]) => (<div key={e} className="flex gap-2"><code className="font-mono text-green-400 shrink-0">{e}</code><span className="text-muted-foreground">{d}</span></div>))}
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════
//  Tab: Capture Config
// ═══════════════════════════════════════════

function CaptureConfigTab({ captureStatus }: { captureStatus: CaptureStatus | undefined }) {
  if (!captureStatus) return <p className="text-sm text-muted-foreground p-4">Loading...</p>;
  const iface = captureStatus.interfaces[0];
  const bpf = iface?.bpf_filter ?? captureStatus.default_bpf;
  const names = captureStatus.interfaces.map((i) => i.name);
  const scapyIface = names.length === 1 ? `"${names[0]}"` : `[${names.map((n) => `"${n}"`).join(", ")}]`;
  const copyScapy = () => { navigator.clipboard.writeText(`sniff(iface=${scapyIface}, filter="${bpf}", prn=callback, promisc=${iface?.promisc ? "True" : "False"}, store=0)`); toast.success("Copied"); };

  return (
    <div className="flex-1 overflow-y-auto p-1 space-y-5">
      <div className="rounded-lg bg-card border border-border p-5">
        <div className="flex items-center gap-3 mb-4">
          <Radio size={16} className={captureStatus.running ? "text-success animate-pulse" : "text-muted-foreground"} />
          <span className="text-sm font-semibold">{captureStatus.running ? "Capture Running" : "Capture Stopped"}</span>
        </div>
        {captureStatus.interfaces.map((i) => (
          <div key={i.name} className="rounded-lg bg-secondary/30 border border-border p-4 mb-2">
            <div className="grid grid-cols-[100px_1fr] gap-2 text-sm">
              <span className="text-xs text-muted-foreground">Interface</span><span className="font-data font-semibold">{i.name}</span>
              <span className="text-xs text-muted-foreground">Mode</span><span className="font-data">{i.capture_mode}</span>
              <span className="text-xs text-muted-foreground">Promiscuous</span><span className={i.promisc ? "text-green-400" : "text-muted-foreground"}>{i.promisc ? "Yes" : "No"}</span>
              <span className="text-xs text-muted-foreground">Probe</span><span className="font-data">{i.probe_mode}</span>
            </div>
          </div>
        ))}
      </div>
      <div className="rounded-lg bg-card border border-border p-5">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-xs font-bold uppercase tracking-widest text-muted-foreground">Scapy Command</h3>
          <Button variant="outline" size="sm" className="text-xs gap-1" onClick={copyScapy}><Copy size={12} /> Copy</Button>
        </div>
        <pre className="rounded border border-border bg-background p-4 font-mono text-sm leading-loose overflow-x-auto">
          <span className="text-blue-400">sniff</span>{"(\n"}
          {"  iface="}<span className="text-green-400">{scapyIface}</span>{",\n"}
          {"  filter="}<span className="text-yellow-400">&quot;...&quot;</span>{",\n"}
          {"  prn="}<span className="text-foreground">callback</span>{",\n"}
          {"  promisc="}<span className={iface?.promisc ? "text-green-400" : "text-red-400"}>{iface?.promisc ? "True" : "False"}</span>{",\n"}
          {"  store="}<span className="text-foreground">0</span>{"\n)"}
        </pre>
      </div>
      <div className="rounded-lg bg-card border border-border p-5">
        <h3 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3">Active BPF Filter</h3>
        <div className="flex flex-wrap gap-1.5">
          {bpf.split(/ or /i).map((t, i) => (<span key={i} className="text-[11px] font-mono px-2 py-1 rounded bg-yellow-400/10 text-yellow-400 border border-yellow-400/20">{t.trim()}</span>))}
        </div>
      </div>

      {/* PCAP Export */}
      <div className="rounded-lg bg-card border border-border p-5">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-1">Packet Export</h3>
            <p className="text-xs text-muted-foreground">Download captured packets as PCAP for analysis in Wireshark or other tools.</p>
          </div>
          <Button variant="outline" size="sm" className="text-xs gap-1.5" asChild>
            <a href="/api/capture/export" download="leetha-capture.pcap">
              <Download size={13} /> Export PCAP
            </a>
          </Button>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════
//  Main Console Page
// ═══════════════════════════════════════════

const TABS = [
  { id: "stream", label: "Live Stream", icon: Terminal },
  { id: "overview", label: "Network Overview", icon: Activity },
  { id: "filters", label: "Filter Builder", icon: Filter },
  { id: "capture", label: "Capture Config", icon: Settings2 },
] as const;
type TabId = (typeof TABS)[number]["id"];

export default function Console() {
  const [activeTab, setActiveTab] = useState<TabId>("stream");
  const packetsRef = useRef<ConsolePacket[]>([]);
  const [packets, setPackets] = useState<ConsolePacket[]>([]);
  const [paused, setPaused] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [protocolFilter, setProtocolFilter] = useState("");
  const [macFilter, setMacFilter] = useState("");
  const [ipFilter, setIpFilter] = useState("");
  const [textFilter, setTextFilter] = useState("");
  const [importing, setImporting] = useState(false);
  const [importProgress, setImportProgress] = useState<{ filename: string; processed: number; total: number } | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const pausedRef = useRef(false);
  const renderTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  pausedRef.current = paused;

  const { data: captureStatus } = useQuery<CaptureStatus>({
    queryKey: ["capture-status"],
    queryFn: () => fetch("/api/capture/status", { headers: authHeaders() }).then((r) => r.json()),
    refetchInterval: 30000,
  });

  // Subscribe to the module-level WebSocket (persists across navigation)
  useEffect(() => {
    _ensureConsoleWs();
    // Sync initial state from module-level buffer
    packetsRef.current = [..._consolePackets];
    setPackets([..._consolePackets]);

    const flush = () => {
      if (!renderTimer.current) {
        renderTimer.current = setTimeout(() => {
          renderTimer.current = null;
          if (!pausedRef.current) {
            packetsRef.current = [..._consolePackets];
            setPackets([..._consolePackets]);
          }
        }, 500);
      }
    };
    _consoleListeners.add(flush);
    return () => {
      _consoleListeners.delete(flush);
      if (renderTimer.current) clearTimeout(renderTimer.current);
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleClear = useCallback(() => {
    _consolePackets = [];
    _consoleTotalCount = 0;
    packetsRef.current = [];
    setPackets([]);
  }, []);

  const handleFileUpload = async (file: File) => {
    setImporting(true);
    try {
      const result = await importPcap(file);
      toast.success(`Importing ${result.filename}...`);
    } catch (e: any) {
      toast.error(e.message || "Import failed");
    } finally {
      setImporting(false);
    }
  };

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) handleFileUpload(file);
  }, []);

  return (
    <div
      className="flex flex-col h-full -m-6"
      onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
      onDrop={handleDrop}
    >
      <div className="flex items-center border-b border-border mb-3 shrink-0">
        {TABS.map((tab) => {
          const Icon = tab.icon;
          return (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)} className={cn("flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px", activeTab === tab.id ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground")}>
              <Icon size={15} />{tab.label}
              {tab.id === "stream" && packets.length > 0 && <span className="text-[10px] text-muted-foreground">{packets.length}</span>}
            </button>
          );
        })}
      </div>
      {/* PCAP Import Bar */}
      <div className={cn("flex items-center gap-2 mb-2 px-1 py-1.5 rounded-lg border border-dashed transition-colors", dragOver ? "border-primary bg-primary/10" : "border-transparent")}>
        <input
          ref={fileInputRef}
          type="file"
          accept=".pcap,.pcapng,.cap"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handleFileUpload(file);
            e.target.value = "";
          }}
        />
        <Button
          variant="outline"
          size="sm"
          className="h-7 text-xs gap-1.5"
          onClick={() => fileInputRef.current?.click()}
          disabled={importing}
        >
          <Upload size={12} />
          {importing ? "Importing..." : "Import PCAP"}
        </Button>
        <span className="text-xs text-muted-foreground">
          {dragOver ? "Drop PCAP file here" : "or drag & drop .pcap / .pcapng / .cap"}
        </span>
        {importProgress && (
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Loader2 className="h-3 w-3 animate-spin" />
            <span>
              Importing {importProgress.filename}: {importProgress.processed.toLocaleString()}/{importProgress.total.toLocaleString()} packets
            </span>
          </div>
        )}
      </div>
      {activeTab === "stream" && <LiveStreamTab packets={packets} paused={paused} setPaused={setPaused} autoScroll={autoScroll} setAutoScroll={setAutoScroll} protocolFilter={protocolFilter} setProtocolFilter={setProtocolFilter} macFilter={macFilter} setMacFilter={setMacFilter} ipFilter={ipFilter} setIpFilter={setIpFilter} textFilter={textFilter} setTextFilter={setTextFilter} onClear={handleClear} />}
      {activeTab === "overview" && <NetworkOverviewTab packets={packets} sessionPackets={_consoleTotalCount} />}
      {activeTab === "filters" && <FilterBuilderTab captureStatus={captureStatus} />}
      {activeTab === "capture" && <CaptureConfigTab captureStatus={captureStatus} />}
    </div>
  );
}
