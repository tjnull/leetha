import { useState, useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  fetchDevices, fetchAlerts, fetchStats,
  fetchActivityStats, fetchProtocolStats, fetchAlertTrend,
  fetchNewDevicesTimeline, fetchTopConnections,
  acknowledgeAlert, type Device,
  authHeaders,
} from "@/lib/api";
import { StatCard } from "@/components/shared/StatCard";
import { DeviceDrawer } from "@/components/shared/DeviceDrawer";
import { getDeviceTypeColor } from "@/lib/constants";
// cn removed — not used on this page
import { Monitor, Bell, Radio, Layers, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { WsStatus, WsMessage } from "@/hooks/use-websocket";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, BarChart, Bar,
} from "recharts";

interface DashboardProps {
  wsStatus: WsStatus;
  subscribe: (handler: (msg: WsMessage) => void) => () => void;
}

// --- Protocol colors for pie chart ---
const PROTO_COLORS: Record<string, string> = {
  arp: "#00e5ff", tcp_syn: "#448aff", dhcpv4: "#69f0ae", dhcpv6: "#4caf50",
  mdns: "#ffd740", dns: "#ffca28", ssdp: "#ea80fc", netbios: "#ff9100",
  tls: "#ce93d8", icmpv6: "#26c6da", ip_observed: "#64748b",
  http_useragent: "#f87171", dns_answer: "#38bdf8", banner: "#bdbdbd",
};

const PIE_FALLBACK_COLORS = ["#3b82f6", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6", "#ec4899", "#06b6d4", "#84cc16"];

function getProtoColor(proto: string, index: number): string {
  return PROTO_COLORS[proto] ?? PIE_FALLBACK_COLORS[index % PIE_FALLBACK_COLORS.length] ?? "#64748b";
}

// --- Helpers ---

function formatTimeAgo(ts: string | null): string {
  if (!ts) return "--";
  try {
    const diff = Date.now() - new Date(ts).getTime();
    if (diff < 60000) return "just now";
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return `${Math.floor(diff / 86400000)}d ago`;
  } catch { return ts; }
}

function confColor(c: number): string {
  if (c >= 80) return "hsl(var(--success))"; if (c >= 50) return "hsl(var(--warning))"; return "hsl(var(--destructive))";
}

function buildHourlyData(counts: number[]): Array<{ hour: string; value: number }> {
  return counts.map((v, i) => ({
    hour: `${i.toString().padStart(2, "0")}:00`,
    value: v,
  }));
}

// --- Custom Recharts tooltip ---

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ value: number }>; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg bg-card border border-border px-3 py-2 text-xs shadow-lg">
      <div className="text-muted-foreground">{label}</div>
      <div className="font-semibold">{payload[0]?.value?.toLocaleString()}</div>
    </div>
  );
}

// ═══════════════════════════════════════════
//  Main Dashboard
// ═══════════════════════════════════════════

export default function Dashboard({ wsStatus, subscribe }: DashboardProps) {
  const queryClient = useQueryClient();
  const [drawerMac, setDrawerMac] = useState<string | null>(null);

  // --- Queries ---
  const { data: statsData, isError: statsError } = useQuery({ queryKey: ["stats"], queryFn: fetchStats, staleTime: 15000, refetchInterval: 30000 });
  const { data: recentDevices } = useQuery({ queryKey: ["dashboard-recent-devices"], queryFn: () => fetchDevices({ sort: "first_seen", order: "desc", per_page: 10, raw: true }), staleTime: 15000, refetchInterval: 30000 });
  const { data: alerts = [] } = useQuery({ queryKey: ["dashboard-alerts"], queryFn: () => fetchAlerts(), staleTime: 15000, refetchInterval: 30000 });
  const { data: activityStats } = useQuery({ queryKey: ["stats-activity"], queryFn: fetchActivityStats, staleTime: 30000, refetchInterval: 30000 });
  const { data: protoStats } = useQuery({ queryKey: ["stats-protocols"], queryFn: fetchProtocolStats, staleTime: 30000, refetchInterval: 30000 });
  const { data: alertTrend } = useQuery({ queryKey: ["stats-alert-trend"], queryFn: fetchAlertTrend, staleTime: 60000, refetchInterval: 60000 });
  const { data: newDevices } = useQuery({ queryKey: ["stats-new-devices"], queryFn: fetchNewDevicesTimeline, staleTime: 30000, refetchInterval: 30000 });
  const { data: topConns } = useQuery({ queryKey: ["stats-top-connections"], queryFn: fetchTopConnections, staleTime: 60000, refetchInterval: 60000 });

  // --- WS: alert + finding toasts + device updates ---
  useEffect(() => {
    return subscribe((msg) => {
      if (msg.alerts && msg.alerts.length > 0) {
        for (const a of msg.alerts) {
          const severity = (a.severity as string) ?? "info";
          const message = (a.message as string) ?? "";
          if (severity === "critical" || severity === "high") toast.error(message);
          else if (severity === "warning") toast.warning(message);
          else toast.info(message);
        }
      }
      if (msg.type === "finding_created" && msg.finding) {
        const f = msg.finding;
        const severity = f.severity ?? "info";
        if (severity === "critical" || severity === "high") toast.error(f.message);
        else if (severity === "warning") toast.warning(f.message);
        else toast.info(f.message);
        queryClient.invalidateQueries({ queryKey: ["dashboard-alerts"] });
        queryClient.invalidateQueries({ queryKey: ["stats"] });
      }
      if (msg.device) {
        queryClient.invalidateQueries({ queryKey: ["stats"] });
        queryClient.invalidateQueries({ queryKey: ["dashboard-recent-devices"] });
      }
    });
  }, [subscribe, queryClient]);

  // --- Derived ---
  const deviceCount = statsData?.device_count ?? 0;
  const alertCount = statsData?.alert_count ?? 0;
  const devices = recentDevices?.devices ?? [];
  const recentAlerts = alerts.slice(0, 5);
  const hourlyData = buildHourlyData(activityStats?.hourly_counts ?? []);
  const newDeviceData = buildHourlyData(newDevices?.hourly_counts ?? []);
  const alertTrendData = buildHourlyData(alertTrend?.hourly_counts ?? []);
  const protocols = protoStats?.protocols ?? [];
  const connections = topConns?.connections ?? [];

  const handleDismiss = async (id: number) => {
    await acknowledgeAlert(id);
    queryClient.invalidateQueries({ queryKey: ["dashboard-alerts"] });
    queryClient.invalidateQueries({ queryKey: ["stats"] });
  };

  return (
    <div className="space-y-4">
      {statsError && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          Unable to connect to backend. Make sure leetha is running.
        </div>
      )}
      {/* Row 1: Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard icon={Monitor} label="Hosts Identified" value={deviceCount.toLocaleString()} sub="identified on the wire" accent="primary" />
        <StatCard icon={Bell} label="Active Findings" value={alertCount} sub={alertCount > 0 ? "pending review" : "all clear"} accent={alertCount > 0 ? "destructive" : "success"} />
        <StatCard icon={Radio} label="Capture Engine" value={wsStatus === "connected" ? "Active" : "Inactive"} sub="monitoring adapters" accent="success" />
        <StatCard icon={Layers} label="Protocols" value={protocols.length} sub="detected in last 24h" accent="warning" />
      </div>

      {/* Row 2: 24-Hour Activity (full width area chart) */}
      <div className="rounded-xl bg-card border border-border p-4">
        <h3 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3">24-Hour Packet Activity</h3>
        <div className="h-40">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={hourlyData}>
              <defs>
                <linearGradient id="activityGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="hour" tick={{ fontSize: 10, fill: "#71717a" }} tickLine={false} axisLine={false} interval={3} />
              <YAxis tick={{ fontSize: 10, fill: "#71717a" }} tickLine={false} axisLine={false} width={35} />
              <Tooltip content={<ChartTooltip />} />
              <Area type="monotone" dataKey="value" stroke="#3b82f6" strokeWidth={2} fill="url(#activityGrad)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Row 3: New Devices Timeline (full width bar chart) */}
      <div className="rounded-xl bg-card border border-border p-4">
        <h3 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3">New Hosts Discovered (24h)</h3>
        <div className="h-28">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={newDeviceData}>
              <XAxis dataKey="hour" tick={{ fontSize: 10, fill: "#71717a" }} tickLine={false} axisLine={false} interval={3} />
              <YAxis tick={{ fontSize: 10, fill: "#71717a" }} tickLine={false} axisLine={false} width={35} allowDecimals={false} />
              <Tooltip content={<ChartTooltip />} />
              <Bar dataKey="value" fill="#10b981" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Row 4: Protocol Distribution + Alert Trend */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Protocol Distribution (pie chart) */}
        <div className="rounded-xl bg-card border border-border p-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3">Protocol Distribution (24h)</h3>
          <div className="flex items-center gap-4">
            <div className="w-40 h-40 shrink-0">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={protocols.map((p) => ({ name: p.protocol, value: p.count }))}
                    cx="50%" cy="50%"
                    innerRadius={35} outerRadius={65}
                    paddingAngle={2}
                    dataKey="value"
                    stroke="none"
                  >
                    {protocols.map((p, i) => (
                      <Cell key={p.protocol} fill={getProtoColor(p.protocol, i)} />
                    ))}
                  </Pie>
                  <Tooltip formatter={(value) => Number(value).toLocaleString()} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="flex-1 space-y-1 overflow-hidden">
              {protocols.slice(0, 8).map((p, i) => {
                const total = protocols.reduce((s, x) => s + x.count, 0) || 1;
                const pct = ((p.count / total) * 100).toFixed(0);
                return (
                  <div key={p.protocol} className="flex items-center gap-2 text-xs">
                    <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: getProtoColor(p.protocol, i) }} />
                    <span className="flex-1 truncate text-muted-foreground">{p.protocol.replace("_", " ")}</span>
                    <span className="font-semibold tabular-nums">{p.count.toLocaleString()}</span>
                    <span className="text-muted-foreground/60 w-8 text-right">{pct}%</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Alert Trend (line chart) */}
        <div className="rounded-xl bg-card border border-border p-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3">Alert Trend (24h)</h3>
          <div className="h-40">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={alertTrendData}>
                <defs>
                  <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="hour" tick={{ fontSize: 10, fill: "#71717a" }} tickLine={false} axisLine={false} interval={3} />
                <YAxis tick={{ fontSize: 10, fill: "#71717a" }} tickLine={false} axisLine={false} width={35} allowDecimals={false} />
                <Tooltip content={<ChartTooltip />} />
                <Area type="monotone" dataKey="value" stroke="transparent" fill="url(#alertGrad)" />
                <Line type="monotone" dataKey="value" stroke="#ef4444" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Row 5: Recently Discovered + Top Connections */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Recently Discovered */}
        <div className="rounded-xl bg-card border border-border p-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3">
            Recently Identified <span className="font-normal text-muted-foreground/60">(latest 10)</span>
          </h3>
          {devices.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
              <Monitor size={24} className="mb-2 opacity-30" />
              <p className="text-xs">No hosts identified yet</p>
            </div>
          ) : (
            <div className="space-y-0.5">
              {devices.map((d: Device) => {
                const mac = d.primary_mac || d.mac;
                return (
                  <button key={mac} onClick={() => setDrawerMac(mac)}
                    className="w-full flex items-start gap-3 px-3 py-2.5 rounded-lg hover:bg-primary/[0.04] transition-colors text-left">
                    <span className="w-2 h-2 rounded-full shrink-0 mt-1.5" style={{ background: getDeviceTypeColor(d.device_type) }} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="font-data text-xs text-foreground">{mac}</span>
                        {d.is_randomized_mac && <span className="text-[8px] font-bold px-1 rounded bg-purple-500/15 text-purple-400">R</span>}
                        <span className="text-xs text-muted-foreground ml-auto">{d.manufacturer || "Unknown"}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        {d.ip_v4 && <span className="font-data text-[11px] text-muted-foreground">{d.ip_v4}</span>}
                        {d.ip_v6 && <span className="font-data text-[10px] text-muted-foreground/60 truncate max-w-[200px]" title={d.ip_v6}>{d.ip_v6}</span>}
                        {!d.ip_v4 && !d.ip_v6 && <span className="text-[11px] text-muted-foreground/40">No IP</span>}
                      </div>
                    </div>
                    <div className="flex flex-col items-end shrink-0">
                      <span className="text-[11px] font-semibold" style={{ color: confColor(d.confidence) }}>{d.confidence}%</span>
                      <span className="text-[10px] text-muted-foreground/50">{formatTimeAgo(d.first_seen)}</span>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Top Connections */}
        <div className="rounded-xl bg-card border border-border p-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3">
            Top Connections <span className="font-normal text-muted-foreground/60">(24h)</span>
          </h3>
          {connections.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
              <ArrowRight size={24} className="mb-2 opacity-30" />
              <p className="text-xs">No connection data yet</p>
            </div>
          ) : (
            <div className="space-y-0.5">
              {connections.slice(0, 10).map((c, i) => {
                const maxCount = connections[0]?.count ?? 1;
                const pct = (c.count / maxCount) * 100;
                return (
                  <div key={`${c.src}-${c.dst}-${i}`} className="flex items-center gap-2 px-3 py-1.5 rounded-lg hover:bg-secondary/30 transition-colors text-xs">
                    <span className="font-data text-foreground w-28 truncate">{c.src}</span>
                    <ArrowRight size={12} className="text-muted-foreground/40 shrink-0" />
                    <span className="font-data text-foreground w-28 truncate">{c.dst}</span>
                    <div className="flex-1 h-1.5 bg-muted/50 rounded-full overflow-hidden mx-2">
                      <div className="h-full rounded-full bg-primary/60" style={{ width: `${pct}%` }} />
                    </div>
                    <span className="font-semibold tabular-nums text-muted-foreground w-12 text-right">{c.count.toLocaleString()}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Row 6: Recent Alerts */}
      {recentAlerts.length > 0 && (
        <div className="rounded-xl bg-card border border-border p-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3">
            Recent Findings <span className="font-normal text-muted-foreground/60">({recentAlerts.length})</span>
          </h3>
          <div className="space-y-1">
            {recentAlerts.map((alert) => (
              <div key={alert.id} className="flex items-start justify-between px-3 py-2 rounded-lg hover:bg-secondary/30 transition-colors">
                <div className="space-y-0.5 min-w-0">
                  <div className="text-xs font-semibold uppercase">{alert.alert_type}</div>
                  <div className="text-xs text-muted-foreground truncate">{alert.message}</div>
                </div>
                <Button variant="ghost" size="sm" className="text-xs shrink-0 h-6" onClick={() => handleDismiss(alert.id)}>Dismiss</Button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Row 7: Network Visibility Report */}
      <NetworkVisibility />

      <DeviceDrawer mac={drawerMac} open={!!drawerMac} onClose={() => setDrawerMac(null)} />
    </div>
  );
}

// ── Network Visibility Report ──

interface SubnetVisibility {
  subnet: string;
  total_devices: number;
  visibility_level: string;
  visibility_score: number;
  protocols_seen: string[];
  coverage_summary: string[];
  rich_evidence: number;
  limited_evidence: number;
  no_evidence: number;
  gaps: Array<{ protocol: string; impact: string; fix: string }>;
}

function NetworkVisibility() {
  const { data } = useQuery<{ subnets: SubnetVisibility[] }>({
    queryKey: ["capture-visibility"],
    queryFn: () => fetch("/api/capture/visibility", { headers: authHeaders() }).then((r) => r.json()),
    staleTime: 60000,
    refetchInterval: 60000,
  });

  const subnets = data?.subnets ?? [];
  if (subnets.length === 0) return null;

  const levelColors: Record<string, { bg: string; text: string; dot: string }> = {
    excellent: { bg: "bg-green-500/10 border-green-500/20", text: "text-green-400", dot: "bg-green-500" },
    good: { bg: "bg-blue-500/10 border-blue-500/20", text: "text-blue-400", dot: "bg-blue-500" },
    partial: { bg: "bg-yellow-500/10 border-yellow-500/20", text: "text-yellow-400", dot: "bg-yellow-500" },
    limited: { bg: "bg-red-500/10 border-red-500/20", text: "text-red-400", dot: "bg-red-500" },
  };

  return (
    <div className="rounded-xl bg-card border border-border p-4">
      <h3 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-3">
        Network Visibility <span className="font-normal text-muted-foreground/60">by subnet</span>
      </h3>
      <div className="space-y-2">
        {subnets.map((sub) => {
          const colors = levelColors[sub.visibility_level] ?? levelColors["limited"]!;
          return (
            <div key={sub.subnet} className={`rounded-lg border px-4 py-3 ${colors.bg}`}>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-3">
                  <span className={`w-2.5 h-2.5 rounded-full ${colors.dot}`} />
                  <span className="font-data text-sm font-semibold">{sub.subnet}</span>
                  <span className="text-xs text-muted-foreground">{sub.total_devices} hosts</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`text-xs font-bold uppercase ${colors.text}`}>{sub.visibility_level}</span>
                </div>
              </div>

              {/* Protocol coverage chips */}
              <div className="flex flex-wrap gap-1.5 mb-2">
                {["L2", "DHCP", "mDNS", "SSDP", "TCP/TLS", "DNS"].map((proto) => {
                  const active = sub.coverage_summary.includes(proto);
                  return (
                    <span key={proto} className={`text-[10px] px-2 py-0.5 rounded-full border ${active ? "border-green-500/30 bg-green-500/10 text-green-400" : "border-border bg-secondary/30 text-muted-foreground/40"}`}>
                      {proto} {active ? "✓" : "✗"}
                    </span>
                  );
                })}
              </div>

              {/* Evidence breakdown */}
              <div className="flex items-center gap-4 text-[10px] text-muted-foreground mb-1">
                <span><span className="text-green-400 font-semibold">{sub.rich_evidence}</span> well-identified</span>
                <span><span className="text-yellow-400 font-semibold">{sub.limited_evidence}</span> limited</span>
                <span><span className="text-red-400 font-semibold">{sub.no_evidence}</span> unknown</span>
              </div>

              {/* Gaps */}
              {sub.gaps.length > 0 && (
                <div className="mt-2 space-y-1">
                  {sub.gaps.slice(0, 2).map((gap) => (
                    <div key={gap.protocol} className="text-[10px] text-muted-foreground">
                      <span className="text-yellow-400 font-medium">Missing {gap.protocol}:</span> {gap.impact}.{" "}
                      <span className="text-foreground/50">{gap.fix}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
