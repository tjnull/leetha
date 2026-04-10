import { useState, useMemo, useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { WsMessage } from "@/hooks/use-websocket";
import { toast } from "sonner";
import {
  fetchAttackSurface,
  fetchExclusions,
  addExclusion,
  removeExclusion,
  type AttackFinding,
  type AttackChain,
  type AttackExclusion,
  type ToolRecommendation,
  type AffectedDevice,
} from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { cn } from "@/lib/utils";
import {
  AlertTriangle,
  Info,
  ShieldAlert,
  Zap,
  CheckCircle,
  LayoutDashboard,
  Target,
  Ban,
  ChevronDown,
  ChevronUp,
  Copy,
  Plus,
  Trash2,
  Search,
  ExternalLink,
  Terminal,
  Download,
} from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

// --- Constants ---

const SEVERITY_FILTERS = ["all", "critical", "high", "medium", "low"] as const;

const CATEGORY_LABELS: Record<string, string> = {
  name_resolution: "Name Resolution",
  layer2: "Layer 2",
  dhcp: "DHCP",
  routing: "Routing",
  service_exploit: "L2/L3 Services",
  tls_crypto: "TLS/Crypto",
  network_intel: "Network Intel",
};

const CATEGORY_COLORS: Record<string, string> = {
  layer2: "#f97316",
  dhcp: "#eab308",
  routing: "#22c55e",
  name_resolution: "#3b82f6",
  service_exploit: "#ef4444",
  tls_crypto: "#a855f7",
  network_intel: "#06b6d4",
};

const sevBadgeClass: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400",
  high: "bg-orange-500/15 text-orange-400",
  medium: "bg-yellow-500/15 text-yellow-400",
  low: "bg-blue-500/15 text-blue-400",
  info: "bg-blue-500/10 text-blue-300",
};

const statIconClasses: Record<string, string> = {
  critical: "bg-destructive/10 text-destructive",
  high: "bg-warning/10 text-warning",
  medlow: "bg-info/10 text-info",
  chains: "bg-success/10 text-success",
};

const TABS = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "chains", label: "Attack Chains", icon: Zap },
  { id: "findings", label: "Findings", icon: Target },
  { id: "exclusions", label: "Exclusions", icon: Ban },
] as const;

type TabId = (typeof TABS)[number]["id"];

// --- Helpers ---

function SeverityBadge({ severity, small }: { severity: string; small?: boolean }) {
  return (
    <span className={cn(
      "inline-flex items-center rounded-full font-bold uppercase tracking-wide",
      small ? "text-[9px] px-1.5 py-0" : "text-[10px] px-2 py-0.5",
      sevBadgeClass[severity] ?? "bg-muted text-muted-foreground"
    )}>
      {severity}
    </span>
  );
}

function copyCmd(text: string, btn: HTMLButtonElement) {
  navigator.clipboard.writeText(text).then(
    () => { const o = btn.textContent; btn.textContent = "Copied!"; setTimeout(() => { btn.textContent = o; }, 1500); },
    () => toast.error("Failed to copy")
  );
}

function DeviceChip({ dev }: { dev: AffectedDevice }) {
  let label = dev.ip || dev.mac || "?";
  if (dev.hostname) label = `${dev.hostname} (${label})`;
  if (dev.port) label += `:${dev.port}`;
  const version = dev.service_version;
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] font-mono px-2 py-0.5 rounded bg-secondary border border-border text-muted-foreground">
      {label}
      {version && <span className="text-[10px] text-primary/70">{version}</span>}
    </span>
  );
}

function ToolCard({ tool }: { tool: ToolRecommendation }) {
  return (
    <div className="rounded-lg bg-background/60 border border-border overflow-hidden">
      {/* Tool header */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-border/50">
        <Terminal size={12} className="text-primary shrink-0" />
        <span className="text-xs font-semibold text-primary">{tool.name}</span>
        {tool.description && (
          <span className="text-[11px] text-muted-foreground flex-1 truncate">{tool.description}</span>
        )}
        {tool.url && (
          <a
            href={tool.url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-muted-foreground hover:text-primary transition-colors shrink-0"
            title={tool.url}
            onClick={(e) => e.stopPropagation()}
          >
            <ExternalLink size={12} />
          </a>
        )}
      </div>
      {/* Command block */}
      <div className="flex items-center gap-2 px-3 py-2">
        <span className="text-green-500/60 text-xs select-none shrink-0">$</span>
        <code className="flex-1 text-xs font-mono text-green-400 overflow-x-auto whitespace-nowrap scrollbar-none">
          {tool.command}
        </code>
        <Button variant="ghost" size="sm" className="shrink-0 text-xs h-6 px-2 text-muted-foreground hover:text-foreground" onClick={(e) => { e.stopPropagation(); copyCmd(tool.command, e.currentTarget); }}>
          <Copy size={11} className="mr-1" /> Copy
        </Button>
      </div>
      {/* Install hint */}
      {tool.install_hint && (
        <div className="flex items-center gap-1.5 px-3 py-1.5 border-t border-border/30 bg-secondary/30">
          <Download size={10} className="text-muted-foreground/50 shrink-0" />
          <code className="text-[10px] font-mono text-muted-foreground/60">{tool.install_hint}</code>
        </div>
      )}
    </div>
  );
}

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ value: number }>; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-border bg-card px-3 py-2 shadow-md">
      <p className="text-xs font-medium mb-0.5">{label}</p>
      <p className="text-sm font-semibold">{payload?.[0]?.value ?? 0} findings</p>
    </div>
  );
}

// --- Main ---

interface AttackSurfaceProps {
  subscribe: (handler: (msg: WsMessage) => void) => () => void;
}

export default function AttackSurface({ subscribe }: AttackSurfaceProps) {
  const queryClient = useQueryClient();

  useEffect(() => {
    return subscribe((msg) => {
      if (msg.device) {
        queryClient.invalidateQueries({ queryKey: ["attack-surface"] });
      }
    });
  }, [subscribe, queryClient]);

  const { data } = useQuery({
    queryKey: ["attack-surface"],
    queryFn: fetchAttackSurface,
    staleTime: 30000,
    refetchInterval: 30000,
  });

  const { data: exclusionsData } = useQuery({
    queryKey: ["attack-exclusions"],
    queryFn: fetchExclusions,
    staleTime: 30000,
  });

  const [activeTab, setActiveTab] = useState<TabId>("dashboard");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [searchText, setSearchText] = useState("");

  // Collapsible state
  const [expandedChains, setExpandedChains] = useState<Set<number>>(new Set());
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());

  // Exclusion form state
  const [exclType, setExclType] = useState("ip");
  const [exclValue, setExclValue] = useState("");
  const [exclBusy, setExclBusy] = useState(false);

  const findings = data?.findings ?? [];
  const chains = data?.chains ?? [];
  const summary = data?.summary ?? {};
  const bySev = summary?.by_severity ?? {};
  const byCat = summary?.by_category ?? {};
  const exclusions = exclusionsData?.exclusions ?? [];

  const criticalCount = bySev.critical ?? 0;
  const highCount = bySev.high ?? 0;
  const medLowCount = (bySev.medium ?? 0) + (bySev.low ?? 0) + (bySev.info ?? 0);
  const chainCount = summary?.chain_count ?? chains.length;

  // Dashboard: category chart data
  const categoryChartData = useMemo(() =>
    Object.entries(byCat).map(([cat, count]) => ({
      name: CATEGORY_LABELS[cat] ?? cat,
      count: count as number,
      color: CATEGORY_COLORS[cat] ?? "#6b7280",
    })),
    [byCat]
  );

  // Dashboard: most affected devices
  const topDevices = useMemo(() => {
    const deviceMap = new Map<string, { ip: string; mac: string; count: number; deviceType?: string }>();
    for (const f of findings) {
      for (const dev of f.affected_devices ?? []) {
        const key = dev.ip || dev.mac || "unknown";
        const existing = deviceMap.get(key);
        if (existing) {
          existing.count++;
        } else {
          deviceMap.set(key, { ip: dev.ip ?? "", mac: dev.mac ?? "", count: 1, deviceType: dev.hostname });
        }
      }
    }
    return Array.from(deviceMap.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }, [findings]);

  // Findings filter
  const categoryChips = useMemo(() =>
    Object.entries(byCat).map(([cat, count]) => ({ key: cat, label: CATEGORY_LABELS[cat] ?? cat, count })),
    [byCat]
  );

  const filtered = useMemo(() => {
    let result = findings;
    if (severityFilter !== "all") result = result.filter((f) => f.severity === severityFilter);
    if (categoryFilter !== "all") result = result.filter((f) => f.category === categoryFilter);
    if (searchText.trim()) {
      const q = searchText.toLowerCase();
      result = result.filter((f) =>
        f.title.toLowerCase().includes(q) || f.description.toLowerCase().includes(q) || f.rule_id.toLowerCase().includes(q) ||
        f.tools?.some((t) => t.name.toLowerCase().includes(q) || t.command.toLowerCase().includes(q)) ||
        f.affected_devices?.some((d) => (d.ip ?? "").includes(q) || (d.mac ?? "").includes(q) || (d.hostname ?? "").toLowerCase().includes(q))
      );
    }
    return result;
  }, [findings, severityFilter, categoryFilter, searchText]);

  const toggleChain = (idx: number) => {
    setExpandedChains((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx); else next.add(idx);
      return next;
    });
  };

  const toggleFinding = (ruleId: string) => {
    setExpandedFindings((prev) => {
      const next = new Set(prev);
      if (next.has(ruleId)) next.delete(ruleId); else next.add(ruleId);
      return next;
    });
  };

  const handleAddExclusion = async () => {
    if (!exclValue.trim()) return;
    setExclBusy(true);
    try {
      await addExclusion(exclType, exclValue.trim());
      toast.success(`Exclusion added: ${exclType}/${exclValue.trim()}`);
      setExclValue("");
      queryClient.invalidateQueries({ queryKey: ["attack-exclusions"] });
      queryClient.invalidateQueries({ queryKey: ["attack-surface"] });
    } catch {
      toast.error("Failed to add exclusion");
    } finally {
      setExclBusy(false);
    }
  };

  const handleRemoveExclusion = async (excl: AttackExclusion) => {
    try {
      await removeExclusion(excl.type, excl.value);
      toast.success(`Exclusion removed: ${excl.type}/${excl.value}`);
      queryClient.invalidateQueries({ queryKey: ["attack-exclusions"] });
      queryClient.invalidateQueries({ queryKey: ["attack-surface"] });
    } catch {
      toast.error("Failed to remove exclusion");
    }
  };

  return (
    <div className="space-y-6">
      {/* Tab bar */}
      <div className="flex items-center border-b border-border">
        <div className="flex gap-0">
          {TABS.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={cn(
                  "flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors -mb-px",
                  isActive
                    ? "border-primary text-foreground"
                    : "border-transparent text-muted-foreground hover:text-foreground hover:border-border"
                )}
              >
                <Icon size={15} />
                {tab.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Tab: Dashboard */}
      {activeTab === "dashboard" && (
        <div className="space-y-5">
          {/* Info card — explains what this page does */}
          <div className="rounded-xl bg-primary/[0.04] border border-primary/20 p-4">
            <div className="flex items-start gap-3">
              <Info size={18} className="text-primary shrink-0 mt-0.5" />
              <div className="space-y-1.5">
                <h3 className="text-sm font-semibold">About Attack Path Analysis</h3>
                <p className="text-xs text-muted-foreground leading-relaxed">
                  Leetha passively analyzes captured network traffic to identify exploitable attack paths at <span className="text-foreground font-medium">Layer 2 (Data Link)</span> and <span className="text-foreground font-medium">Layer 3 (Network)</span>.
                  This includes ARP spoofing opportunities, DHCP starvation/rogue server attacks, IPv6 Router Advertisement abuse, name resolution poisoning (LLMNR/NBT-NS/mDNS), and cleartext protocol exposure.
                  Findings are based on real observed traffic — not theoretical vulnerabilities. Attack chains combine multiple findings into actionable exploitation paths with tool commands.
                </p>
                <div className="flex flex-wrap gap-2 pt-1">
                  <span className="text-[10px] px-2 py-0.5 rounded-full border border-border bg-card text-muted-foreground">ARP / NDP</span>
                  <span className="text-[10px] px-2 py-0.5 rounded-full border border-border bg-card text-muted-foreground">DHCP / DHCPv6</span>
                  <span className="text-[10px] px-2 py-0.5 rounded-full border border-border bg-card text-muted-foreground">LLMNR / NBT-NS</span>
                  <span className="text-[10px] px-2 py-0.5 rounded-full border border-border bg-card text-muted-foreground">mDNS / SSDP</span>
                  <span className="text-[10px] px-2 py-0.5 rounded-full border border-border bg-card text-muted-foreground">IPv6 RA</span>
                  <span className="text-[10px] px-2 py-0.5 rounded-full border border-border bg-card text-muted-foreground">STP</span>
                  <span className="text-[10px] px-2 py-0.5 rounded-full border border-border bg-card text-muted-foreground">SMB / LDAP</span>
                  <span className="text-[10px] px-2 py-0.5 rounded-full border border-border bg-card text-muted-foreground">TLS / HTTP</span>
                </div>
              </div>
            </div>
          </div>

          {/* Row 1: Compact stat cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {[
              { key: "critical", label: "CRITICAL", value: criticalCount, icon: ShieldAlert },
              { key: "high", label: "HIGH", value: highCount, icon: AlertTriangle },
              { key: "medlow", label: "MEDIUM / LOW", value: medLowCount, icon: Info },
              { key: "chains", label: "ATTACK CHAINS", value: chainCount, icon: Zap },
            ].map((s) => (
              <div key={s.key} className="rounded-lg bg-card border border-border px-4 py-3 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <s.icon size={15} className={cn(statIconClasses[s.key]?.split(" ").pop())} />
                  <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">{s.label}</span>
                </div>
                <span className="text-xl font-bold">{s.value}</span>
              </div>
            ))}
          </div>

          {/* Row 2: Attack Chains — the most important section */}
          {chains.length > 0 && (
            <div className="rounded-xl bg-card border border-border overflow-hidden">
              <div className="px-5 py-3 border-b border-border flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Zap size={15} className="text-warning" />
                  <h3 className="text-sm font-semibold">Active Attack Chains</h3>
                </div>
                <span className="text-xs text-muted-foreground">{chains.length} identified — click to expand</span>
              </div>
              <div className="p-4 space-y-3">
                {chains.map((chain, ci) => (
                  <CollapsibleChainCard key={ci} chain={chain} index={ci} expanded={expandedChains.has(ci)} onToggle={() => toggleChain(ci)} />
                ))}
              </div>
            </div>
          )}

          {/* Row 3: Network Layer Breakdown — full width */}
          <div className="rounded-xl bg-card border border-border p-5">
            <h3 className="text-sm font-semibold mb-1">Network Layer Breakdown</h3>
            <p className="text-[10px] text-muted-foreground mb-4">Findings grouped by the network layer where the attack vector exists.</p>
            {categoryChartData.length > 0 ? (
              <>
                <div style={{ height: Math.max(categoryChartData.length * 44, 120) }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={categoryChartData} layout="vertical" margin={{ left: 0, right: 15, top: 0, bottom: 0 }}>
                        <XAxis type="number" tick={{ fontSize: 10, fill: "#71717a" }} tickLine={false} axisLine={false} allowDecimals={false} />
                        <YAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: "#a1a1aa" }} tickLine={false} axisLine={false} width={110} />
                        <Tooltip content={<ChartTooltip />} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
                        <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={20}>
                          {categoryChartData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                  {/* Layer legend */}
                  <div className="grid grid-cols-2 gap-x-4 gap-y-1 mt-3 pt-3 border-t border-border">
                    <div className="text-[10px] text-muted-foreground"><span className="font-semibold text-foreground">Layer 2:</span> ARP spoofing, STP manipulation, VLAN hopping, NDP</div>
                    <div className="text-[10px] text-muted-foreground"><span className="font-semibold text-foreground">Layer 3:</span> DHCP rogue, IPv6 RA, routing attacks, ICMP redirect</div>
                    <div className="text-[10px] text-muted-foreground"><span className="font-semibold text-foreground">Name Resolution:</span> LLMNR/NBT-NS/mDNS/WPAD poisoning</div>
                    <div className="text-[10px] text-muted-foreground"><span className="font-semibold text-foreground">Services:</span> SMB relay, LDAP, cleartext protocols, ICS/SCADA</div>
                  </div>
                </>
              ) : (
                <p className="text-sm text-muted-foreground py-8 text-center">No findings detected yet. Start a capture to analyze network traffic.</p>
              )}
          </div>

          {/* Row 4: Most Exposed Devices — full width */}
          <div className="rounded-xl bg-card border border-border p-5">
            <h3 className="text-sm font-semibold mb-1">Most Exposed Hosts</h3>
            <p className="text-[10px] text-muted-foreground mb-4">Hosts that appear in the most attack findings — highest priority for hardening.</p>
            {topDevices.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5">
                {topDevices.map((dev, i) => {
                  const maxCount = topDevices[0]?.count ?? 1;
                  const pct = (dev.count / maxCount) * 100;
                  return (
                    <div key={i} className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-secondary/30 transition-colors">
                      <span className="text-[10px] font-bold text-muted-foreground w-5 shrink-0">#{i + 1}</span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-data truncate">{dev.ip || dev.mac}</span>
                          {dev.deviceType && <span className="text-[10px] text-muted-foreground truncate">{dev.deviceType}</span>}
                        </div>
                        <div className="h-1 bg-muted/50 rounded-full mt-1 overflow-hidden">
                          <div className="h-full rounded-full bg-destructive/60" style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                      <span className="text-xs font-bold text-destructive shrink-0">{dev.count}</span>
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground py-8 text-center">No affected hosts found yet.</p>
            )}
          </div>

          {/* Row 4: Top Findings preview */}
          {findings.length > 0 && (
            <div className="rounded-xl bg-card border border-border p-5">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold">Highest Severity Findings</h3>
                <button onClick={() => setActiveTab("findings")} className="text-xs text-primary hover:underline">View all {findings.length} findings</button>
              </div>
              <div className="space-y-2">
                {[...findings].sort((a, b) => {
                  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                  return (order[a.severity] ?? 9) - (order[b.severity] ?? 9);
                }).slice(0, 5).map((f) => (
                  <div key={f.rule_id} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-secondary/30 border border-border">
                    <SeverityBadge severity={f.severity} />
                    <span className="text-xs font-mono text-muted-foreground">{f.rule_id}</span>
                    <span className="text-sm font-medium flex-1 truncate">{f.title}</span>
                    <span className="text-xs text-muted-foreground shrink-0">{f.affected_devices?.length ?? 0} hosts</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab: Attack Chains */}
      {activeTab === "chains" && (
        <div className="rounded-xl bg-card border border-border overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3 border-b border-border">
            <h3 className="text-sm font-semibold">Attack Chains</h3>
            <span className="text-xs text-muted-foreground">{chains.length} identified</span>
          </div>
          <div className="p-4 space-y-3">
            {chains.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <CheckCircle size={28} className="mb-2 text-success" />
                <p className="text-sm font-medium">No attack chains</p>
                <p className="text-xs">No attack chains identified from captured data.</p>
              </div>
            ) : (
              chains.map((chain, ci) => (
                <CollapsibleChainCard
                  key={ci}
                  chain={chain}
                  index={ci}
                  expanded={expandedChains.has(ci)}
                  onToggle={() => toggleChain(ci)}
                />
              ))
            )}
          </div>
        </div>
      )}

      {/* Tab: Findings */}
      {activeTab === "findings" && (
        <div className="rounded-xl bg-card border border-border overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3 border-b border-border flex-wrap gap-2">
            <h3 className="text-sm font-semibold">
              Findings <span className="text-muted-foreground font-normal">({filtered.length})</span>
            </h3>
            <div className="flex flex-wrap gap-1">
              <button
                className={cn(
                  "text-xs px-2.5 py-1 rounded-full border transition-colors",
                  categoryFilter === "all"
                    ? "bg-primary text-primary-foreground border-primary"
                    : "border-border text-muted-foreground hover:text-foreground"
                )}
                onClick={() => setCategoryFilter("all")}
              >
                All
              </button>
              {categoryChips.map((cat) => (
                <button
                  key={cat.key}
                  className={cn(
                    "text-xs px-2.5 py-1 rounded-full border transition-colors",
                    categoryFilter === cat.key
                      ? "bg-primary text-primary-foreground border-primary"
                      : "border-border text-muted-foreground hover:text-foreground"
                  )}
                  onClick={() => setCategoryFilter(cat.key)}
                >
                  {cat.label} ({cat.count})
                </button>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-3 px-5 py-3 border-b border-border flex-wrap">
            <div className="flex-1 min-w-[200px] relative">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search findings, tools, devices..."
                value={searchText}
                onChange={(e) => setSearchText(e.target.value)}
                className="pl-9 bg-secondary border-border"
              />
            </div>
            <ToggleGroup type="single" value={severityFilter} onValueChange={(v) => v && setSeverityFilter(v)} className="gap-1">
              {SEVERITY_FILTERS.map((f) => (
                <ToggleGroupItem key={f} value={f} className="text-xs capitalize px-3 py-1 h-8">{f}</ToggleGroupItem>
              ))}
            </ToggleGroup>
          </div>
          <div className="p-4">
            {filtered.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <CheckCircle size={28} className="mb-2 text-success" />
                <p className="text-sm font-medium">No findings</p>
                <p className="text-xs">No attack surface findings detected from captured data.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {filtered.map((f) => (
                  <CollapsibleFindingCard
                    key={f.rule_id}
                    finding={f}
                    expanded={expandedFindings.has(f.rule_id)}
                    onToggle={() => toggleFinding(f.rule_id)}
                  />
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab: Exclusions */}
      {activeTab === "exclusions" && (
        <div className="rounded-xl bg-card border border-border overflow-hidden">
          <div className="px-5 py-3 border-b border-border">
            <h3 className="text-sm font-semibold">Manage Exclusions</h3>
            <p className="text-xs text-muted-foreground mt-0.5">Exclude IPs, MACs, or rules from attack surface analysis.</p>
          </div>

          {/* Add form */}
          <div className="flex items-center gap-3 px-5 py-4 border-b border-border flex-wrap">
            <select
              value={exclType}
              onChange={(e) => setExclType(e.target.value)}
              className="h-9 rounded-md border border-border bg-secondary px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
            >
              <option value="ip">Network Address</option>
              <option value="mac">Hardware Address</option>
              <option value="rule">Rule ID</option>
            </select>
            <Input
              placeholder={exclType === "ip" ? "e.g. 192.168.1.1" : exclType === "mac" ? "e.g. aa:bb:cc:dd:ee:ff" : "e.g. RULE_001"}
              value={exclValue}
              onChange={(e) => setExclValue(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") handleAddExclusion(); }}
              className="flex-1 min-w-[200px] bg-secondary border-border"
            />
            <Button size="sm" onClick={handleAddExclusion} disabled={exclBusy || !exclValue.trim()}>
              <Plus size={14} className="mr-1.5" />
              Add
            </Button>
          </div>

          {/* Existing exclusions */}
          <div className="p-4">
            {exclusions.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Ban size={28} className="mb-2 opacity-40" />
                <p className="text-sm font-medium">No exclusions</p>
                <p className="text-xs">Add exclusions above to filter out known-safe items.</p>
              </div>
            ) : (
              <div className="space-y-2">
                {exclusions.map((excl, i) => (
                  <div key={i} className="flex items-center justify-between rounded-lg bg-secondary/40 border border-border px-4 py-2.5">
                    <div className="flex items-center gap-3">
                      <span className="text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 rounded bg-muted text-muted-foreground">
                        {excl.type}
                      </span>
                      <span className="text-sm font-mono">{excl.value}</span>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-destructive hover:text-destructive hover:bg-destructive/10 h-8"
                      onClick={() => handleRemoveExclusion(excl)}
                    >
                      <Trash2 size={14} className="mr-1" />
                      Remove
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// --- Collapsible Chain Card ---

function CollapsibleChainCard({
  chain,
  index,
  expanded,
  onToggle,
}: {
  chain: AttackChain;
  index: number;
  expanded: boolean;
  onToggle: () => void;
}) {
  const triggeredCount = chain.triggered_by?.length ?? chain.findings?.length ?? 0;

  return (
    <div id={`chain-${chain.chain_id ?? index}`} className="rounded-xl border border-yellow-500/25 bg-yellow-500/[0.03] overflow-hidden">
      {/* Header — always visible */}
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-2 flex-wrap px-4 py-3 text-left hover:bg-yellow-500/[0.06] transition-colors"
      >
        <SeverityBadge severity={chain.severity} />
        {chain.chain_id && <span className="text-[10px] font-mono text-muted-foreground/60">{chain.chain_id}</span>}
        <span className="font-semibold text-sm flex-1 min-w-0 truncate">{chain.name}</span>
        {chain.interface && (
          <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-blue-500/15 text-blue-400">{chain.interface}</span>
        )}
        <span className="text-xs text-muted-foreground">{triggeredCount} finding{triggeredCount !== 1 ? "s" : ""}</span>
        {expanded ? <ChevronUp size={16} className="text-muted-foreground shrink-0" /> : <ChevronDown size={16} className="text-muted-foreground shrink-0" />}
      </button>

      {/* Expanded content */}
      {expanded && (
        <div className="border-t border-yellow-500/15">
          {/* Description */}
          <div className="px-4 py-3">
            <p className="text-sm text-muted-foreground leading-relaxed">{chain.description}</p>
          </div>

          {/* Section 1: Trigger — why this chain was identified */}
          {chain.triggered_by && chain.triggered_by.length > 0 && (
            <div className="mx-4 mb-3 rounded-lg border border-border/50 overflow-hidden">
              <div className="flex items-center gap-2 px-3 py-2 bg-yellow-500/[0.06] border-b border-border/50">
                <div className="w-1 h-4 rounded-full bg-yellow-500 shrink-0" />
                <span className="text-[10px] font-semibold uppercase tracking-widest text-yellow-400/80">Identified Because</span>
              </div>
              <div className="p-3 space-y-3">
                {chain.triggered_by.map((trigger, ti) => (
                  <div key={ti}>
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityBadge severity={trigger.severity} small />
                      <span className="text-[10px] font-mono text-muted-foreground/60">{trigger.rule_id}</span>
                      <span className="text-sm font-medium">{trigger.name}</span>
                    </div>
                    {trigger.evidence && trigger.evidence.filter(Boolean).length > 0 && (
                      <p className="text-[11px] text-muted-foreground/70 ml-6 mb-1">{trigger.evidence.filter(Boolean).join(" · ")}</p>
                    )}
                    {trigger.affected_devices && trigger.affected_devices.length > 0 && (
                      <div className="flex flex-wrap gap-1 ml-6">
                        {trigger.affected_devices.slice(0, 8).map((dev, di) => <DeviceChip key={di} dev={dev} />)}
                        {trigger.affected_devices.length > 8 && (
                          <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-secondary border border-border text-muted-foreground">+{trigger.affected_devices.length - 8} more</span>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Section 2: Attack Path — ordered steps */}
          {chain.steps && chain.steps.length > 0 && (
            <div className="mx-4 mb-3 rounded-lg border border-border/50 overflow-hidden">
              <div className="flex items-center gap-2 px-3 py-2 bg-secondary/40 border-b border-border/50">
                <div className="w-1 h-4 rounded-full bg-primary shrink-0" />
                <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Attack Path</span>
              </div>
              <div className="p-3 space-y-0">
                {chain.steps.map((step, si) => (
                  <div key={step.order} className="flex items-start gap-3 relative">
                    {/* Connector line */}
                    {si < chain.steps!.length - 1 && (
                      <div className="absolute left-[11px] top-6 w-px h-[calc(100%-4px)] bg-border/60" />
                    )}
                    <span className="flex items-center justify-center w-6 h-6 rounded-full bg-primary/15 text-primary text-[11px] font-bold shrink-0 relative z-10 border border-primary/30">
                      {step.order}
                    </span>
                    <span className="text-sm text-muted-foreground pt-0.5 pb-3">{step.description}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Section 3: Arsenal — tools with full details */}
          {chain.tools && chain.tools.length > 0 && (
            <div className="mx-4 mb-4 rounded-lg border border-border/50 overflow-hidden">
              <div className="flex items-center gap-2 px-3 py-2 bg-green-500/[0.05] border-b border-border/50">
                <div className="w-1 h-4 rounded-full bg-green-500 shrink-0" />
                <Terminal size={12} className="text-green-400" />
                <span className="text-[10px] font-semibold uppercase tracking-widest text-green-400/80">Arsenal</span>
                <span className="text-[10px] text-muted-foreground/50">{chain.tools.length} tool{chain.tools.length !== 1 ? "s" : ""}</span>
              </div>
              <div className="p-3 space-y-2">
                {chain.tools.map((tool, ti) => <ToolCard key={ti} tool={tool} />)}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// --- Collapsible Finding Card ---

function CollapsibleFindingCard({
  finding,
  expanded,
  onToggle,
}: {
  finding: AttackFinding;
  expanded: boolean;
  onToggle: () => void;
}) {
  const catColor = CATEGORY_COLORS[finding.category] ?? "#6b7280";
  const deviceCount = finding.affected_devices?.length ?? 0;
  const toolCount = finding.tools?.length ?? 0;

  return (
    <div className="rounded-xl border border-border bg-secondary/30 hover:border-muted-foreground/20 transition-colors overflow-hidden">
      {/* Header — always visible */}
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-2 flex-wrap px-4 py-3 text-left hover:bg-secondary/50 transition-colors"
      >
        <SeverityBadge severity={finding.severity} />
        <span className="text-[10px] font-mono text-muted-foreground/50">{finding.rule_id}</span>
        <span className="font-semibold text-sm flex-1 min-w-0 truncate">{finding.title || finding.name}</span>
        <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full border text-muted-foreground" style={{ borderColor: `${catColor}40`, color: catColor }}>
          {CATEGORY_LABELS[finding.category] ?? finding.category}
        </span>
        {deviceCount > 0 && <span className="text-[10px] text-muted-foreground/60">{deviceCount} host{deviceCount !== 1 ? "s" : ""}</span>}
        {expanded ? <ChevronUp size={16} className="text-muted-foreground shrink-0" /> : <ChevronDown size={16} className="text-muted-foreground shrink-0" />}
      </button>

      {/* Expanded content */}
      {expanded && (
        <div className="border-t border-border/50">
          {/* Description */}
          <div className="px-4 py-3">
            <p className="text-sm text-muted-foreground leading-relaxed">{finding.description}</p>
          </div>

          {/* Evidence */}
          {finding.evidence?.filter(Boolean).length > 0 && (
            <div className="mx-4 mb-3 rounded-lg bg-secondary/40 border border-border/40 px-3 py-2">
              <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60 mr-2">Evidence</span>
              <span className="text-[11px] font-mono text-muted-foreground/80">{finding.evidence.filter(Boolean).join(" · ")}</span>
            </div>
          )}

          {/* Affected hosts */}
          {deviceCount > 0 && (
            <div className="mx-4 mb-3">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60">Affected Hosts</span>
                <span className="text-[10px] text-muted-foreground/40">{deviceCount}</span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {finding.affected_devices.slice(0, 12).map((dev, i) => <DeviceChip key={i} dev={dev} />)}
                {deviceCount > 12 && (
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-secondary border border-border text-muted-foreground">+{deviceCount - 12} more</span>
                )}
              </div>
            </div>
          )}

          {/* Arsenal */}
          {toolCount > 0 && (
            <div className="mx-4 mb-4 rounded-lg border border-border/50 overflow-hidden">
              <div className="flex items-center gap-2 px-3 py-2 bg-green-500/[0.05] border-b border-border/50">
                <div className="w-1 h-4 rounded-full bg-green-500 shrink-0" />
                <Terminal size={12} className="text-green-400" />
                <span className="text-[10px] font-semibold uppercase tracking-widest text-green-400/80">Arsenal</span>
                <span className="text-[10px] text-muted-foreground/50">{toolCount} tool{toolCount !== 1 ? "s" : ""}</span>
              </div>
              <div className="p-3 space-y-2">
                {finding.tools.map((tool, i) => <ToolCard key={i} tool={tool} />)}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
