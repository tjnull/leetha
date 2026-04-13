import { useState, useMemo, useRef, useCallback } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  fetchIncidents, fetchIncidentDetail,
  fetchIncidentStats, fetchIncidentTimeline, fetchIncidentTopDevices,
  resolveIncident, reopenIncident, saveIncidentNotes,
  exportFindingsUrl,
  fetchTrustedBindings, addTrustedBinding, removeTrustedBinding,
  fetchSuppressionRules, addSuppressionRule, removeSuppressionRule,
  type Incident, type IncidentDetail, type IncidentStats, type TopDevice,
} from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";
import {
  ShieldAlert, Shield, Plus, Search,
  AlertTriangle, Info, ChevronDown,
  TrendingUp, TrendingDown, Minus,
  Trash2, LayoutDashboard,
  ListFilter, Ban, Target, X,
  Download,
} from "lucide-react";
import {
  AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from "recharts";

// ═══════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════

const SUBTYPE_LABELS: Record<string, string> = {
  gateway_impersonation: "Gateway Impersonation",
  ip_conflict: "IP Conflict",
  flip_flop: "ARP Flip-Flop",
  grat_flood: "Gratuitous ARP Flood",
  fingerprint_drift: "Fingerprint Drift",
  oui_mismatch: "OUI Mismatch",
  mac_spoofing: "Identity Shift",
  infra_offline: "Device Offline",
  dhcp_anomaly: "DHCP Anomaly",
  new_device: "New Device",
  os_change: "OS Change",
  mac_randomized: "MAC Randomized",
  unclassified: "Low Confidence",
  source_stale: "Stale Source",
  sensor_connect: "Sensor Connected",
  sensor_disconnect: "Sensor Disconnected",
  other: "Network Anomaly",
};

const SEVERITY_COLORS: Record<string, { border: string; bg: string; text: string; chart: string }> = {
  threat: { border: "border-l-red-500", bg: "bg-red-500/10", text: "text-red-400", chart: "#ef4444" },
  suspicious: { border: "border-l-yellow-500", bg: "bg-yellow-500/10", text: "text-yellow-400", chart: "#eab308" },
  informational: { border: "border-l-blue-500", bg: "bg-blue-500/10", text: "text-blue-400", chart: "#3b82f6" },
};

const CATEGORY_COLORS: Record<string, string> = {
  new_host: "#3b82f6",
  identity_shift: "#ef4444",
  addr_conflict: "#f97316",
  dhcp_anomaly: "#eab308",
  behavioral_drift: "#8b5cf6",
  randomized_addr: "#06b6d4",
  stale_source: "#6b7280",
  low_certainty: "#9ca3af",
  sensor_connect: "#22c55e",
  sensor_disconnect: "#f59e0b",
};

const TABS = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "findings", label: "Findings", icon: ListFilter },
  { id: "exclusions", label: "Exclusions", icon: Ban },
] as const;

// ═══════════════════════════════════════════
//  Sparkline (inline SVG)
// ═══════════════════════════════════════════

function Sparkline({ data, width = 48, height = 16, color = "#3b82f6" }: { data: number[]; width?: number; height?: number; color?: string }) {
  if (!data.length || data.every(d => d === 0)) return null;
  const max = Math.max(...data, 1);
  const points = data.map((v, i) => `${(i / (data.length - 1)) * width},${height - (v / max) * height}`).join(" ");
  return (
    <svg width={width} height={height} className="shrink-0">
      <polyline points={points} fill="none" stroke={color} strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// ═══════════════════════════════════════════
//  Relative Time Helper
// ═══════════════════════════════════════════

function relativeTime(iso: string | null): string {
  if (!iso) return "";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "now";
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h`;
  return `${Math.floor(hrs / 24)}d`;
}

// ═══════════════════════════════════════════
//  Chart Tooltip
// ═══════════════════════════════════════════

function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-border bg-card px-3 py-2 shadow-lg">
      <p className="text-xs font-medium mb-1">{label}</p>
      {payload.map((p: any) => (
        <p key={p.name} className="text-xs" style={{ color: p.color }}>
          {p.name}: {p.value}
        </p>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════
//  Severity Badge
// ═══════════════════════════════════════════

function SeverityBadge({ severity }: { severity: string }) {
  const colors = SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.informational;
  return (
    <Badge className={cn("text-[10px] uppercase font-semibold", colors.bg, colors.text, "border-0")}>
      {severity}
    </Badge>
  );
}

// ═══════════════════════════════════════════
//  Collapsible Finding Card
// ═══════════════════════════════════════════

function CollapsibleFindingCard({
  incident,
  expanded,
  onToggle,
  selected,
  onSelect,
  detail,
  onDismiss,
  onSuppress,
}: {
  incident: Incident;
  expanded: boolean;
  onToggle: () => void;
  selected: boolean;
  onSelect: (checked: boolean) => void;
  detail: IncidentDetail | null;
  onDismiss: () => void;
  onSuppress: () => void;
}) {
  const colors = SEVERITY_COLORS[incident.severity] ?? SEVERITY_COLORS.informational;

  // Parse a cleaner summary — extract device name from raw message
  const deviceLabel = incident.manufacturer
    ? `${incident.manufacturer}${incident.device_ip ? ` (${incident.device_ip})` : ""}`
    : incident.device_ip ?? incident.device_mac;

  // Relative time
  const timeAgo = incident.last_seen
    ? (() => {
        const diff = Date.now() - new Date(incident.last_seen).getTime();
        const mins = Math.floor(diff / 60000);
        if (mins < 1) return "just now";
        if (mins < 60) return `${mins}m ago`;
        const hrs = Math.floor(mins / 60);
        if (hrs < 24) return `${hrs}h ago`;
        return `${Math.floor(hrs / 24)}d ago`;
      })()
    : null;

  // Deduplicate fingerprint history — combine entries with same source+category+vendor
  const deduplicateFpHistory = (entries: any[]) => {
    const seen = new Map<string, any>();
    for (const fp of entries) {
      const key = `${fp.source}|${fp.device_type || ""}|${fp.manufacturer || ""}|${fp.os_family || ""}`;
      if (!seen.has(key) || (fp.device_type || fp.manufacturer || fp.os_family)) {
        seen.set(key, fp);
      }
    }
    return Array.from(seen.values()).filter(
      (fp) => fp.device_type || fp.manufacturer || fp.os_family || fp.hostname
    );
  };

  // Format observation data — parse JSON strings into readable text
  const formatObsData = (obs: any): string => {
    try {
      const data = typeof obs.raw_data === "string" ? JSON.parse(obs.raw_data) : obs.raw_data;
      if (typeof data === "object" && data !== null) {
        const parts: string[] = [];
        if (data.ip) parts.push(`IP: ${data.ip}`);
        if (data.hostname) parts.push(`Host: ${data.hostname}`);
        if (data.vendor_class) parts.push(`DHCP: ${data.vendor_class}`);
        if (data.op) parts.push(`Op: ${data.op}`);
        if (data.evidence_count) parts.push(`${data.evidence_count} evidence`);
        return parts.length > 0 ? parts.join(" · ") : "";
      }
      return String(data);
    } catch {
      return obs.raw_data || "";
    }
  };

  // Deduplicate observations — group by source type and show count
  const deduplicateObs = (entries: any[]) => {
    const grouped = new Map<string, { count: number; latest: any; maxConfidence: number }>();
    for (const obs of entries) {
      const key = obs.source_type;
      const existing = grouped.get(key);
      if (!existing) {
        grouped.set(key, { count: 1, latest: obs, maxConfidence: obs.confidence });
      } else {
        existing.count++;
        existing.maxConfidence = Math.max(existing.maxConfidence, obs.confidence);
        if (obs.timestamp > (existing.latest.timestamp || "")) {
          existing.latest = obs;
        }
      }
    }
    return Array.from(grouped.values());
  };

  return (
    <div>
      {/* Detail panel only — header row is rendered by the parent */}
      {expanded && (
        <div>
          {detail ? (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-0 divide-y lg:divide-y-0 lg:divide-x divide-border">
              {/* Left column: context + recommendation */}
              <div className="p-5 space-y-4">
                {/* Recommendation first — most actionable */}
                {detail.detection_context?.recommendation && (
                  <div className="rounded-lg bg-primary/[0.04] border border-primary/20 p-3">
                    <p className="text-xs leading-relaxed">
                      <span className="font-semibold">Action:</span>{" "}
                      {detail.detection_context.recommendation.replace(/^(CRITICAL|HIGH|WARNING|INFO):\s*/i, "")}
                    </p>
                  </div>
                )}

                {/* Detection context */}
                {detail.detection_context && (
                  <div className="space-y-2">
                    <h4 className="text-[11px] font-semibold text-muted-foreground flex items-center gap-2">
                      <Target size={12} />
                      How This Was Detected
                    </h4>
                    <div className="rounded-lg bg-muted/20 p-3 space-y-2 text-xs">
                      <p><span className="text-muted-foreground">Trigger:</span> {detail.detection_context.trigger}</p>
                      <p className="text-muted-foreground leading-relaxed">{detail.detection_context.method}</p>
                    </div>
                  </div>
                )}

                {/* ARP History — only show rows with data */}
                {detail.arp_history && detail.arp_history.length > 0 && (
                  <div className="space-y-2">
                    <h4 className="text-[11px] font-semibold text-muted-foreground">ARP Bindings</h4>
                    <div className="space-y-1">
                      {detail.arp_history.map((h: any, i: number) => (
                        <div key={i} className="flex items-center gap-3 text-xs rounded-lg bg-muted/20 px-3 py-2">
                          <span className="font-mono font-medium">{h.ip}</span>
                          {h.interface && <span className="text-muted-foreground">{h.interface}</span>}
                          {h.packets && <span className="text-muted-foreground">{h.packets} pkts</span>}
                          {h.last_seen && (
                            <span className="ml-auto text-[10px] text-muted-foreground">
                              {new Date(h.last_seen).toLocaleString()}
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Actions */}
                <div className="flex gap-2 pt-2">
                  <Button size="sm" variant="outline" className="text-xs h-7" onClick={onDismiss}>Resolve</Button>
                  <Button size="sm" variant="outline" className="text-xs h-7" onClick={onSuppress}>Suppress</Button>
                </div>
              </div>

              {/* Right column: evidence timeline */}
              <div className="p-5 space-y-4">
                {/* Fingerprint evidence — deduplicated */}
                {detail.fingerprint_history && detail.fingerprint_history.length > 0 && (() => {
                  const deduped = deduplicateFpHistory(detail.fingerprint_history);
                  if (deduped.length === 0) return null;
                  return (
                    <div className="space-y-2">
                      <h4 className="text-[11px] font-semibold text-muted-foreground">Fingerprint Evidence</h4>
                      <div className="space-y-1.5">
                        {deduped.map((fp: any, i: number) => (
                          <div key={i} className="rounded-lg border border-border bg-muted/10 px-3 py-2">
                            <div className="flex items-center gap-2 mb-1">
                              <Badge variant="outline" className="text-[9px] font-mono">{fp.source}</Badge>
                              {fp.timestamp && (
                                <span className="text-[10px] text-muted-foreground ml-auto">
                                  {new Date(fp.timestamp).toLocaleString()}
                                </span>
                              )}
                            </div>
                            <div className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs">
                              {fp.device_type && <><span className="text-muted-foreground">Category:</span><span>{fp.device_type}</span></>}
                              {fp.manufacturer && <><span className="text-muted-foreground">Vendor:</span><span>{fp.manufacturer}</span></>}
                              {fp.os_family && <><span className="text-muted-foreground">OS:</span><span>{fp.os_family}</span></>}
                              {fp.hostname && <><span className="text-muted-foreground">Hostname:</span><span className="font-mono">{fp.hostname}</span></>}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })()}

                {/* Recent observations — deduplicated by source */}
                {detail.recent_observations && detail.recent_observations.length > 0 && (() => {
                  const deduped = deduplicateObs(detail.recent_observations);
                  return (
                    <div className="space-y-2">
                      <h4 className="text-[11px] font-semibold text-muted-foreground">
                        Observation Sources ({detail.recent_observations.length} total)
                      </h4>
                      <div className="space-y-1">
                        {deduped.map((group, i) => (
                          <div key={i} className="flex items-center gap-3 text-xs rounded-lg bg-muted/20 px-3 py-2">
                            <Badge variant="outline" className="text-[9px] font-mono shrink-0">{group.latest.source_type}</Badge>
                            <span className="flex-1 truncate text-muted-foreground">
                              {formatObsData(group.latest) || `${group.count} observation${group.count !== 1 ? "s" : ""}`}
                            </span>
                            <Badge
                              variant="secondary"
                              className={cn(
                                "text-[9px] shrink-0",
                                group.maxConfidence >= 80 && "bg-success/20 text-success",
                                group.maxConfidence >= 50 && group.maxConfidence < 80 && "bg-yellow-500/20 text-yellow-500",
                              )}
                            >
                              {group.maxConfidence}%
                            </Badge>
                            {group.count > 1 && (
                              <span className="text-[10px] text-muted-foreground shrink-0">{group.count}x</span>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })()}

                {/* Evidence summary — only show meaningful keys */}
                {detail.evidence && typeof detail.evidence === "object" && (() => {
                  const meaningful = Object.entries(detail.evidence).filter(
                    ([key]) => !["chain", "raw", "_finding"].includes(key) && key !== "source_count"
                  );
                  if (meaningful.length === 0) return null;
                  return (
                    <div className="space-y-2">
                      <h4 className="text-[11px] font-semibold text-muted-foreground">Evidence Summary</h4>
                      <div className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs rounded-lg bg-muted/20 px-3 py-2">
                        {meaningful.map(([key, val]) => (
                          <span key={key} className="contents">
                            <span className="text-muted-foreground capitalize">{key.replace(/_/g, " ")}:</span>
                            <span>{typeof val === "object" ? JSON.stringify(val).slice(0, 100) : String(val)}</span>
                          </span>
                        ))}
                      </div>
                    </div>
                  );
                })()}
              </div>
            </div>
          ) : (
            <div className="p-5">
              <p className="text-xs text-muted-foreground">Loading details...</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════
//  Main Component
// ═══════════════════════════════════════════

export default function ThreatDetection() {
  const queryClient = useQueryClient();

  // Tab state
  const [activeTab, setActiveTab] = useState<string>("dashboard");

  // Data queries
  const [showResolved, setShowResolved] = useState(false);
  const { data: incidentData } = useQuery({
    queryKey: ["incidents", showResolved],
    queryFn: () => fetchIncidents(showResolved),
    refetchInterval: 15000,
  });
  const { data: stats } = useQuery({ queryKey: ["incident-stats"], queryFn: fetchIncidentStats, refetchInterval: 30000 });
  const { data: timelineData } = useQuery({ queryKey: ["incident-timeline"], queryFn: fetchIncidentTimeline, refetchInterval: 60000 });
  const { data: topDevicesData } = useQuery({ queryKey: ["incident-top-devices"], queryFn: fetchIncidentTopDevices, refetchInterval: 30000 });
  const { data: bindings = [] } = useQuery({ queryKey: ["trusted-bindings"], queryFn: fetchTrustedBindings });
  const { data: rules = [] } = useQuery({ queryKey: ["suppression-rules"], queryFn: fetchSuppressionRules });

  const incidents = incidentData?.incidents ?? [];
  const timeline = timelineData?.timeline ?? [];
  const topDevices = topDevicesData?.devices ?? [];

  // Findings tab state
  const [severityFilter, setSeverityFilter] = useState("all");
  const [ruleFilter, setRuleFilter] = useState("all");
  const [searchText, setSearchText] = useState("");
  const [expandedIncidentId, setExpandedIncidentId] = useState<string | null>(null);
  const [detailCache, setDetailCache] = useState<Record<string, IncidentDetail>>({});

  // Undo resolve: track pending resolves with timers
  const pendingResolves = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  const [pendingIds, setPendingIds] = useState<Set<string>>(new Set());

  const resolveWithUndo = useCallback((incidentId: string, disposition: string) => {
    // Mark as pending immediately (visual feedback)
    setPendingIds(prev => { const next = new Set(prev); next.add(incidentId); return next; });
    setExpandedIncidentId(null);

    const label = disposition.replace("_", " ");

    // Set timer to actually resolve after 5 seconds
    const timer = setTimeout(async () => {
      pendingResolves.current.delete(incidentId);
      setPendingIds(prev => { const next = new Set(prev); next.delete(incidentId); return next; });
      await resolveIncident(incidentId, disposition);
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["incident-stats"] });
    }, 5000);
    pendingResolves.current.set(incidentId, timer);

    toast(`Marked as ${label}`, {
      description: "Undo within 5 seconds",
      action: {
        label: "Undo",
        onClick: () => {
          clearTimeout(timer);
          pendingResolves.current.delete(incidentId);
          setPendingIds(prev => { const next = new Set(prev); next.delete(incidentId); return next; });
          toast.success("Action undone");
        },
      },
      duration: 5000,
    });
  }, [queryClient]);

  // Exclusions tab state
  const [exclusionType, setExclusionType] = useState("trusted_binding");
  const [exMac, setExMac] = useState("");
  const [exIp, setExIp] = useState("");
  const [exSubtype, setExSubtype] = useState("");
  const [exReason, setExReason] = useState("");

  // --- Available rule types for filter ---
  const availableRules = useMemo(() => {
    const set = new Set(incidents.map((i) => i.subtype));
    return Array.from(set).sort();
  }, [incidents]);

  // --- Category chart data ---
  const categoryChartData = useMemo(() => {
    return (stats?.categories ?? []).map((c) => ({
      name: SUBTYPE_LABELS[c.name] ?? c.name,
      count: c.count,
      color: CATEGORY_COLORS[c.name] ?? "#6b7280",
    }));
  }, [stats]);

  // --- Handlers ---

  const handleAddExclusion = async () => {
    try {
      if (exclusionType === "trusted_binding") {
        if (!exMac.trim() || !exIp.trim()) { toast.error("MAC and IP required"); return; }
        await addTrustedBinding(exMac.trim(), exIp.trim());
        toast.success("Trusted binding added");
      } else {
        await addSuppressionRule({
          mac: exMac.trim() || undefined,
          ip: exIp.trim() || undefined,
          subtype: exSubtype.trim() || undefined,
          reason: exReason.trim() || undefined,
        });
        toast.success("Suppression rule added");
      }
      setExMac(""); setExIp(""); setExSubtype(""); setExReason("");
      queryClient.invalidateQueries({ queryKey: ["trusted-bindings"] });
      queryClient.invalidateQueries({ queryKey: ["suppression-rules"] });
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
    } catch (err) {
      toast.error(`Failed to add exclusion: ${err}`);
    }
  };

  const handleRemoveBinding = async (mac: string) => {
    try {
      await removeTrustedBinding(mac);
      toast.success("Binding removed");
      queryClient.invalidateQueries({ queryKey: ["trusted-bindings"] });
    } catch (err) {
      toast.error(`Failed: ${err}`);
    }
  };

  const handleRemoveRule = async (id: number) => {
    try {
      await removeSuppressionRule(id);
      toast.success("Rule removed");
      queryClient.invalidateQueries({ queryKey: ["suppression-rules"] });
    } catch (err) {
      toast.error(`Failed: ${err}`);
    }
  };

  // --- Render helpers ---

  const renderFindingCard = (incident: Incident) => (
    <CollapsibleFindingCard
      key={incident.id}
      incident={incident}
      expanded={expandedIds.has(incident.id)}
      onToggle={() => toggleExpanded(incident.id)}
      selected={selectedIds.has(incident.id)}
      onSelect={(checked) => toggleSelected(incident.id, checked)}
      detail={detailCache[incident.id] ?? null}
      onDismiss={() => {
        setSelectedIds(new Set([incident.id]));
        handleBulkAction("resolve");
      }}
      onSuppress={() => handleSuppress(incident)}
    />
  );

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
                {tab.id === "findings" && incidents.length > 0 && (
                  <Badge variant="secondary" className="ml-1 text-[10px] h-4 px-1.5">{incidents.length}</Badge>
                )}
                {tab.id === "exclusions" && (bindings.length + rules.length) > 0 && (
                  <Badge variant="secondary" className="ml-1 text-[10px] h-4 px-1.5">{bindings.length + rules.length}</Badge>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* ════════════════════════════════════════
          Dashboard Tab
         ════════════════════════════════════════ */}
      {activeTab === "dashboard" && (
        <div className="space-y-5">
          {/* Info card */}
          <div className="rounded-xl bg-primary/[0.04] border border-primary/20 p-4">
            <div className="flex items-start gap-3">
              <Info size={18} className="text-primary shrink-0 mt-0.5" />
              <div className="space-y-1.5">
                <h3 className="text-sm font-semibold">About Detections</h3>
                <p className="text-xs text-muted-foreground leading-relaxed">
                  Leetha continuously monitors network traffic for anomalous behavior, identity changes, and security events.
                  Detections include <span className="text-foreground font-medium">identity shifts</span> (device fingerprint changes),{" "}
                  <span className="text-foreground font-medium">address conflicts</span> (multiple MACs claiming the same IP),{" "}
                  <span className="text-foreground font-medium">DHCP anomalies</span> (rogue servers, starvation),{" "}
                  <span className="text-foreground font-medium">behavioral drift</span> (DNS affinity changes), and{" "}
                  <span className="text-foreground font-medium">sensor events</span> (remote sensor connect/disconnect).
                </p>
                <div className="flex flex-wrap gap-2 pt-1">
                  {["Identity Shift", "Address Conflict", "DHCP Anomaly", "Behavioral Drift", "MAC Spoofing", "Sensor Events"].map((tag) => (
                    <span key={tag} className="text-[10px] px-2 py-0.5 rounded-full border border-border bg-card text-muted-foreground">{tag}</span>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Stat cards with trends */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {[
              { key: "threat" as const, label: "THREAT", icon: ShieldAlert, color: "text-red-400" },
              { key: "suspicious" as const, label: "SUSPICIOUS", icon: AlertTriangle, color: "text-yellow-400" },
              { key: "informational" as const, label: "INFORMATIONAL", icon: Info, color: "text-blue-400" },
              { key: "total" as const, label: "TOTAL", icon: Shield, color: "text-foreground" },
            ].map((s) => {
              const count = stats?.severity?.[s.key] ?? 0;
              const trend = stats?.trends?.[s.key];
              return (
                <div key={s.key} className="rounded-xl bg-card border border-border p-5">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <s.icon size={14} className={s.color} />
                        <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">{s.label}</span>
                      </div>
                      <p className="text-2xl font-bold">{count}</p>
                    </div>
                    {trend && trend.direction !== "flat" && (
                      <div className={cn("flex items-center gap-1 text-xs", trend.direction === "up" ? "text-red-400" : "text-green-400")}>
                        {trend.direction === "up" ? <TrendingUp size={14} /> : <TrendingDown size={14} />}
                        <span>{trend.percentage}%</span>
                      </div>
                    )}
                    {trend?.direction === "flat" && (
                      <div className="flex items-center gap-1 text-xs text-muted-foreground">
                        <Minus size={14} />
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Timeline chart */}
          {timeline.length > 0 && (
            <div className="rounded-xl bg-card border border-border p-5">
              <h3 className="text-sm font-semibold mb-1">Findings Over Time</h3>
              <p className="text-[10px] text-muted-foreground mb-4">Last 7 days, grouped by severity</p>
              <div style={{ height: 200 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timeline} margin={{ left: 0, right: 0, top: 0, bottom: 0 }}>
                    <XAxis dataKey="date" tick={{ fontSize: 10, fill: "#71717a" }} tickLine={false} axisLine={false} tickFormatter={(v) => v.slice(5)} />
                    <YAxis tick={{ fontSize: 10, fill: "#71717a" }} tickLine={false} axisLine={false} allowDecimals={false} width={30} />
                    <Tooltip content={<ChartTooltip />} />
                    <Area type="monotone" dataKey="threat" stackId="1" fill="#ef4444" stroke="#ef4444" fillOpacity={0.3} name="Threat" />
                    <Area type="monotone" dataKey="suspicious" stackId="1" fill="#eab308" stroke="#eab308" fillOpacity={0.3} name="Suspicious" />
                    <Area type="monotone" dataKey="informational" stackId="1" fill="#3b82f6" stroke="#3b82f6" fillOpacity={0.3} name="Informational" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* Category breakdown */}
          {categoryChartData.length > 0 && (
            <div className="rounded-xl bg-card border border-border p-5">
              <h3 className="text-sm font-semibold mb-1">Detection Type Breakdown</h3>
              <p className="text-[10px] text-muted-foreground mb-4">Active findings grouped by detection rule</p>
              <div style={{ height: Math.max(categoryChartData.length * 44, 120) }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={categoryChartData} layout="vertical" margin={{ left: 0, right: 15, top: 0, bottom: 0 }}>
                    <XAxis type="number" tick={{ fontSize: 10, fill: "#71717a" }} tickLine={false} axisLine={false} allowDecimals={false} />
                    <YAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: "#a1a1aa" }} tickLine={false} axisLine={false} width={140} />
                    <Tooltip content={<ChartTooltip />} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={20}>
                      {categoryChartData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* Most Targeted Devices */}
          {topDevices.length > 0 && (
            <div className="rounded-xl bg-card border border-border p-5">
              <h3 className="text-sm font-semibold mb-1">Most Targeted Devices</h3>
              <p className="text-[10px] text-muted-foreground mb-4">Devices with the highest number of active findings</p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5">
                {topDevices.map((d, i) => (
                  <div key={d.hw_addr} className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-secondary/30 transition-colors">
                    <span className="text-[10px] font-bold text-muted-foreground w-5 shrink-0">#{i + 1}</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-mono truncate">{d.hw_addr}</span>
                        {d.ip_addr && <span className="text-xs text-muted-foreground">{d.ip_addr}</span>}
                      </div>
                      {d.vendor && <span className="text-[10px] text-muted-foreground">{d.vendor}</span>}
                      <div className="h-1 bg-muted/50 rounded-full mt-1 overflow-hidden">
                        <div className="h-full rounded-full bg-destructive/60" style={{ width: `${d.bar_width}%` }} />
                      </div>
                    </div>
                    <Badge variant="secondary" className="text-xs shrink-0">{d.finding_count}</Badge>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recent Findings preview */}
          {incidents.length > 0 && (
            <div className="rounded-xl bg-card border border-border p-5">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold">Recent Findings</h3>
                <button onClick={() => setActiveTab("findings")} className="text-xs text-primary hover:underline">
                  View all {incidents.length} findings
                </button>
              </div>
              <div className="space-y-2">
                {incidents.slice(0, 5).map((incident) => (
                  <div key={incident.id} className={cn("flex items-center gap-3 px-3 py-2 rounded-lg border border-border", SEVERITY_COLORS[incident.severity]?.bg)}>
                    <SeverityBadge severity={incident.severity} />
                    <span className="text-xs flex-1 truncate">{incident.summary}</span>
                    <span className="text-[10px] font-mono text-muted-foreground">{incident.device_mac}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Empty state */}
          {incidents.length === 0 && !stats && (
            <div className="rounded-xl bg-card border border-border flex flex-col items-center justify-center py-16 text-muted-foreground">
              <Shield size={32} className="mb-3" />
              <p className="font-medium text-foreground">No detections yet</p>
              <p className="text-xs mt-1">Start a capture to monitor network traffic for anomalies and threats.</p>
            </div>
          )}
        </div>
      )}

      {/* ════════════════════════════════════════
          Findings Tab — Accordion Cards
         ════════════════════════════════════════ */}
      {activeTab === "findings" && (() => {
        // Filter incidents for the card list
        const allIncidents = incidents;
        const severityCounts = {
          threat: allIncidents.filter(i => i.severity === "threat").length,
          suspicious: allIncidents.filter(i => i.severity === "suspicious").length,
          informational: allIncidents.filter(i => i.severity === "informational").length,
        };

        // Apply filters — matching incidents stay visible, non-matching fade
        const matchesFilters = (i: Incident) => {
          if (severityFilter !== "all" && i.severity !== severityFilter) return false;
          if (ruleFilter !== "all" && i.subtype !== ruleFilter) return false;
          return true;
        };

        const matchesSearch = (i: Incident) => {
          if (!searchText) return true;
          const q = searchText.toLowerCase();
          return (
            i.device_mac.toLowerCase().includes(q) ||
            (i.device_ip ?? "").toLowerCase().includes(q) ||
            (i.manufacturer ?? "").toLowerCase().includes(q) ||
            i.summary.toLowerCase().includes(q) ||
            (SUBTYPE_LABELS[i.subtype] ?? i.subtype).toLowerCase().includes(q)
          );
        };

        // Sort: matching cards first (newest first), then non-matching (faded, at bottom)
        const sorted = [...allIncidents].sort((a, b) => {
          const aMatch = matchesFilters(a) && matchesSearch(a);
          const bMatch = matchesFilters(b) && matchesSearch(b);
          if (aMatch !== bMatch) return aMatch ? -1 : 1;
          return new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime();
        });

        const visibleCount = sorted.filter(i => matchesFilters(i) && matchesSearch(i)).length;

        return (
        <div className="space-y-3">
          {/* Search bar */}
          <div className="relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <Input
              className="pl-9 h-9 text-sm"
              placeholder="Search MAC, IP, vendor, hostname..."
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
            />
            {searchText && (
              <button
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                onClick={() => setSearchText("")}
              >
                <X size={14} />
              </button>
            )}
          </div>

          {/* Severity pills + Rule dropdown + Export */}
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => setSeverityFilter("all")}
              className={cn(
                "px-2.5 py-1 rounded-full text-[11px] font-semibold uppercase transition-colors",
                severityFilter === "all"
                  ? "bg-primary/10 text-primary"
                  : "bg-muted/30 text-muted-foreground hover:bg-muted/50"
              )}
            >
              All
            </button>
            {(["threat", "suspicious", "informational"] as const).map((sev) => {
              const colors = SEVERITY_COLORS[sev];
              const isActive = severityFilter === sev;
              const count = severityCounts[sev];
              return (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(isActive ? "all" : sev)}
                  className={cn(
                    "px-2.5 py-1 rounded-full text-[11px] font-semibold uppercase transition-colors",
                    isActive
                      ? `${colors.bg} ${colors.text}`
                      : "bg-muted/30 text-muted-foreground hover:bg-muted/50"
                  )}
                >
                  {sev}
                  {count > 0 && <span className="ml-1 opacity-70">{count}</span>}
                </button>
              );
            })}

            <div className="w-px h-5 bg-border" />

            <Select value={ruleFilter} onValueChange={setRuleFilter}>
              <SelectTrigger className="w-44 h-8 text-xs">
                <SelectValue placeholder="All Rules" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Rules</SelectItem>
                {availableRules.map((r) => (
                  <SelectItem key={r} value={r}>
                    {SUBTYPE_LABELS[r] ?? r}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <div className="ml-auto flex gap-1.5">
              <Button variant="outline" size="sm" className="text-xs h-7 gap-1" onClick={() => window.open(exportFindingsUrl("json"), "_blank")}>
                <Download size={12} /> JSON
              </Button>
              <Button variant="outline" size="sm" className="text-xs h-7 gap-1" onClick={() => window.open(exportFindingsUrl("csv"), "_blank")}>
                <Download size={12} /> CSV
              </Button>
            </div>
          </div>

          {/* Results count + Show Resolved toggle */}
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted-foreground">
              Showing {visibleCount} of {allIncidents.length} finding{allIncidents.length !== 1 ? "s" : ""}
            </span>
            <button
              onClick={() => setShowResolved(!showResolved)}
              className={cn(
                "text-xs px-2.5 py-1 rounded-full transition-colors",
                showResolved
                  ? "bg-primary/10 text-primary"
                  : "bg-muted/30 text-muted-foreground hover:bg-muted/50"
              )}
            >
              {showResolved ? "Hide Resolved" : "Show Resolved"}
            </button>
          </div>

          {/* Card list */}
          <div className="space-y-2">
            {sorted.length === 0 && (
              <div className="rounded-xl bg-card border border-border flex flex-col items-center justify-center py-16 text-muted-foreground">
                <Shield size={32} className="mb-3" />
                <p className="font-medium text-foreground">No findings</p>
                <p className="text-xs mt-1">No detections have been recorded yet.</p>
              </div>
            )}

            {sorted.map((incident) => {
              const isMatch = matchesFilters(incident) && matchesSearch(incident);
              const isExpanded = expandedIncidentId === incident.id;
              const colors = SEVERITY_COLORS[incident.severity] ?? SEVERITY_COLORS.informational;
              const showExpanded = isMatch && isExpanded;
              const isPending = pendingIds.has(incident.id);
              const isResolved = incident.status === "resolved" || incident.status === "false_positive";

              // Hide cards that are pending resolve (undo window active)
              if (isPending) return null;

              return (
                <div
                  key={incident.id}
                  className={cn(
                    "transition-all duration-300",
                    !isMatch && "opacity-[0.15] pointer-events-none",
                    isResolved && "opacity-60",
                  )}
                >
                  {/* Collapsed card */}
                  <div
                    className={cn(
                      "rounded-lg bg-card border cursor-pointer transition-colors",
                      isExpanded ? "border-primary/40 shadow-md" : "border-border hover:border-primary/30 hover:shadow-sm",
                      colors.border, "border-l-[3px]"
                    )}
                    onClick={async () => {
                      if (isExpanded) {
                        setExpandedIncidentId(null);
                      } else {
                        setExpandedIncidentId(incident.id);
                        if (!detailCache[incident.id]) {
                          try {
                            const detail = await fetchIncidentDetail(incident.id);
                            setDetailCache((prev) => ({ ...prev, [incident.id]: detail }));
                          } catch { /* ignore */ }
                        }
                      }
                    }}
                  >
                    <div className="px-4 py-3">
                      {/* Line 1: severity badge + rule label + timestamp */}
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={incident.severity} />
                        <span className="text-sm font-semibold">
                          {SUBTYPE_LABELS[incident.subtype] ?? incident.subtype}
                        </span>
                        <span className="ml-auto text-xs text-muted-foreground">
                          {relativeTime(incident.last_seen)}
                        </span>
                        <ChevronDown
                          size={16}
                          className={cn(
                            "text-muted-foreground transition-transform duration-200",
                            isExpanded && "rotate-180"
                          )}
                        />
                      </div>

                      {/* Line 2: device info */}
                      <div className="flex items-center gap-2 mt-1.5 text-sm">
                        {incident.manufacturer && (
                          <span className="font-medium">{incident.manufacturer}</span>
                        )}
                        {incident.device_ip && (
                          <span className="text-muted-foreground">{incident.device_ip}</span>
                        )}
                        <span className="font-mono text-xs text-muted-foreground">
                          {incident.device_mac}
                        </span>
                      </div>

                      {/* Line 3: finding message + resolved badge */}
                      <div className="flex items-center gap-2 mt-1">
                        <p className="text-xs text-muted-foreground truncate flex-1">
                          {incident.summary}
                        </p>
                        {isResolved && (
                          <Badge variant="outline" className="text-[10px] shrink-0 capitalize opacity-70">
                            {incident.disposition?.replace("_", " ") ?? "resolved"}
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Expanded detail */}
                  {showExpanded && (
                    <div className="rounded-b-lg border border-t-0 border-border bg-card/50 overflow-hidden animate-in slide-in-from-top-1 duration-200">
                      <div className="px-5 py-5 space-y-6">
                        {!detailCache[incident.id] ? (
                          <p className="text-sm text-muted-foreground">Loading details...</p>
                        ) : (() => {
                          const detail = detailCache[incident.id];
                          const dev = detail.device as any;
                          const ctx = detail.detection_context;
                          const alerts = (detail as any)?.alert_messages ?? [];
                          const confColor = (c: number) =>
                            c >= 80 ? "hsl(var(--success))" : c >= 50 ? "hsl(var(--warning))" : "hsl(var(--destructive))";

                          return (
                            <>
                              {/* 1. WHY THIS TRIGGERED */}
                              {ctx && (
                                <div className="space-y-3">
                                  <h3 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                                    Why This Triggered
                                  </h3>
                                  {ctx.recommendation && (
                                    <div className="rounded-lg bg-yellow-500/[0.06] border border-yellow-500/20 p-4">
                                      <div className="flex items-start gap-2">
                                        <AlertTriangle size={14} className="text-yellow-500 mt-0.5 shrink-0" />
                                        <p className="text-sm leading-relaxed">
                                          {ctx.recommendation.replace(/^(CRITICAL|HIGH|WARNING|INFO):\s*/i, "")}
                                        </p>
                                      </div>
                                    </div>
                                  )}
                                  <div className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
                                    <span className="text-muted-foreground">Rule:</span>
                                    <span className="font-mono">{ctx.rule}</span>
                                    <span className="text-muted-foreground">Trigger:</span>
                                    <span>{ctx.trigger}</span>
                                    <span className="text-muted-foreground">Method:</span>
                                    <span className="text-muted-foreground">{ctx.method}</span>
                                  </div>
                                </div>
                              )}

                              {/* 2. DEVICE IDENTITY + CLASSIFICATION (side by side) */}
                              {dev && (
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                  <div className="space-y-3">
                                    <h3 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                                      Device Identity
                                    </h3>
                                    <div className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
                                      <span className="text-muted-foreground">MAC:</span>
                                      <span className="font-mono">{dev.mac ?? incident.device_mac}</span>
                                      <span className="text-muted-foreground">Hostname:</span>
                                      <span>{dev.hostname || "—"}</span>
                                      <span className="text-muted-foreground">Vendor:</span>
                                      <span>{dev.manufacturer || incident.manufacturer || "—"}</span>
                                      <span className="text-muted-foreground">IPv4:</span>
                                      <span className="font-mono">{dev.ip_v4 || incident.device_ip || "—"}</span>
                                      <span className="text-muted-foreground">IPv6:</span>
                                      <span className="font-mono break-all">{dev.ip_v6 || "—"}</span>
                                    </div>
                                  </div>
                                  <div className="space-y-3">
                                    <h3 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                                      Classification
                                    </h3>
                                    <div className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
                                      <span className="text-muted-foreground">Category:</span>
                                      <span>{dev.device_type || "—"}</span>
                                      <span className="text-muted-foreground">Platform:</span>
                                      <span>{dev.os_family || "—"}</span>
                                      <span className="text-muted-foreground">Version:</span>
                                      <span>{dev.os_version || "—"}</span>
                                      <span className="text-muted-foreground">Certainty:</span>
                                      <div className="flex items-center gap-2">
                                        <span className="font-bold" style={{ color: confColor(dev.confidence ?? 0) }}>
                                          {dev.confidence ?? 0}%
                                        </span>
                                        <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden max-w-[100px]">
                                          <div
                                            className="h-full rounded-full transition-all"
                                            style={{
                                              width: `${dev.confidence ?? 0}%`,
                                              background: confColor(dev.confidence ?? 0),
                                            }}
                                          />
                                        </div>
                                      </div>
                                    </div>
                                  </div>
                                </div>
                              )}

                              {/* 3. FINGERPRINT EVIDENCE */}
                              {detail.fingerprint_history && detail.fingerprint_history.length > 0 && (() => {
                                const seen = new Map<string, any>();
                                for (const fp of detail.fingerprint_history) {
                                  const key = `${fp.source}|${fp.device_type || ""}|${fp.manufacturer || ""}`;
                                  if (!seen.has(key) && (fp.device_type || fp.manufacturer || fp.os_family || fp.hostname))
                                    seen.set(key, fp);
                                }
                                const deduped = Array.from(seen.values());
                                if (deduped.length === 0) return null;
                                return (
                                  <div className="space-y-3">
                                    <h3 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                                      Fingerprint Evidence
                                    </h3>
                                    <div className="overflow-x-auto">
                                      <table className="w-full text-sm">
                                        <thead>
                                          <tr className="text-xs text-muted-foreground border-b border-border">
                                            <th className="text-left py-2 pr-4 font-medium">Time</th>
                                            <th className="text-left py-2 pr-4 font-medium">Source</th>
                                            <th className="text-left py-2 pr-4 font-medium">Category</th>
                                            <th className="text-left py-2 pr-4 font-medium">Vendor</th>
                                            <th className="text-left py-2 pr-4 font-medium">OS</th>
                                            <th className="text-left py-2 font-medium">Hostname</th>
                                          </tr>
                                        </thead>
                                        <tbody>
                                          {deduped.map((fp: any, i: number) => (
                                            <tr key={i} className="border-b border-border/50">
                                              <td className="py-2 pr-4 text-muted-foreground text-xs">
                                                {fp.timestamp ? relativeTime(fp.timestamp) : "—"}
                                              </td>
                                              <td className="py-2 pr-4">
                                                <Badge variant="outline" className="text-[10px] font-mono">{fp.source}</Badge>
                                              </td>
                                              <td className="py-2 pr-4">{fp.device_type || "—"}</td>
                                              <td className="py-2 pr-4">{fp.manufacturer || "—"}</td>
                                              <td className="py-2 pr-4">{fp.os_family || "—"}</td>
                                              <td className="py-2 font-mono text-xs">{fp.hostname || "—"}</td>
                                            </tr>
                                          ))}
                                        </tbody>
                                      </table>
                                    </div>
                                  </div>
                                );
                              })()}

                              {/* 4. ARP BINDINGS */}
                              {detail.arp_history && detail.arp_history.length > 0 && (
                                <div className="space-y-3">
                                  <h3 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                                    ARP Bindings
                                  </h3>
                                  <div className="overflow-x-auto">
                                    <table className="w-full text-sm">
                                      <thead>
                                        <tr className="text-xs text-muted-foreground border-b border-border">
                                          <th className="text-left py-2 pr-4 font-medium">IP</th>
                                          <th className="text-left py-2 pr-4 font-medium">Interface</th>
                                          <th className="text-left py-2 pr-4 font-medium">Packets</th>
                                          <th className="text-left py-2 font-medium">Last Seen</th>
                                        </tr>
                                      </thead>
                                      <tbody>
                                        {detail.arp_history.map((h: any, i: number) => (
                                          <tr key={i} className="border-b border-border/50">
                                            <td className="py-2 pr-4 font-mono">{h.ip}</td>
                                            <td className="py-2 pr-4 text-muted-foreground">{h.interface || "—"}</td>
                                            <td className="py-2 pr-4 text-muted-foreground">{h.packets ?? "—"}</td>
                                            <td className="py-2 text-xs text-muted-foreground">
                                              {h.last_seen ? relativeTime(h.last_seen) : "—"}
                                            </td>
                                          </tr>
                                        ))}
                                      </tbody>
                                    </table>
                                  </div>
                                </div>
                              )}

                              {/* 5. RECENT OBSERVATIONS */}
                              {detail.recent_observations && detail.recent_observations.length > 0 && (() => {
                                const obsGrouped = new Map<string, { count: number; maxConf: number; lastTs: string }>();
                                for (const obs of detail.recent_observations) {
                                  const existing = obsGrouped.get(obs.source_type);
                                  if (!existing)
                                    obsGrouped.set(obs.source_type, { count: 1, maxConf: obs.confidence, lastTs: obs.timestamp });
                                  else {
                                    existing.count++;
                                    existing.maxConf = Math.max(existing.maxConf, obs.confidence);
                                  }
                                }
                                return (
                                  <div className="space-y-3">
                                    <h3 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                                      Recent Observations ({detail.recent_observations.length})
                                    </h3>
                                    <div className="overflow-x-auto">
                                      <table className="w-full text-sm">
                                        <thead>
                                          <tr className="text-xs text-muted-foreground border-b border-border">
                                            <th className="text-left py-2 pr-4 font-medium">Source</th>
                                            <th className="text-left py-2 pr-4 font-medium">Count</th>
                                            <th className="text-left py-2 pr-4 font-medium">Confidence</th>
                                            <th className="text-left py-2 font-medium">Last Seen</th>
                                          </tr>
                                        </thead>
                                        <tbody>
                                          {Array.from(obsGrouped.entries()).map(([source, data]) => (
                                            <tr key={source} className="border-b border-border/50">
                                              <td className="py-2 pr-4">
                                                <Badge variant="outline" className="text-[10px] font-mono">{source}</Badge>
                                              </td>
                                              <td className="py-2 pr-4 text-muted-foreground">
                                                {data.count}
                                              </td>
                                              <td className="py-2 pr-4">
                                                <span className={cn(
                                                  "font-medium",
                                                  data.maxConf >= 80 ? "text-green-400" : data.maxConf >= 50 ? "text-yellow-400" : "text-muted-foreground"
                                                )}>
                                                  {data.maxConf}%
                                                </span>
                                              </td>
                                              <td className="py-2 text-xs text-muted-foreground">
                                                {relativeTime(data.lastTs)}
                                              </td>
                                            </tr>
                                          ))}
                                        </tbody>
                                      </table>
                                    </div>
                                  </div>
                                );
                              })()}

                              {/* 6. ALERT HISTORY */}
                              {alerts.length > 0 && (
                                <div className="space-y-3">
                                  <h3 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                                    Alert History ({alerts.length})
                                  </h3>
                                  <div className="space-y-1.5">
                                    {alerts.slice(0, 10).map((a: any, i: number) => (
                                      <div key={i} className="rounded-lg bg-muted/20 px-4 py-2.5 text-sm flex items-start gap-3">
                                        <div className={cn("w-2 h-2 rounded-full mt-1.5 shrink-0", {
                                          "bg-red-500": a.severity === "critical" || a.severity === "high",
                                          "bg-yellow-500": a.severity === "warning",
                                          "bg-blue-500": a.severity === "info" || a.severity === "low",
                                        })} />
                                        <div className="flex-1 min-w-0">
                                          <p className="text-sm">{a.message}</p>
                                          <p className="text-[10px] text-muted-foreground mt-1">
                                            {new Date(a.timestamp).toLocaleString()}
                                          </p>
                                        </div>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {/* 7. ACTIONS + NOTES */}
                              <div className="space-y-4 pt-2 border-t border-border">
                                <div className="flex gap-2 flex-wrap items-center">
                                  {incident.status === "resolved" || incident.status === "false_positive" ? (
                                    <>
                                      <Badge variant="outline" className="text-xs capitalize">
                                        {incident.disposition?.replace("_", " ") ?? incident.status?.replace("_", " ")}
                                      </Badge>
                                      <Button
                                        size="sm"
                                        variant="outline"
                                        className="text-xs h-8"
                                        onClick={async (e) => {
                                          e.stopPropagation();
                                          await reopenIncident(incident.id);
                                          toast.success("Finding reopened");
                                          setExpandedIncidentId(null);
                                          queryClient.invalidateQueries({ queryKey: ["incidents"] });
                                          queryClient.invalidateQueries({ queryKey: ["incident-stats"] });
                                        }}
                                      >
                                        Reopen
                                      </Button>
                                    </>
                                  ) : (
                                    <>
                                      {(["true_positive", "false_positive", "benign"] as const).map((disp) => (
                                        <Button
                                          key={disp}
                                          size="sm"
                                          variant="outline"
                                          className="text-xs h-8 capitalize"
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            resolveWithUndo(incident.id, disp);
                                          }}
                                        >
                                          {disp.replace("_", " ")}
                                        </Button>
                                      ))}
                                      <Select onValueChange={async (v) => {
                                        const { snoozeIncident: si } = await import("@/lib/api");
                                        await si(incident.id, Number(v));
                                        toast.success(`Snoozed for ${v}h`);
                                        setExpandedIncidentId(null);
                                        queryClient.invalidateQueries({ queryKey: ["incidents"] });
                                      }}>
                                        <SelectTrigger className="w-28 h-8 text-xs">
                                          <SelectValue placeholder="Snooze..." />
                                        </SelectTrigger>
                                        <SelectContent>
                                          <SelectItem value="1">1 hour</SelectItem>
                                          <SelectItem value="4">4 hours</SelectItem>
                                          <SelectItem value="24">24 hours</SelectItem>
                                        </SelectContent>
                                      </Select>
                                    </>
                                  )}
                                </div>

                                <div>
                                  <h3 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground mb-2">
                                    Analyst Notes
                                  </h3>
                                  <textarea
                                    className="w-full h-20 rounded-lg border border-border bg-muted/20 px-4 py-3 text-sm resize-none focus:outline-none focus:ring-1 focus:ring-primary"
                                    placeholder="Add investigation notes..."
                                    defaultValue={(detail as any)?.notes ?? ""}
                                    onClick={(e) => e.stopPropagation()}
                                    onBlur={async (e) => {
                                      await saveIncidentNotes(incident.id, e.target.value);
                                    }}
                                  />
                                </div>
                              </div>
                            </>
                          );
                        })()}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
        );
      })()}

      {/* ════════════════════════════════════════
          Exclusions Tab
         ════════════════════════════════════════ */}
      {activeTab === "exclusions" && (
        <div className="space-y-6">
          {/* Add exclusion form */}
          <div className="rounded-xl bg-card border border-border overflow-hidden">
            <div className="px-5 py-3 border-b border-border">
              <h3 className="text-sm font-semibold">Add Exclusion</h3>
              <p className="text-[10px] text-muted-foreground mt-0.5">Add trusted bindings to allow known MAC-IP pairs, or suppression rules to silence specific detections.</p>
            </div>
            <div className="px-5 py-4">
              <div className="flex gap-3 items-end flex-wrap">
                <div>
                  <span className="text-xs text-muted-foreground">Type</span>
                  <Select value={exclusionType} onValueChange={setExclusionType}>
                    <SelectTrigger className="w-48 mt-1">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="trusted_binding">Trusted Binding</SelectItem>
                      <SelectItem value="suppression">Suppression Rule</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {exclusionType === "trusted_binding" ? (
                  <>
                    <div>
                      <span className="text-xs text-muted-foreground">MAC Address</span>
                      <Input placeholder="aa:bb:cc:dd:ee:ff" value={exMac} onChange={(e) => setExMac(e.target.value)} className="w-48 mt-1" />
                    </div>
                    <div>
                      <span className="text-xs text-muted-foreground">IP Address</span>
                      <Input placeholder="192.168.1.1" value={exIp} onChange={(e) => setExIp(e.target.value)} className="w-48 mt-1" />
                    </div>
                  </>
                ) : (
                  <>
                    <div>
                      <span className="text-xs text-muted-foreground">MAC (optional)</span>
                      <Input placeholder="aa:bb:cc:dd:ee:ff" value={exMac} onChange={(e) => setExMac(e.target.value)} className="w-40 mt-1" />
                    </div>
                    <div>
                      <span className="text-xs text-muted-foreground">IP (optional)</span>
                      <Input placeholder="192.168.1.1" value={exIp} onChange={(e) => setExIp(e.target.value)} className="w-40 mt-1" />
                    </div>
                    <div>
                      <span className="text-xs text-muted-foreground">Subtype (optional)</span>
                      <Input placeholder="dhcp_anomaly" value={exSubtype} onChange={(e) => setExSubtype(e.target.value)} className="w-40 mt-1" />
                    </div>
                    <div>
                      <span className="text-xs text-muted-foreground">Reason</span>
                      <Input placeholder="Known device" value={exReason} onChange={(e) => setExReason(e.target.value)} className="w-48 mt-1" />
                    </div>
                  </>
                )}

                <Button size="sm" className="text-xs h-9 gap-1.5" onClick={handleAddExclusion}>
                  <Plus size={14} />
                  Add
                </Button>
              </div>
            </div>
          </div>

          {/* Existing exclusions */}
          <div className="rounded-xl bg-card border border-border overflow-hidden">
            <div className="px-5 py-3 border-b border-border flex items-center gap-2">
              <h3 className="text-sm font-semibold">Active Exclusions</h3>
              <Badge variant="secondary" className="text-[10px]">{bindings.length + rules.length}</Badge>
            </div>
            <div className="divide-y divide-border">
              {bindings.map((b) => (
                <div key={b.mac} className="flex items-center justify-between px-5 py-3">
                  <div className="flex items-center gap-3">
                    <Badge variant="outline" className="text-[10px] uppercase font-semibold bg-green-500/10 text-green-400 border-green-500/30">Trusted</Badge>
                    <span className="font-mono text-sm">{b.mac}</span>
                    <span className="text-xs text-muted-foreground">{b.ip}</span>
                  </div>
                  <Button variant="ghost" size="sm" className="text-destructive hover:text-destructive h-7 w-7 p-0" onClick={() => handleRemoveBinding(b.mac)}>
                    <Trash2 size={14} />
                  </Button>
                </div>
              ))}
              {rules.map((r) => (
                <div key={r.id} className="flex items-center justify-between px-5 py-3">
                  <div className="flex items-center gap-3">
                    <Badge variant="outline" className="text-[10px] uppercase font-semibold bg-yellow-500/10 text-yellow-400 border-yellow-500/30">Suppression</Badge>
                    {r.mac && <span className="font-mono text-sm">{r.mac}</span>}
                    {r.ip && <span className="text-xs">{r.ip}</span>}
                    {r.subtype && <Badge variant="secondary" className="text-[10px]">{SUBTYPE_LABELS[r.subtype] ?? r.subtype}</Badge>}
                    {r.reason && <span className="text-xs text-muted-foreground italic">{r.reason}</span>}
                  </div>
                  <Button variant="ghost" size="sm" className="text-destructive hover:text-destructive h-7 w-7 p-0" onClick={() => handleRemoveRule(r.id)}>
                    <Trash2 size={14} />
                  </Button>
                </div>
              ))}
              {bindings.length === 0 && rules.length === 0 && (
                <div className="px-5 py-12 text-center text-muted-foreground">
                  <Ban size={24} className="mx-auto mb-2 opacity-50" />
                  <p className="text-xs">No exclusions configured. Add trusted bindings or suppression rules above.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
