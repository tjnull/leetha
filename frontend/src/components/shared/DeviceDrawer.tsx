import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Collapsible, CollapsibleTrigger, CollapsibleContent } from "@/components/ui/collapsible";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn } from "@/lib/utils";
import { getDeviceTypeColor } from "@/lib/constants";
import { toast } from "sonner";
import { X, ChevronDown } from "lucide-react";
import { authHeaders, fetchDeviceTimeline, type TimelineEvent } from "@/lib/api";
import { CustomProperties, type CustomPropsValues } from "@/components/shared/CustomProperties";
import { CriticalityPill, type Criticality } from "@/components/CriticalityPill";

// --- API ---

async function apiFetch<T>(url: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(url, { ...opts, headers: authHeaders({ "Content-Type": "application/json", ...opts?.headers }) });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

interface DeviceInfo {
  mac: string; primary_mac?: string; ip_v4: string | null; ip_v6: string | null;
  manufacturer: string | null; device_type: string | null; os_family: string | null;
  os_version: string | null; hostname: string | null; model: string | null; confidence: number;
  is_randomized_mac: boolean; correlated_mac: string | null;
  first_seen: string | null; last_seen: string | null;
  alert_status: string | null; manual_override: Record<string, string> | null;
  // Phase A.1 custom properties (merged from devices table row)
  owner?: string | null;
  location?: string | null;
  criticality?: Criticality;
  tags?: string[];
  notes?: string | null;
}
interface DeviceDetailResponse { device: DeviceInfo; evidence: Array<Record<string, unknown>>; }
interface Observation { id: number; timestamp: string; source_type: string; confidence: number | null; }
interface ServiceResult {
  port?: number; protocol: string; result?: string | Record<string, unknown>;
  service?: string; banner?: string; sni?: string; timestamp?: string;
  details?: Record<string, unknown>;
}

function formatTs(ts: string | null): string {
  if (!ts) return "-";
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}
function confColor(c: number): string {
  if (c >= 80) return "hsl(var(--success))"; if (c >= 50) return "hsl(var(--warning))"; return "hsl(var(--destructive))";
}
function statusCls(s: string): string {
  if (s === "suspicious") return "text-red-400 bg-red-400/10 border-red-400/30";
  if (s === "known") return "text-blue-400 bg-blue-400/10 border-blue-400/30";
  if (s === "self") return "text-yellow-400 bg-yellow-400/10 border-yellow-400/30";
  return "text-green-400 bg-green-400/10 border-green-400/30";
}

function formatRelativeTime(date: Date): string {
  const now = Date.now();
  const diff = now - date.getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return date.toLocaleDateString();
}

// --- Components ---

interface DeviceDrawerProps { mac: string | null; open: boolean; onClose: () => void; }

export function DeviceDrawer({ mac, open, onClose }: DeviceDrawerProps) {
  const queryClient = useQueryClient();

  const { data: detailData, isLoading } = useQuery({
    queryKey: ["device-detail", mac],
    queryFn: () => apiFetch<DeviceDetailResponse>(`/api/devices/${encodeURIComponent(mac!)}/detail`),
    enabled: !!mac && open,
  });
  const { data: obsData } = useQuery({
    queryKey: ["device-observations", mac],
    queryFn: () => apiFetch<{ observations: Observation[] }>(`/api/devices/${encodeURIComponent(mac!)}/observations?limit=20`),
    enabled: !!mac && open,
  });
  const { data: svcData } = useQuery({
    queryKey: ["device-services", mac],
    queryFn: () => apiFetch<{ services: ServiceResult[] }>(`/api/devices/${encodeURIComponent(mac!)}/services`),
    enabled: !!mac && open,
  });
  const { data: activityData } = useQuery({
    queryKey: ["device-activity", mac],
    queryFn: () => apiFetch<{ hourly_counts: number[] }>(`/api/devices/${encodeURIComponent(mac!)}/activity`),
    enabled: !!mac && open,
  });

  const { data: timelineData } = useQuery({
    queryKey: ["device-timeline", mac],
    queryFn: () => fetchDeviceTimeline(mac!),
    enabled: !!mac && open,
  });

  const { data: coverageData } = useQuery({
    queryKey: ["device-coverage", mac],
    queryFn: () => apiFetch<{
      quality: string; source_count: number; evidence_count: number;
      observed: Array<{ source: string; count: number; last_seen: string; provides: string[]; layer: string }>;
      missing: Array<{ source: string; provides: string[]; layer: string }>;
      recommendations: Array<{ priority: string; message: string; action: string }>;
    }>(`/api/devices/${encodeURIComponent(mac!)}/coverage`),
    enabled: !!mac && open,
    staleTime: 0,
  });

  const device = detailData?.device;
  const evidence = detailData?.evidence ?? [];
  const observations = obsData?.observations ?? [];
  const services = svcData?.services ?? [];
  const hourly = activityData?.hourly_counts ?? [];
  const coverage = coverageData;

  // Override form
  const [showOvrForm, setShowOvrForm] = useState(false);
  const [ovrFields, setOvrFields] = useState<Record<string, string>>({});

  const openOvrForm = () => {
    const o = device?.manual_override;
    setOvrFields({
      hostname: o?.hostname ?? device?.hostname ?? "",
      manufacturer: o?.manufacturer ?? device?.manufacturer ?? "",
      model: o?.model ?? device?.model ?? "",
      device_type: o?.device_type ?? device?.device_type ?? "",
      os_family: o?.os_family ?? device?.os_family ?? "",
      os_version: o?.os_version ?? device?.os_version ?? "",
      connection_type: o?.connection_type ?? "",
      disposition: o?.disposition ?? device?.alert_status ?? "new",
      notes: o?.notes ?? "",
    });
    setShowOvrForm(true);
  };

  const updateField = (key: string, value: string) =>
    setOvrFields((prev) => ({ ...prev, [key]: value }));

  const saveOverride = async () => {
    if (!mac) return;
    try {
      await apiFetch(`/api/devices/${encodeURIComponent(mac)}/override`, {
        method: "PUT",
        body: JSON.stringify(ovrFields),
      });
      queryClient.invalidateQueries({ queryKey: ["device-detail", mac] });
      queryClient.invalidateQueries({ queryKey: ["devices"] });
      setShowOvrForm(false);
      toast.success("Override saved");
    } catch (err) {
      toast.error(`Failed: ${err instanceof Error ? err.message : "unknown"}`);
    }
  };
  const clearOverride = async () => {
    if (!mac) return;
    try {
      await apiFetch(`/api/devices/${encodeURIComponent(mac)}/override`, { method: "DELETE" });
      queryClient.invalidateQueries({ queryKey: ["device-detail", mac] });
      queryClient.invalidateQueries({ queryKey: ["devices"] });
      toast.success("Override cleared");
    } catch (err) { toast.error(`Failed: ${err instanceof Error ? err.message : "unknown"}`); }
  };

  if (!open) return null;

  return (
    <>
      {/* Overlay */}
      <div className="fixed inset-0 bg-black/50 z-40" onClick={onClose} />

      {/* Panel — takes ~half the screen */}
      <div className="fixed top-0 right-0 h-full w-full max-w-[50vw] min-w-[500px] bg-background border-l border-border z-50 flex flex-col shadow-2xl animate-in slide-in-from-right duration-200">
        {/* Header */}
        <div className="shrink-0 px-8 py-5 border-b border-border bg-card flex items-start justify-between">
          <div>
            <h2 className="text-xl font-semibold font-data">{device?.hostname || device?.mac || mac}</h2>
            {device && (
              <div className="flex items-center gap-3 mt-2">
                <span className={cn("text-[11px] font-semibold uppercase px-2 py-0.5 rounded border", statusCls(device.alert_status ?? "new"))}>
                  {device.alert_status ?? "new"}
                </span>
                {device.device_type && (
                  <div className="flex items-center gap-1.5 text-sm text-muted-foreground">
                    <span className="w-2 h-2 rounded-full" style={{ background: getDeviceTypeColor(device.device_type) }} />
                    {device.device_type}
                  </div>
                )}
                {device.manufacturer && <span className="text-sm text-muted-foreground">{device.manufacturer}</span>}
                <span className="text-sm font-bold" style={{ color: confColor(device.confidence) }}>{device.confidence}% certainty</span>
              </div>
            )}
          </div>
          <button onClick={() => { onClose(); setShowOvrForm(false); }} className="p-2 rounded-lg hover:bg-secondary transition-colors">
            <X size={20} />
          </button>
        </div>

        {/* Body — scrollable */}
        <div className="flex-1 overflow-y-auto">
          {isLoading ? (
            <div className="p-8 space-y-6">
              <Skeleton className="h-6 w-1/2" /><Skeleton className="h-6 w-1/3" />
              <Skeleton className="h-40 w-full" /><Skeleton className="h-6 w-2/3" />
            </div>
          ) : device ? (
            <div className="p-8 space-y-8">

              {/* ── Identity ── */}
              <Section title="Identity">
                <div className="grid grid-cols-2 lg:grid-cols-3 gap-x-10 gap-y-5">
                  <LabelValue label="Hardware Address" mono>
                    {device.mac}
                    {device.is_randomized_mac && <Badge variant="outline" className="ml-2 text-[9px] text-purple-400 border-purple-400/30">Randomized</Badge>}
                  </LabelValue>
                  <LabelValue label="Hostname">{device.hostname || "-"}</LabelValue>
                  <LabelValue label="Vendor">{device.manufacturer || "-"}</LabelValue>
                  <LabelValue label="IPv4" mono>{device.ip_v4 || "-"}</LabelValue>
                  <LabelValue label="IPv6" mono><span className="break-all">{device.ip_v6 || "-"}</span></LabelValue>
                  {device.correlated_mac && <LabelValue label="Correlated MAC" mono>{device.correlated_mac}</LabelValue>}
                  {device.criticality && (
                    <LabelValue label="Criticality"><CriticalityPill value={device.criticality} /></LabelValue>
                  )}
                </div>
              </Section>

              {/* ── Custom Properties ── */}
              {mac && (
                <CustomProperties
                  mac={mac}
                  initial={{
                    owner: device.owner ?? null,
                    location: device.location ?? null,
                    criticality: device.criticality ?? null,
                    tags: device.tags ?? [],
                    notes: device.notes ?? null,
                  }}
                  onSaved={(next: CustomPropsValues) => {
                    queryClient.invalidateQueries({ queryKey: ["device-detail", mac] });
                    queryClient.invalidateQueries({ queryKey: ["devices"] });
                    void next;
                  }}
                />
              )}

              {/* ── Classification ── */}
              <Section title="Classification">
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-x-10 gap-y-5">
                  <LabelValue label="Host Category">
                    <div className="flex items-center gap-2">
                      <span className="w-3 h-3 rounded-full" style={{ background: getDeviceTypeColor(device.device_type) }} />
                      <span className="font-medium">{device.device_type || "-"}</span>
                    </div>
                  </LabelValue>
                  <LabelValue label="Platform">{device.os_family || "-"}</LabelValue>
                  <LabelValue label="Platform Version">{device.os_version || "-"}</LabelValue>
                  <LabelValue label="Certainty">
                    <div className="flex items-center gap-3">
                      <span className="text-lg font-bold" style={{ color: confColor(device.confidence) }}>{device.confidence}%</span>
                      <div className="flex-1 h-2.5 bg-muted rounded-full overflow-hidden max-w-[140px]">
                        <div className="h-full rounded-full transition-all" style={{ width: `${device.confidence}%`, background: confColor(device.confidence) }} />
                      </div>
                    </div>
                  </LabelValue>
                </div>
              </Section>

              {/* ── Manual Override ── */}
              <Section title="Manual Override" badge={device.manual_override ? <Badge className="text-[9px] bg-primary/20 text-primary border-primary/30">ACTIVE</Badge> : undefined}>
                {device.manual_override && !showOvrForm && (
                  <div className="mb-4">
                    <div className="grid grid-cols-3 gap-x-10 gap-y-4">
                      {device.manual_override.hostname && <LabelValue label="Hostname">{device.manual_override.hostname}</LabelValue>}
                      {device.manual_override.device_type && <LabelValue label="Host Category">{device.manual_override.device_type}</LabelValue>}
                      {device.manual_override.manufacturer && <LabelValue label="Vendor">{device.manual_override.manufacturer}</LabelValue>}
                      {device.manual_override.model && <LabelValue label="Model">{device.manual_override.model}</LabelValue>}
                      {device.manual_override.os_family && <LabelValue label="Platform">{device.manual_override.os_family}</LabelValue>}
                      {device.manual_override.os_version && <LabelValue label="Platform Version">{device.manual_override.os_version}</LabelValue>}
                      {device.manual_override.connection_type && <LabelValue label="Connection">{device.manual_override.connection_type}</LabelValue>}
                      {device.manual_override.disposition && <LabelValue label="Disposition">{device.manual_override.disposition}</LabelValue>}
                      {device.manual_override.notes && <LabelValue label="Notes">{device.manual_override.notes}</LabelValue>}
                    </div>
                    <Button variant="ghost" size="sm" className="mt-4 text-xs text-destructive" onClick={clearOverride}>Clear Override</Button>
                  </div>
                )}
                {showOvrForm ? (
                  <div className="space-y-4 bg-card rounded-lg border border-border p-5">
                    {/* Identity */}
                    <Collapsible defaultOpen>
                      <CollapsibleTrigger className="flex items-center gap-2 text-xs font-semibold uppercase text-muted-foreground w-full">
                        <ChevronDown size={14} /> Identity
                      </CollapsibleTrigger>
                      <CollapsibleContent className="pt-3">
                        <div className="grid grid-cols-3 gap-4">
                          <div>
                            <label className="text-xs text-muted-foreground block mb-1.5">Hostname</label>
                            <Input value={ovrFields.hostname} onChange={(e) => updateField("hostname", e.target.value)} className="bg-secondary" />
                          </div>
                          <div>
                            <label className="text-xs text-muted-foreground block mb-1.5">Vendor</label>
                            <Input value={ovrFields.manufacturer} onChange={(e) => updateField("manufacturer", e.target.value)} className="bg-secondary" />
                          </div>
                          <div>
                            <label className="text-xs text-muted-foreground block mb-1.5">Model</label>
                            <Input value={ovrFields.model} onChange={(e) => updateField("model", e.target.value)} className="bg-secondary" />
                          </div>
                        </div>
                      </CollapsibleContent>
                    </Collapsible>

                    {/* Classification */}
                    <Collapsible defaultOpen>
                      <CollapsibleTrigger className="flex items-center gap-2 text-xs font-semibold uppercase text-muted-foreground w-full">
                        <ChevronDown size={14} /> Classification
                      </CollapsibleTrigger>
                      <CollapsibleContent className="pt-3">
                        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                          <div>
                            <label className="text-xs text-muted-foreground block mb-1.5">Host Category</label>
                            <Select value={ovrFields.device_type} onValueChange={(v) => updateField("device_type", v)}>
                              <SelectTrigger className="bg-secondary"><SelectValue placeholder="Select..." /></SelectTrigger>
                              <SelectContent>
                                {["laptop", "desktop", "phone", "tablet", "printer", "server",
                                  "switch", "router", "access_point", "camera", "nas", "iot",
                                  "workstation", "media_player", "game_console", "smart_home",
                                  "voip_phone", "other"].map((t) => (
                                  <SelectItem key={t} value={t}>{t.replace(/_/g, " ")}</SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </div>
                          <div>
                            <label className="text-xs text-muted-foreground block mb-1.5">Platform</label>
                            <Input value={ovrFields.os_family} onChange={(e) => updateField("os_family", e.target.value)} className="bg-secondary" />
                          </div>
                          <div>
                            <label className="text-xs text-muted-foreground block mb-1.5">Platform Version</label>
                            <Input value={ovrFields.os_version} onChange={(e) => updateField("os_version", e.target.value)} className="bg-secondary" />
                          </div>
                          <div>
                            <label className="text-xs text-muted-foreground block mb-1.5">Connection Type</label>
                            <Select value={ovrFields.connection_type} onValueChange={(v) => updateField("connection_type", v)}>
                              <SelectTrigger className="bg-secondary"><SelectValue placeholder="Select..." /></SelectTrigger>
                              <SelectContent>
                                <SelectItem value="wired">Wired</SelectItem>
                                <SelectItem value="wireless">Wireless</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                        </div>
                      </CollapsibleContent>
                    </Collapsible>

                    {/* Analyst */}
                    <Collapsible defaultOpen>
                      <CollapsibleTrigger className="flex items-center gap-2 text-xs font-semibold uppercase text-muted-foreground w-full">
                        <ChevronDown size={14} /> Analyst
                      </CollapsibleTrigger>
                      <CollapsibleContent className="pt-3">
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <label className="text-xs text-muted-foreground block mb-1.5">Disposition</label>
                            <Select value={ovrFields.disposition} onValueChange={(v) => updateField("disposition", v)}>
                              <SelectTrigger className="bg-secondary"><SelectValue placeholder="Select..." /></SelectTrigger>
                              <SelectContent>
                                <SelectItem value="new">New</SelectItem>
                                <SelectItem value="known">Known</SelectItem>
                                <SelectItem value="suspicious">Suspicious</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                          <div className="col-span-2">
                            <label className="text-xs text-muted-foreground block mb-1.5">Notes</label>
                            <textarea
                              value={ovrFields.notes}
                              onChange={(e) => updateField("notes", e.target.value)}
                              rows={3}
                              className="flex w-full rounded-md border border-input bg-secondary px-3 py-2 text-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                              placeholder="Analyst notes..."
                            />
                          </div>
                        </div>
                      </CollapsibleContent>
                    </Collapsible>

                    <div className="flex gap-3 pt-2">
                      <Button size="sm" onClick={saveOverride}>Save Override</Button>
                      <Button variant="ghost" size="sm" onClick={() => setShowOvrForm(false)}>Cancel</Button>
                    </div>
                  </div>
                ) : (
                  <Button variant="outline" size="sm" onClick={openOvrForm}>Edit Override</Button>
                )}
              </Section>

              {/* ── Timestamps ── */}
              <Section title="Timestamps">
                <div className="grid grid-cols-2 gap-x-10 gap-y-5">
                  <LabelValue label="Discovered" mono>{formatTs(device.first_seen)}</LabelValue>
                  <LabelValue label="Last Active" mono>{formatTs(device.last_seen)}</LabelValue>
                </div>
              </Section>

              {/* ── Services ── */}
              {services.length > 0 && (
                <Section title={`Detected Services (${services.length})`}>
                  <div className="space-y-3">
                    {services.map((svc, i) => {
                      // Handle both new sightings-based format and old probe result format
                      let name: string;
                      let ver: string | null = null;
                      let conf = 0;
                      let meta: Record<string, unknown> = {};

                      if (svc.service) {
                        // New format: {service, protocol, port, banner, sni, details}
                        name = String(svc.service).replace(/_/g, " ");
                        const details = svc.details ?? {};
                        meta = {};
                        if (svc.banner) meta["banner"] = svc.banner;
                        if (svc.sni) meta["sni"] = svc.sni;
                        for (const [k, v] of Object.entries(details)) {
                          if (!["service", "service_type", "port", "dst_port", "raw_banner", "server", "sni"].includes(k) && v) {
                            meta[k] = v;
                          }
                        }
                      } else if (svc.result) {
                        // Old probe format: {port, protocol, result: JSON string}
                        let parsed: Record<string, unknown> = {};
                        try { parsed = typeof svc.result === "string" ? JSON.parse(svc.result) : (svc.result as Record<string, unknown>); } catch { /* */ }
                        name = String(parsed?.service ?? "?").replace(/_/g, " ");
                        ver = parsed?.version ? `v${parsed.version}` : null;
                        conf = Number(parsed?.confidence) || 0;
                        meta = (parsed?.metadata ?? {}) as Record<string, unknown>;
                      } else {
                        name = svc.protocol ?? "unknown";
                      }

                      const metaKeys = Object.keys(meta).filter((k) => k !== "version").slice(0, 4);
                      return (
                        <div key={i} className="rounded-lg bg-card border border-border p-4">
                          <div className="flex items-center gap-4">
                            {svc.port ? (
                              <span className="text-base font-bold font-data text-primary">{svc.port}/{svc.protocol ?? "tcp"}</span>
                            ) : (
                              <span className="text-base font-bold font-data text-primary">{svc.protocol ?? "?"}</span>
                            )}
                            <span className="text-sm font-medium flex-1">{name}</span>
                            {ver && <span className="text-xs text-muted-foreground">{ver}</span>}
                            {conf > 0 && <span className="text-sm font-bold" style={{ color: confColor(conf) }}>{conf}%</span>}
                          </div>
                          {metaKeys.length > 0 && (
                            <div className="flex flex-wrap gap-2 mt-2">
                              {metaKeys.map((k) => (
                                <span key={k} className="text-[11px] px-2 py-0.5 rounded bg-secondary border border-border text-muted-foreground font-data">
                                  {k}: {String(meta[k]).substring(0, 50)}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </Section>
              )}

              {/* ── Activity ── */}
              {hourly.length > 0 && (
                <Section title="24-Hour Activity">
                  <div className="rounded-lg bg-card border border-border p-4">
                    <div className="flex items-end gap-0.5 h-24">
                      {hourly.map((count, hour) => {
                        const max = Math.max(...hourly, 1);
                        const pct = (count / max) * 100;
                        return (
                          <div key={hour} className="flex-1 bg-primary/50 hover:bg-primary rounded-t transition-colors cursor-default"
                            style={{ height: `${Math.max(pct, 3)}%` }} title={`${hour}:00 — ${count} packets`} />
                        );
                      })}
                    </div>
                    <div className="flex justify-between text-[10px] text-muted-foreground mt-2">
                      <span>12 AM</span><span>6 AM</span><span>12 PM</span><span>6 PM</span><span>12 AM</span>
                    </div>
                  </div>
                </Section>
              )}

              {/* ── Observations ── */}
              <Section title="Recent Observations">
                {observations.length === 0 ? (
                  <p className="text-sm text-muted-foreground py-4">No observations recorded.</p>
                ) : (
                  <div className="rounded-lg border border-border overflow-hidden">
                    {observations.map((obs, i) => (
                      <div key={obs.id} className={cn("flex items-center gap-5 px-4 py-3", i % 2 === 0 ? "bg-card" : "bg-secondary/20")}>
                        <span className="w-2 h-2 rounded-full bg-primary shrink-0" />
                        <span className="text-xs text-muted-foreground font-data min-w-[170px]">{formatTs(obs.timestamp)}</span>
                        <span className="text-sm font-medium flex-1">{obs.source_type}</span>
                        {obs.confidence != null && (
                          <span className="text-sm font-bold" style={{ color: confColor(obs.confidence) }}>{obs.confidence}%</span>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </Section>

              {/* ── Coverage Diagnostics ── */}
              {coverage && (
                <Section title={`Source Coverage (${coverage.source_count} sources — ${coverage.quality})`}>
                  {/* Observed sources */}
                  <div className="space-y-1.5 mb-3">
                    {coverage.observed.map((s) => (
                      <div key={s.source} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-success/[0.04] border border-success/20">
                        <span className="w-2 h-2 rounded-full bg-success shrink-0" />
                        <span className="text-xs font-semibold w-24 shrink-0">{s.source}</span>
                        <span className="text-[10px] text-muted-foreground flex-1 truncate">{s.provides.join(", ")}</span>
                        <span className="text-[10px] text-muted-foreground shrink-0">{s.count} obs</span>
                      </div>
                    ))}
                  </div>
                  {/* Missing sources */}
                  {coverage.missing.length > 0 && (
                    <div className="space-y-1.5 mb-3">
                      {coverage.missing.filter(s => !["banner", "snmp", "cdp"].includes(s.source)).slice(0, 6).map((s) => (
                        <div key={s.source} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-secondary/30 border border-border">
                          <span className="w-2 h-2 rounded-full bg-muted-foreground/30 shrink-0" />
                          <span className="text-xs font-semibold text-muted-foreground w-24 shrink-0">{s.source}</span>
                          <span className="text-[10px] text-muted-foreground flex-1 truncate">{s.provides.join(", ")}</span>
                          <span className="text-[10px] text-muted-foreground/50 shrink-0">{s.layer}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {/* Recommendations */}
                  {coverage.recommendations.length > 0 && (
                    <div className="space-y-2">
                      {coverage.recommendations.map((r, i) => (
                        <div key={i} className={cn("rounded-lg border px-4 py-3 text-xs",
                          r.priority === "high" ? "border-warning/30 bg-warning/[0.04]" : "border-border bg-secondary/20"
                        )}>
                          <p className="font-medium mb-1">{r.message}</p>
                          <p className="text-muted-foreground">{r.action}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </Section>
              )}

              {/* ── Evidence ── */}
              {evidence.length > 0 && (
                <Section title={`Fingerprint Evidence (${evidence.length})`}>
                  <div className="space-y-3 max-h-[400px] overflow-y-auto">
                    {evidence.map((ev, i) => {
                      const e = ev as Record<string, unknown>;
                      const rd = (e.raw_data ?? {}) as Record<string, unknown>;
                      const source = String(e.source ?? ""); const conf = Number(e.confidence ?? 0);
                      const matchType = String(e.match_type ?? "");
                      const sourceDb = String(rd.source_db ?? "");
                      const sourceFile = String(rd.source_file ?? "");
                      const matchedKey = String(rd.matched_key ?? "");

                      const fields: Array<[string, string]> = [];
                      if (e.manufacturer) fields.push(["Vendor", String(e.manufacturer)]);
                      if (e.device_type) fields.push(["Host Category", String(e.device_type)]);
                      if (e.os_family) fields.push(["Platform", String(e.os_family)]);
                      if (e.os_version) fields.push(["Platform Version", String(e.os_version)]);
                      if (e.model) fields.push(["Model", String(e.model)]);
                      if (matchType) fields.push(["Match Type", matchType]);
                      return (
                        <div key={i} className="rounded-lg bg-card border border-border p-4">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-sm font-semibold text-cyan-400">{source}</span>
                            <span className="text-sm font-bold" style={{ color: confColor(conf) }}>{conf}%</span>
                          </div>
                          {/* Source attribution */}
                          {(sourceDb || sourceFile || matchedKey) && (
                            <div className="mb-3 space-y-0.5">
                              {sourceDb && (
                                <div className="text-[10px] text-muted-foreground">
                                  Database: <span className="text-foreground/70">{sourceDb}</span>
                                </div>
                              )}
                              {sourceFile && (
                                <div className="text-[10px] text-muted-foreground">
                                  Source: <span className="font-data text-foreground/50">{sourceFile}</span>
                                </div>
                              )}
                              {matchedKey && (
                                <div className="text-[10px] text-muted-foreground">
                                  Matched: <span className="font-data text-foreground/70">{matchedKey}</span>
                                </div>
                              )}
                            </div>
                          )}
                          {fields.length > 0 && (
                            <div className="grid grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-2">
                              {fields.map(([k, v]) => (
                                <div key={k}>
                                  <span className="text-[11px] text-muted-foreground">{k}</span>
                                  <div className="text-sm">{v}</div>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </Section>
              )}

              {/* ── Timeline ── */}
              <Section title={`Timeline (${timelineData?.events.length ?? 0} events)`}>
                <div className="relative space-y-0">
                  {(timelineData?.events ?? []).slice(0, 50).map((event, i) => {
                    const dotColor = {
                      first_seen: "bg-zinc-400",
                      observation: "bg-blue-400",
                      classification: "bg-green-400",
                      ip_change: "bg-orange-400",
                      finding: "bg-red-400",
                    }[event.type] ?? "bg-zinc-500";

                    const ts = new Date(event.timestamp);
                    const relative = formatRelativeTime(ts);

                    return (
                      <div key={i} className="flex gap-3 py-2 group">
                        <div className="flex flex-col items-center w-6 shrink-0">
                          <div className={`w-2.5 h-2.5 rounded-full ${dotColor} ring-2 ring-background shrink-0 mt-1`} />
                          {i < (timelineData?.events.length ?? 0) - 1 && (
                            <div className="w-px flex-1 bg-border" />
                          )}
                        </div>
                        <div className="flex-1 min-w-0 pb-2">
                          <div className="flex items-baseline gap-2">
                            <span className="text-xs font-medium">{event.title}</span>
                            <span className="text-[10px] text-muted-foreground ml-auto shrink-0" title={ts.toISOString()}>
                              {relative}
                            </span>
                          </div>
                          {event.detail && (
                            <p className="text-[11px] text-muted-foreground mt-0.5 truncate">{event.detail}</p>
                          )}
                        </div>
                      </div>
                    );
                  })}
                  {!timelineData?.events.length && (
                    <p className="text-sm text-muted-foreground">No timeline events recorded.</p>
                  )}
                </div>
              </Section>

            </div>
          ) : (
            <div className="flex items-center justify-center h-32 text-muted-foreground">Device not found</div>
          )}
        </div>
      </div>
    </>
  );
}

// --- Reusable pieces ---

function Section({ title, badge, children }: { title: string; badge?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section>
      <div className="flex items-center gap-2 mb-4">
        <h3 className="text-xs font-bold uppercase tracking-[0.15em] text-muted-foreground">{title}</h3>
        {badge}
      </div>
      {children}
    </section>
  );
}

function LabelValue({ label, children, mono }: { label: string; children: React.ReactNode; mono?: boolean }) {
  return (
    <div>
      <div className="text-xs text-muted-foreground mb-1.5">{label}</div>
      <div className={cn("text-sm", mono && "font-data")}>{children}</div>
    </div>
  );
}
