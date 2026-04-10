// frontend/src/lib/api.ts

let _redirecting = false;

/** Inject auth token into a raw fetch call. Use for non-JSON responses (blobs, streams). */
export function authHeaders(extra?: HeadersInit): Record<string, string> {
  const token = localStorage.getItem("leetha_token");
  const h: Record<string, string> = {};
  if (token) h["Authorization"] = `Bearer ${token}`;
  if (extra) {
    const entries = extra instanceof Headers
      ? Object.fromEntries(extra.entries())
      : (extra as Record<string, string>);
    Object.assign(h, entries);
  }
  return h;
}

async function apiFetch<T>(url: string, options?: RequestInit): Promise<T> {
  const token = localStorage.getItem("leetha_token");
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  // Merge caller-provided headers (they override defaults)
  if (options?.headers) {
    const extra = options.headers instanceof Headers
      ? Object.fromEntries(options.headers.entries())
      : (options.headers as Record<string, string>);
    Object.assign(headers, extra);
  }
  const res = await fetch(url, { ...options, headers });
  if (res.status === 401 && !_redirecting) {
    _redirecting = true;
    localStorage.removeItem("leetha_token");
    localStorage.removeItem("leetha_role");
    window.location.href = "/login";
    throw new Error("Authentication required");
  }
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

// --- Types ---

export interface Device {
  mac: string;
  primary_mac?: string;
  ip_v4: string | null;
  ip_v6: string | null;
  manufacturer: string | null;
  device_type: string | null;
  os_family: string | null;
  os_version: string | null;
  hostname: string | null;
  confidence: number;
  is_randomized_mac: boolean;
  correlated_mac: string | null;
  first_seen: string | null;
  last_seen: string | null;
  alert_status: string | null;
  manual_override: Record<string, string> | null;
  raw_evidence?: Array<Record<string, unknown>>;
}

export interface DeviceListResponse {
  devices: Device[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}

export interface Alert {
  id: number;
  device_mac: string;
  alert_type: string;
  severity: string;
  message: string;
  timestamp: string;
  acknowledged: boolean;
}

export interface DeviceDetail extends Device {
  observations: Array<Record<string, unknown>>;
  services?: Array<Record<string, unknown>>;
}

export interface StatsResponse {
  device_count: number;
  alert_count: number;
  capturing_count: number;
}

// --- Endpoints ---

export async function fetchDevices(params?: {
  page?: number;
  per_page?: number;
  sort?: string;
  order?: string;
  q?: string;
  device_type?: string;
  os_family?: string;
  manufacturer?: string;
  alert_status?: string;
  confidence_min?: number;
  interface?: string;
  raw?: boolean;
}): Promise<DeviceListResponse> {
  const searchParams = new URLSearchParams();
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        searchParams.set(key, String(value));
      }
    });
  }
  const qs = searchParams.toString();
  return apiFetch(`/api/devices${qs ? `?${qs}` : ""}`);
}

export async function fetchDeviceDetail(mac: string): Promise<DeviceDetail> {
  return apiFetch(`/api/devices/${encodeURIComponent(mac)}/detail`);
}

export async function fetchDeviceActivity(mac: string) {
  return apiFetch<{ hours: Array<{ hour: string; count: number }> }>(
    `/api/devices/${encodeURIComponent(mac)}/activity`
  );
}

export async function fetchDeviceServices(mac: string) {
  return apiFetch<{ services: Array<Record<string, unknown>> }>(
    `/api/devices/${encodeURIComponent(mac)}/services`
  );
}

export async function fetchAlerts(params?: {
  page?: number;
  per_page?: number;
}): Promise<Alert[]> {
  const searchParams = new URLSearchParams();
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        searchParams.set(key, String(value));
      }
    });
  }
  const qs = searchParams.toString();
  const data = await apiFetch<{ alerts: Alert[] } | Alert[]>(
    `/api/alerts${qs ? `?${qs}` : ""}`
  );
  // Handle both paginated response {alerts: [...]} and legacy array
  return Array.isArray(data) ? data : data.alerts;
}

// --- Stats endpoints ---

export interface DeviceTypeCount {
  type: string;
  count: number;
}

export async function fetchDeviceTypeStats(): Promise<{ types: DeviceTypeCount[] }> {
  return apiFetch("/api/stats/device-types");
}

export async function fetchActivityStats(): Promise<{ hourly_counts: number[] }> {
  return apiFetch("/api/stats/activity");
}

export interface ProtocolCount {
  protocol: string;
  count: number;
}

export async function fetchProtocolStats(): Promise<{ protocols: ProtocolCount[] }> {
  return apiFetch("/api/stats/protocols");
}

export async function fetchAlertTrend(): Promise<{ hourly_counts: number[] }> {
  return apiFetch("/api/stats/alert-trend");
}

export async function fetchNewDevicesTimeline(): Promise<{ hourly_counts: number[] }> {
  return apiFetch("/api/stats/new-devices");
}

export interface ConnectionEntry {
  src: string;
  dst: string;
  count: number;
}

export async function fetchTopConnections(): Promise<{ connections: ConnectionEntry[] }> {
  return apiFetch("/api/stats/top-connections");
}

export interface FilterOptions {
  device_types: string[];
  os_families: string[];
  manufacturers: string[];
}

export async function fetchFilterOptions(): Promise<FilterOptions> {
  return apiFetch("/api/stats/filters");
}

export async function acknowledgeAlert(alertId: number): Promise<void> {
  await apiFetch(`/api/alerts/${alertId}/acknowledge`, { method: "POST" });
}

export async function bulkAcknowledgeAlerts(ids: number[]): Promise<void> {
  await apiFetch("/api/alerts/bulk", {
    method: "POST",
    body: JSON.stringify({ action: "acknowledge", ids }),
  });
}

export async function bulkDeleteAlerts(ids: number[]): Promise<{ deleted: number }> {
  return apiFetch("/api/alerts/bulk", {
    method: "POST",
    body: JSON.stringify({ action: "delete", ids }),
  });
}

export async function deleteResolvedAlerts(): Promise<{ deleted: number }> {
  return apiFetch("/api/alerts/resolved", { method: "DELETE" });
}

export async function deleteAllAlerts(): Promise<{ deleted: number }> {
  return apiFetch("/api/alerts/all?confirm=true", { method: "DELETE" });
}

export async function fetchStats(): Promise<StatsResponse> {
  return apiFetch("/api/stats");
}

// --- Interface types ---

export interface NetworkInterface {
  name: string;
  type: string;
  state: string;
  mac: string | null;
  mtu: number | null;
  bindings: Array<{ address: string; prefix?: number }>;
  capturing: boolean;
}

export interface InterfaceListResponse {
  detected: NetworkInterface[];
  active: Array<{ name: string; type: string; label?: string; probe_mode?: string }>;
}

export interface ProbeInfo {
  name: string;
  description: string;
  requires_l2?: boolean;
}

// --- Interface endpoints ---

export async function fetchInterfaceList(): Promise<InterfaceListResponse> {
  return apiFetch("/api/interfaces");
}

export async function enableInterface(name: string) {
  return apiFetch<{ status: string }>(`/api/interfaces/${encodeURIComponent(name)}/enable`, { method: "POST" });
}

export async function disableInterface(name: string) {
  return apiFetch<{ status: string }>(`/api/interfaces/${encodeURIComponent(name)}/disable`, { method: "POST" });
}

export async function setProbeMode(name: string, mode: string) {
  return apiFetch(`/api/interfaces/${encodeURIComponent(name)}/probe-mode`, {
    method: "PUT",
    body: JSON.stringify({ mode }),
  });
}

export async function runProbes(name: string, probes: string[] | "all") {
  return apiFetch(`/api/interfaces/${encodeURIComponent(name)}/probe`, {
    method: "POST",
    body: JSON.stringify({ probes }),
  });
}

export async function fetchProbeStatus(name: string): Promise<{ probes?: ProbeInfo[]; available_probes?: ProbeInfo[] }> {
  return apiFetch(`/api/interfaces/${encodeURIComponent(name)}/probe-status`);
}

// --- Pattern types ---

export interface PatternEntry {
  pattern: string;
  device_type: string;
  manufacturer: string;
  confidence: number;
}

export interface PatternsResponse {
  [type: string]: PatternEntry[];
}

// --- Pattern endpoints ---

export async function fetchPatterns(): Promise<PatternsResponse> {
  return apiFetch("/api/patterns");
}

export async function addPattern(type: string, pattern: PatternEntry) {
  return apiFetch(`/api/patterns/${encodeURIComponent(type)}`, {
    method: "POST",
    body: JSON.stringify(pattern),
  });
}

export async function deletePattern(type: string, index: number) {
  return apiFetch(`/api/patterns/${encodeURIComponent(type)}/${index}`, { method: "DELETE" });
}

/** @deprecated Use fetchInterfaceList instead */
export async function fetchInterfaces() {
  return apiFetch<{ interfaces: Array<Record<string, unknown>> }>("/api/interfaces");
}

// --- Sync / Validation types ---

export interface SourceInfo {
  name: string;
  display_name: string;
  url: string;
  source_type: string;
  description: string;
}

export interface SyncProgressEvent {
  source: string;
  event: string;
  status?: string;
  progress?: number;
  detail?: string;
  url?: string;
  downloaded?: number;
  total?: number;
  unit?: string;
  current_file?: string;
  entries?: number;
  size?: number;
  error?: string;
  total_sources?: number;
  succeeded?: number;
  failed?: number;
}

// --- Sync / Validation endpoints ---

export async function fetchSyncSources(): Promise<{ sources: SourceInfo[] }> {
  return apiFetch("/api/sync/sources");
}

export async function triggerSyncAll() {
  return apiFetch<{ status: string }>("/api/sync", { method: "POST" });
}

export async function triggerSyncSource(sourceName: string) {
  return apiFetch<{ status: string }>(`/api/sync/${encodeURIComponent(sourceName)}`, { method: "POST" });
}

export async function triggerValidation() {
  return apiFetch<{ status: string }>("/api/validate", { method: "POST" });
}

export async function fetchValidationReport() {
  return apiFetch<Record<string, unknown>>("/api/validate/report");
}

// --- Incident types ---

export interface Incident {
  id: string;
  subtype: string;
  severity: "threat" | "suspicious" | "informational";
  device_mac: string;
  device_ip: string | null;
  manufacturer: string | null;
  alert_count: number;
  first_seen: string | null;
  last_seen: string | null;
  summary: string;
  is_randomized_mac: boolean;
  correlated_mac: string | null;
  alert_ids: number[];
}

export interface IncidentCounts {
  threat: number;
  suspicious: number;
  informational: number;
  total: number;
}

export interface IncidentDetail {
  incident_id: string;
  subtype: string;
  device: Record<string, unknown>;
  evidence: Array<Record<string, unknown>>;
  arp_history: Array<Record<string, unknown>>;
  fingerprint_history: Array<Record<string, unknown>>;
  recent_observations: Array<Record<string, unknown>>;
  trusted_bindings: Array<Record<string, unknown>>;
  suppression_rules: Array<Record<string, unknown>>;
  detection_context: {
    rule: string;
    trigger: string;
    method: string;
    cooldown_seconds: number;
    mac_randomized: boolean;
    correlated_mac: string | null;
    recommendation: string;
  };
}

// --- Incident endpoints ---

export async function fetchIncidents(): Promise<{ incidents: Incident[]; counts: IncidentCounts }> {
  return apiFetch("/api/incidents");
}

export async function fetchIncidentDetail(id: string): Promise<IncidentDetail> {
  return apiFetch(`/api/incidents/${encodeURIComponent(id)}/detail`);
}

// --- Threat Detection types ---

export interface TrustedBinding {
  mac: string;
  ip: string;
}

export interface SuppressionRule {
  id: number;
  mac: string | null;
  ip: string | null;
  subtype: string | null;
  reason: string | null;
}

export interface ArpEntry {
  mac: string;
  ip: string;
  first_seen: string;
  last_seen: string;
}

// --- Threat Detection endpoints ---

export async function fetchTrustedBindings(): Promise<TrustedBinding[]> {
  const res = await apiFetch<{ bindings: TrustedBinding[] } | TrustedBinding[]>("/api/trust");
  return Array.isArray(res) ? res : res.bindings ?? [];
}

export async function addTrustedBinding(mac: string, ip: string) {
  return apiFetch("/api/trust", { method: "POST", body: JSON.stringify({ mac, ip }) });
}

export async function removeTrustedBinding(mac: string) {
  return apiFetch(`/api/trust/${encodeURIComponent(mac)}`, { method: "DELETE" });
}

export async function fetchSuppressionRules(): Promise<SuppressionRule[]> {
  const res = await apiFetch<{ rules: SuppressionRule[] } | SuppressionRule[]>("/api/suppressions");
  return Array.isArray(res) ? res : res.rules ?? [];
}

export async function addSuppressionRule(rule: { mac?: string; ip?: string; subtype?: string; reason?: string }) {
  return apiFetch("/api/suppressions", { method: "POST", body: JSON.stringify(rule) });
}

export async function removeSuppressionRule(id: number) {
  return apiFetch(`/api/suppressions/${id}`, { method: "DELETE" });
}

export async function fetchAlertTypeStats(): Promise<{ types: Array<{ type: string; severity: string; count: number }> }> {
  return apiFetch("/api/stats/alert-types");
}

export async function fetchTargetedDevices(): Promise<{ devices: Array<{ mac: string; count: number; ip: string | null; manufacturer: string | null; device_type: string | null }> }> {
  return apiFetch("/api/stats/targeted-devices");
}

export async function fetchArpHistory(query: { mac?: string; ip?: string }): Promise<ArpEntry[]> {
  const params = new URLSearchParams();
  if (query.mac) params.set("mac", query.mac);
  if (query.ip) params.set("ip", query.ip);
  return apiFetch(`/api/arp-history?${params}`);
}

// --- Attack Surface types ---

export interface ToolRecommendation {
  name: string;
  command: string;
  description?: string;
  url?: string;
  install_hint?: string;
}

export interface AffectedDevice {
  mac: string;
  ip?: string;
  hostname?: string;
  port?: string;
  service_version?: string;
  banner?: string;
}

export interface AttackFinding {
  rule_id: string;
  title: string;
  name?: string;
  description: string;
  severity: string;
  category: string;
  category_label?: string;
  affected_devices: AffectedDevice[];
  tools: ToolRecommendation[];
  evidence: string[];
  chain_ids?: string[];
}

export interface ChainTrigger {
  rule_id: string;
  name: string;
  severity: string;
  evidence?: string[];
  affected_devices?: AffectedDevice[];
}

export interface AttackChain {
  chain_id?: string;
  name: string;
  description: string;
  severity: string;
  findings: string[];
  interface?: string;
  triggered_by?: ChainTrigger[];
  steps?: Array<{ order: number; description: string }>;
  tools?: ToolRecommendation[];
}

export interface AttackSurfaceSummary {
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  chain_count: number;
}

export interface AttackSurfaceResponse {
  findings: AttackFinding[];
  chains: AttackChain[];
  summary?: AttackSurfaceSummary;
}

// --- Attack Surface endpoints ---

export async function fetchAttackSurface(): Promise<AttackSurfaceResponse> {
  return apiFetch("/api/attack-surface");
}

export async function fetchAttackSurfaceSummary(): Promise<AttackSurfaceSummary> {
  return apiFetch("/api/attack-surface/summary");
}

export interface AttackExclusion {
  type: string;
  value: string;
}

export async function fetchExclusions(): Promise<{ exclusions: AttackExclusion[] }> {
  return apiFetch("/api/attack-surface/exclusions");
}

export async function addExclusion(type: string, value: string) {
  return apiFetch("/api/attack-surface/exclude", { method: "POST", body: JSON.stringify({ type, value }) });
}

export async function removeExclusion(type: string, value: string) {
  return apiFetch(`/api/attack-surface/exclude/${encodeURIComponent(type)}/${encodeURIComponent(value)}`, { method: "DELETE" });
}

// --- Settings types ---

export interface LeethaSettings {
  web_host: string;
  web_port: number;
  sync_interval: number;
  worker_count: number;
  db_batch_size: number;
  db_flush_interval: number;
  bpf_filter: string;
  probe_enabled: boolean;
  max_concurrent_probes: number;
  probe_cooldown: number;
  [key: string]: string | number | boolean;
}

export interface DbInfo {
  db_path: string;
  db_size_bytes: number;
  wal_size_bytes: number;
  device_count: number;
  cache_dir: string;
  table_counts: Record<string, number>;
  page_count: number;
  page_size: number;
  last_modified: number | null;
}

// --- Settings endpoints ---

export async function fetchSettings(): Promise<LeethaSettings> {
  return apiFetch("/api/settings");
}

export async function updateSettings(settings: Partial<LeethaSettings>): Promise<LeethaSettings> {
  return apiFetch("/api/settings", { method: "PUT", body: JSON.stringify(settings) });
}

export async function applySettings() {
  return apiFetch<{ status: string; message: string }>("/api/settings/apply", { method: "POST" });
}

export async function resetSettings(): Promise<LeethaSettings> {
  return apiFetch("/api/settings/reset", { method: "POST" });
}

export async function exportSettings() {
  const res = await fetch("/api/settings/export", { headers: authHeaders() });
  if (!res.ok) throw new Error(`Export failed: ${res.status} ${res.statusText}`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "leetha-settings.json";
  a.click();
  URL.revokeObjectURL(url);
}

export async function importSettings(data: Record<string, unknown>): Promise<LeethaSettings> {
  return apiFetch("/api/settings/import", { method: "POST", body: JSON.stringify(data) });
}

export async function fetchDbInfo(): Promise<DbInfo> {
  return apiFetch("/api/settings/db-info");
}

export async function runQuery(sql: string) {
  return apiFetch<{ columns: string[]; rows: unknown[][] }>("/api/settings/query", {
    method: "POST",
    body: JSON.stringify({ sql }),
  });
}

export async function clearDatabase() {
  return apiFetch<{ status: string }>("/api/settings/db", { method: "DELETE" });
}

export async function exportDatabase(format: "sqlite" | "sql") {
  const res = await fetch(`/api/settings/db-export?format=${format}`, {
    headers: authHeaders(),
  });
  if (!res.ok) throw new Error(`Export failed: ${res.status} ${res.statusText}`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = format === "sqlite" ? "leetha.db" : "leetha-dump.sql";
  a.click();
  URL.revokeObjectURL(url);
}

// --- Auth ---

export async function checkAuthStatus(): Promise<{ auth_enabled: boolean }> {
  const res = await fetch("/api/auth/status");
  return res.json();
}

export async function loginWithToken(token: string): Promise<{ valid: boolean; role: string }> {
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
  });
  if (!res.ok) {
    throw new Error("Invalid token");
  }
  return res.json();
}

export async function fetchAuthTokens(): Promise<{
  tokens: Array<{
    id: number;
    role: string;
    label: string | null;
    created_at: string;
    last_used: string | null;
    revoked: number;
  }>;
}> {
  return apiFetch("/api/auth/tokens");
}

export async function createAuthToken(
  role: string,
  label?: string
): Promise<{ token: string; id: number; role: string }> {
  return apiFetch("/api/auth/tokens", {
    method: "POST",
    body: JSON.stringify({ role, label }),
  });
}

export async function revokeAuthToken(
  tokenId: number
): Promise<{ status: string }> {
  return apiFetch(`/api/auth/tokens/${tokenId}`, { method: "DELETE" });
}

export async function fetchTopology(): Promise<{
  nodes: Array<{
    id: string; type: string; hostname: string | null; ip: string | null;
    manufacturer: string | null; confidence: number; subnet: string | null;
    is_gateway: boolean; is_infrastructure?: boolean; last_seen: string | null;
    os_family: string | null; tier?: string; parent_group?: string | null;
    label?: string; device_count?: number; infra_count?: number; client_count?: number;
  }>;
  edges: Array<{
    source: string; target: string; type: string;
    packet_count?: number; port_id?: string;
  }>;
  subnets: string[];
}> {
  return apiFetch("/api/topology");
}

export async function createTopologyOverride(childMac: string, parentMac: string) {
  return apiFetch<{ status: string; child_mac: string; parent_mac: string }>(
    "/api/topology/override",
    { method: "PUT", body: JSON.stringify({ child_mac: childMac, parent_mac: parentMac }) },
  );
}

export async function deleteTopologyOverride(mac: string) {
  return apiFetch<{ status: string }>(`/api/topology/override/${mac}`, { method: "DELETE" });
}

export async function fetchTopologyOverrides(): Promise<{
  overrides: Array<{ child_mac: string; parent_mac: string }>;
}> {
  return apiFetch("/api/topology/overrides");
}

export interface TimelineEvent {
  timestamp: string;
  type: "first_seen" | "observation" | "classification" | "ip_change" | "finding";
  title: string;
  detail: string | null;
  source: string | null;
}

export async function fetchDeviceTimeline(mac: string, limit = 100): Promise<{ events: TimelineEvent[]; total: number }> {
  return apiFetch(`/api/devices/${encodeURIComponent(mac)}/timeline?limit=${limit}`);
}

export async function importPcap(file: File): Promise<{ status: string; filename: string }> {
  const token = localStorage.getItem("leetha_token");
  const formData = new FormData();
  formData.append("file", file);
  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch("/api/import", {
    method: "POST",
    headers,
    body: formData,
  });
  if (res.status === 401) {
    localStorage.removeItem("leetha_token");
    localStorage.removeItem("leetha_role");
    window.location.href = "/login";
    throw new Error("Authentication required");
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Upload failed" }));
    throw new Error(err.error || `Upload failed: ${res.status}`);
  }
  return res.json();
}

// --- Notification settings ---

export interface NotificationSettings {
  urls: string[];
  min_severity: string;
}

export async function fetchNotificationSettings(): Promise<NotificationSettings> {
  return apiFetch("/api/settings/notifications");
}

export async function updateNotificationSettings(settings: Partial<NotificationSettings>): Promise<NotificationSettings> {
  return apiFetch("/api/settings/notifications", {
    method: "PUT",
    body: JSON.stringify(settings),
  });
}

export async function testNotification(): Promise<{ status: string; message?: string }> {
  return apiFetch("/api/settings/notifications/test", { method: "POST" });
}
