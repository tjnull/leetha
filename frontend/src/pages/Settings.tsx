import { useState, useCallback, useRef } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  fetchSettings,
  updateSettings,
  applySettings,
  resetSettings,
  exportSettings,
  importSettings,
  fetchDbInfo,
  runQuery,
  clearDatabase,
  exportDatabase,
  type LeethaSettings,
  browseFilesystem,
  type BrowseResult,
} from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogClose,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { useTheme, ACCENT_PRESETS } from "@/providers/theme-provider";
import {
  Save,
  RotateCcw,
  Download,
  Upload,
  Trash2,
  Play,
  Database,
  Settings2,
  Crosshair,
  AlertTriangle,
  Copy,
  HardDrive,
  Terminal,
  Palette,
  Bell,
  Plus,
  X,
  Send,
  ShieldCheck,
  FolderOpen,
  Folder,
  FileText,
  ChevronUp,
} from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  fetchNotificationSettings,
  updateNotificationSettings,
  testNotification,
} from "@/lib/api";

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

const TABS = [
  { id: "general", label: "General", icon: Settings2 },
  { id: "capture", label: "Capture & Probing", icon: Crosshair },
  { id: "database", label: "Database", icon: Database },
  { id: "notifications", label: "Notifications", icon: Bell },
  { id: "appearance", label: "Appearance", icon: Palette },
  { id: "actions", label: "Import / Export", icon: Download },
] as const;

type TabId = (typeof TABS)[number]["id"];

function ConfirmAction({ trigger, title, description, onConfirm }: {
  trigger: React.ReactNode; title: string; description: string; onConfirm: () => void;
}) {
  return (
    <Dialog>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <DialogClose asChild><Button variant="outline">Cancel</Button></DialogClose>
          <DialogClose asChild><Button variant="destructive" onClick={onConfirm}>Confirm</Button></DialogClose>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function Settings() {
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [activeTab, setActiveTab] = useState<TabId>("general");

  const { data: settings, isLoading } = useQuery({ queryKey: ["settings"], queryFn: fetchSettings });
  const { data: dbInfo } = useQuery({ queryKey: ["db-info"], queryFn: fetchDbInfo });

  const [draft, setDraft] = useState<Partial<LeethaSettings>>({});
  const [restartRequired, setRestartRequired] = useState(false);
  const [saving, setSaving] = useState(false);

  const merged = { ...settings, ...draft } as LeethaSettings | undefined;
  const hasDraft = Object.keys(draft).length > 0;

  const updateField = useCallback((key: string, value: string | number | boolean) => {
    setDraft((prev) => ({ ...prev, [key]: value }));
  }, []);

  const handleSave = useCallback(async () => {
    if (!hasDraft) { toast.info("No changes to save"); return; }
    setSaving(true);
    try {
      await updateSettings(draft);
      setDraft({});
      setRestartRequired(true);
      queryClient.invalidateQueries({ queryKey: ["settings"] });
      toast.success("Settings saved");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to save");
    } finally { setSaving(false); }
  }, [draft, hasDraft, queryClient]);

  const handleApply = useCallback(async () => {
    try { await applySettings(); setRestartRequired(false); toast.success("Restarting..."); }
    catch (err) { toast.error(err instanceof Error ? err.message : "Failed"); }
  }, []);

  const handleReset = useCallback(async () => {
    try {
      await resetSettings();
      setDraft({});
      setRestartRequired(true);
      queryClient.invalidateQueries({ queryKey: ["settings"] });
      toast.success("Settings reset to defaults");
    } catch (err) { toast.error(err instanceof Error ? err.message : "Failed"); }
  }, [queryClient]);

  const handleImport = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const data = JSON.parse(await file.text());
      await importSettings(data);
      setDraft({});
      setRestartRequired(true);
      queryClient.invalidateQueries({ queryKey: ["settings"] });
      toast.success("Settings imported");
    } catch (err) { toast.error(err instanceof Error ? err.message : "Failed"); }
    if (fileInputRef.current) fileInputRef.current.value = "";
  }, [queryClient]);

  const handleClearDb = useCallback(async () => {
    try {
      await clearDatabase();
      // Force refetch everything — device count, stats, db info
      await queryClient.refetchQueries({ queryKey: ["db-info"] });
      await queryClient.invalidateQueries({ queryKey: ["stats"] });
      await queryClient.invalidateQueries({ queryKey: ["devices"] });
      toast.success("Database cleared — all hosts removed");
    } catch (err) { toast.error(err instanceof Error ? err.message : "Failed to clear database"); }
  }, [queryClient]);

  // SQL Console state
  const [sql, setSql] = useState("SELECT mac, ip_v4, hostname FROM devices LIMIT 20");
  const [sqlResult, setSqlResult] = useState<{ columns: string[]; rows: unknown[][] } | null>(null);
  const [sqlRunning, setSqlRunning] = useState(false);
  const [queryHistory, setQueryHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [queryTime, setQueryTime] = useState<number | null>(null);

  const handleRunQuery = useCallback(async () => {
    setSqlRunning(true);
    setQueryTime(null);
    const start = performance.now();
    try {
      const result = await runQuery(sql);
      setQueryTime(performance.now() - start);
      setSqlResult(result);
      setQueryHistory((prev) => {
        const filtered = prev.filter((q) => q !== sql);
        return [sql, ...filtered].slice(0, 20);
      });
      setHistoryIndex(-1);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Query failed");
      setSqlResult(null);
    } finally {
      setSqlRunning(false);
    }
  }, [sql]);

  if (isLoading || !merged) {
    return <div className="flex items-center justify-center h-64 text-muted-foreground">Loading settings...</div>;
  }

  return (
    <div className="space-y-0">
      {/* Restart banner */}
      {restartRequired && (
        <div className="flex items-center justify-between rounded-lg border border-yellow-500/30 bg-yellow-500/[0.06] px-4 py-3 mb-4">
          <div className="flex items-center gap-2 text-sm font-medium text-yellow-400">
            <AlertTriangle size={16} />
            Settings saved. A restart is required for changes to take effect.
          </div>
          <Button size="sm" onClick={handleApply}>Apply &amp; Restart</Button>
        </div>
      )}

      {/* Tab bar */}
      <div className="flex items-center justify-between border-b border-border mb-6">
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
        <Button
          size="sm"
          onClick={handleSave}
          disabled={saving || !hasDraft}
          className="mb-2"
        >
          <Save size={14} className="mr-1.5" />
          {saving ? "Saving..." : "Save"}
        </Button>
      </div>

      {/* Tab content */}
      <div className="rounded-xl bg-card border border-border p-6">
        {activeTab === "general" && (
          <div className="space-y-6">
            <div>
              <h3 className="text-base font-semibold mb-1">General Settings</h3>
              <p className="text-sm text-muted-foreground">Web server, background workers, and data pipeline configuration.</p>
            </div>
            <Separator />

            {/* Web Server */}
            <div className="space-y-4">
              <div>
                <h4 className="text-sm font-semibold">Web Server</h4>
                <p className="text-xs text-muted-foreground">Address and port the dashboard listens on.</p>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <SettingField label="Bind Address" hint="IP address to bind the web server to" value={merged.web_host ?? ""} onChange={(v) => updateField("web_host", v)} placeholder="0.0.0.0" />
                <SettingField label="Port" hint="Port for the web server" type="number" value={merged.web_port ?? ""} onChange={(v) => updateField("web_port", Number(v))} />
              </div>
            </div>

            <Separator />

            {/* TLS / HTTPS */}
            <div className="space-y-4">
              <div>
                <h4 className="text-sm font-semibold flex items-center gap-1.5"><ShieldCheck className="h-4 w-4" /> TLS / HTTPS</h4>
                <p className="text-xs text-muted-foreground">Encrypt web traffic with HTTPS. Auto-generates a self-signed certificate if no custom cert is provided.</p>
              </div>
              <div className="flex items-center justify-between rounded-lg bg-secondary/50 border border-border p-4">
                <div>
                  <div className="text-sm font-medium">HTTPS Enabled</div>
                  <div className="text-xs text-muted-foreground">Serve the web UI over HTTPS (requires restart)</div>
                </div>
                <Switch checked={merged.web_tls ?? true} onCheckedChange={(c) => updateField("web_tls", c)} />
              </div>
              {merged.web_tls !== false && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <FilePathField label="TLS Certificate" hint="Leave empty to auto-generate a self-signed cert" value={merged.web_tls_cert ?? ""} onChange={(v) => updateField("web_tls_cert", v)} placeholder="Auto-generated" browseTitle="Select TLS Certificate" />
                  <FilePathField label="TLS Private Key" hint="Leave empty to auto-generate" value={merged.web_tls_key ?? ""} onChange={(v) => updateField("web_tls_key", v)} placeholder="Auto-generated" browseTitle="Select TLS Private Key" />
                </div>
              )}
            </div>

            <Separator />

            {/* Background Workers */}
            <div className="space-y-4">
              <div>
                <h4 className="text-sm font-semibold">Background Workers</h4>
                <p className="text-xs text-muted-foreground">Controls how many workers process captured packets in parallel.</p>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <SettingField label="Worker Count" hint="Number of background workers" type="number" value={merged.worker_count ?? ""} onChange={(v) => updateField("worker_count", Number(v))} />
                <SettingField label="Sync Interval (days)" hint="Days between fingerprint source syncs" type="number" value={merged.sync_interval ?? ""} onChange={(v) => updateField("sync_interval", Number(v))} />
              </div>
            </div>

            <Separator />

            {/* Database Pipeline */}
            <div className="space-y-4">
              <div>
                <h4 className="text-sm font-semibold">Database Pipeline</h4>
                <p className="text-xs text-muted-foreground">Tuning for how captured data is batched and flushed to the database.</p>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <SettingField label="Batch Size" hint="Records per database batch write" type="number" value={merged.db_batch_size ?? ""} onChange={(v) => updateField("db_batch_size", Number(v))} />
                <SettingField label="Flush Interval (s)" hint="Seconds between database flushes" type="number" value={merged.db_flush_interval ?? ""} onChange={(v) => updateField("db_flush_interval", Number(v))} step="0.01" />
              </div>
            </div>
          </div>
        )}

        {activeTab === "capture" && (
          <div className="space-y-6">
            <div>
              <h3 className="text-base font-semibold mb-1">Capture &amp; Probing</h3>
              <p className="text-sm text-muted-foreground">Packet capture filters and active probing configuration.</p>
            </div>
            <Separator />
            <div className="space-y-6">
              <SettingField label="BPF Filter" hint="Berkeley Packet Filter expression. Leave empty for no filter." value={merged.bpf_filter ?? ""} onChange={(v) => updateField("bpf_filter", v)} mono placeholder="e.g. not port 22" />
              <Separator />
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                <div className="flex items-center justify-between rounded-lg bg-secondary/50 border border-border p-4">
                  <div>
                    <div className="text-sm font-medium">Probe Enabled</div>
                    <div className="text-xs text-muted-foreground">Enable active network probing</div>
                  </div>
                  <Switch checked={merged.probe_enabled ?? false} onCheckedChange={(c) => updateField("probe_enabled", c)} />
                </div>
                <SettingField label="Max Concurrent Probes" hint="Maximum simultaneous probes" type="number" value={merged.max_concurrent_probes ?? ""} onChange={(v) => updateField("max_concurrent_probes", Number(v))} />
                <SettingField label="Probe Cooldown (s)" hint="Seconds between probe runs per host" type="number" value={merged.probe_cooldown ?? ""} onChange={(v) => updateField("probe_cooldown", Number(v))} />
              </div>
            </div>
          </div>
        )}

        {activeTab === "notifications" && <NotificationsTab />}

        {activeTab === "appearance" && <AppearanceTab />}

        {activeTab === "database" && (
          <div className="space-y-6">
            <div>
              <h3 className="text-base font-semibold mb-1">Database</h3>
              <p className="text-sm text-muted-foreground">Storage metrics, data export, and query console.</p>
            </div>
            <Separator />

            {/* Storage Overview */}
            <div className="space-y-4">
              <div>
                <h4 className="text-sm font-semibold">Storage Overview</h4>
                <p className="text-xs text-muted-foreground">Database size, table counts, and storage details.</p>
              </div>
              {dbInfo && (
                <>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <InfoCard icon={<Database size={16} />} label="Database Path" value={dbInfo.db_path} mono copyable />
                    <InfoCard icon={<HardDrive size={16} />} label="Database Size" value={`${formatBytes(dbInfo.db_size_bytes)}${dbInfo.wal_size_bytes ? ` (+${formatBytes(dbInfo.wal_size_bytes)} WAL)` : ""}`} />
                    <InfoCard icon={<Settings2 size={16} />} label="Pages" value={`${dbInfo.page_count.toLocaleString()} pages (${formatBytes(dbInfo.page_size)} each)`} />
                    <InfoCard icon={<Database size={16} />} label="Last Modified" value={dbInfo.last_modified ? new Date(dbInfo.last_modified * 1000).toLocaleString() : "Unknown"} />
                  </div>
                  {dbInfo.table_counts && (
                    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                      {Object.entries(dbInfo.table_counts).map(([table, count]) => (
                        <div key={table} className="rounded-lg bg-secondary/50 border border-border px-3 py-2.5 text-center">
                          <div className="text-lg font-semibold tabular-nums">{(count as number).toLocaleString()}</div>
                          <div className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{table}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>

            <Separator />

            {/* Export */}
            <div className="space-y-4">
              <div>
                <h4 className="text-sm font-semibold">Export Database</h4>
                <p className="text-xs text-muted-foreground">Download a copy of the database for backup or analysis.</p>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="rounded-lg border border-border bg-secondary/30 p-5 space-y-3">
                  <div className="flex items-center gap-2">
                    <Download size={18} className="text-primary" />
                    <h4 className="font-semibold text-sm">SQLite File</h4>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Download the raw SQLite database file. Use with any SQLite client for full access.
                  </p>
                  <Button variant="outline" size="sm" onClick={() => { exportDatabase("sqlite").catch((e) => toast.error(e.message)); }}>
                    <Download size={14} className="mr-1.5" /> Download .db
                  </Button>
                </div>
                <div className="rounded-lg border border-border bg-secondary/30 p-5 space-y-3">
                  <div className="flex items-center gap-2">
                    <Terminal size={18} className="text-primary" />
                    <h4 className="font-semibold text-sm">SQL Dump</h4>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Export schema and data as a SQL text file with CREATE and INSERT statements.
                  </p>
                  <Button variant="outline" size="sm" onClick={() => { exportDatabase("sql").catch((e) => toast.error(e.message)); }}>
                    <Download size={14} className="mr-1.5" /> Download .sql
                  </Button>
                </div>
              </div>
            </div>

            <Separator />

            {/* SQL Console */}
            <div className="space-y-4">
              <div>
                <h4 className="text-sm font-semibold">SQL Console</h4>
                <p className="text-xs text-muted-foreground">Read-only query console. Only SELECT statements are allowed. Press Up/Down to cycle query history.</p>
              </div>
              <textarea
                value={sql}
                onChange={(e) => setSql(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "ArrowUp" && queryHistory.length > 0) {
                    e.preventDefault();
                    const next = Math.min(historyIndex + 1, queryHistory.length - 1);
                    setHistoryIndex(next);
                    setSql(queryHistory[next]);
                  } else if (e.key === "ArrowDown" && historyIndex > 0) {
                    e.preventDefault();
                    const next = historyIndex - 1;
                    setHistoryIndex(next);
                    setSql(queryHistory[next]);
                  } else if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
                    e.preventDefault();
                    handleRunQuery();
                  }
                }}
                rows={4}
                className="w-full rounded-lg border border-border bg-black/40 px-4 py-3 text-sm font-mono text-green-400 placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-ring resize-vertical"
                placeholder="SELECT * FROM hosts LIMIT 10"
              />
              <div className="flex items-center gap-3">
                <Button size="sm" onClick={handleRunQuery} disabled={sqlRunning || !sql.trim()}>
                  <Play size={14} className="mr-1" />
                  {sqlRunning ? "Running..." : "Run Query"}
                </Button>
                <span className="text-xs text-muted-foreground">Ctrl+Enter to run</span>
                {queryTime !== null && sqlResult && (
                  <span className="text-xs text-muted-foreground ml-auto tabular-nums">
                    {sqlResult.rows.length.toLocaleString()} row{sqlResult.rows.length !== 1 ? "s" : ""} in {queryTime.toFixed(0)}ms
                  </span>
                )}
              </div>

              {sqlResult && (
                <div className="rounded-lg border border-border overflow-auto max-h-96">
                  <Table>
                    <TableHeader>
                      <TableRow className="border-border">
                        {sqlResult.columns.map((col) => (
                          <TableHead key={col} className="text-xs font-mono text-muted-foreground">{col}</TableHead>
                        ))}
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {sqlResult.rows.length === 0 ? (
                        <TableRow>
                          <TableCell colSpan={sqlResult.columns.length} className="text-center text-muted-foreground py-8">
                            No rows returned
                          </TableCell>
                        </TableRow>
                      ) : (
                        sqlResult.rows.map((row, i) => (
                          <TableRow key={i} className="border-border">
                            {row.map((cell, j) => (
                              <TableCell key={j} className="text-xs font-mono py-1.5">
                                {cell === null ? <span className="text-muted-foreground italic">NULL</span> : String(cell)}
                              </TableCell>
                            ))}
                          </TableRow>
                        ))
                      )}
                    </TableBody>
                  </Table>
                </div>
              )}
            </div>

            <Separator />

            {/* Danger Zone */}
            <div className="space-y-4 rounded-lg border border-destructive/30 bg-destructive/[0.03] p-5">
              <div>
                <h4 className="text-sm font-semibold text-destructive">Danger Zone</h4>
                <p className="text-xs text-muted-foreground">Destructive actions that cannot be undone.</p>
              </div>
              <div className="flex flex-wrap gap-3">
                <ConfirmAction
                  trigger={
                    <Button variant="outline" size="sm" className="text-destructive border-destructive/30 hover:bg-destructive/10">
                      <Trash2 size={14} className="mr-1.5" /> Clear All Hosts
                    </Button>
                  }
                  title="Clear Database"
                  description="This will permanently delete all identified hosts and associated data. This action cannot be undone."
                  onConfirm={handleClearDb}
                />
                <ConfirmAction
                  trigger={
                    <Button variant="outline" size="sm" className="text-destructive border-destructive/30 hover:bg-destructive/10">
                      <RotateCcw size={14} className="mr-1.5" /> Reset to Defaults
                    </Button>
                  }
                  title="Reset Settings"
                  description="This will reset all settings to their default values. You will need to restart for changes to take effect."
                  onConfirm={handleReset}
                />
              </div>
            </div>
          </div>
        )}

        {activeTab === "actions" && (
          <div className="space-y-6">
            <div>
              <h3 className="text-base font-semibold mb-1">Import &amp; Export</h3>
              <p className="text-sm text-muted-foreground">Backup and restore your Leetha settings configuration. For database exports, use the Database tab.</p>
            </div>
            <Separator />
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Export */}
              <div className="rounded-lg border border-border bg-secondary/30 p-5 space-y-3">
                <div className="flex items-center gap-2">
                  <Download size={18} className="text-primary" />
                  <h4 className="font-semibold text-sm">Export Configuration</h4>
                </div>
                <p className="text-xs text-muted-foreground">
                  Download your current settings as a JSON file. This includes all general, capture, and probing settings.
                </p>
                <Button variant="outline" size="sm" onClick={() => exportSettings()}>
                  <Download size={14} className="mr-1.5" /> Download JSON
                </Button>
              </div>

              {/* Import */}
              <div className="rounded-lg border border-border bg-secondary/30 p-5 space-y-3">
                <div className="flex items-center gap-2">
                  <Upload size={18} className="text-primary" />
                  <h4 className="font-semibold text-sm">Import Configuration</h4>
                </div>
                <p className="text-xs text-muted-foreground">
                  Upload a previously exported JSON settings file. This will overwrite your current settings.
                </p>
                <Button variant="outline" size="sm" onClick={() => fileInputRef.current?.click()}>
                  <Upload size={14} className="mr-1.5" /> Upload JSON
                </Button>
                <input ref={fileInputRef} type="file" accept=".json" className="hidden" onChange={handleImport} />
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════
//  Notifications Tab
// ═══════════════════════════════════════════

const SEVERITY_OPTIONS = [
  { value: "info", label: "Info & above (all)" },
  { value: "low", label: "Low & above" },
  { value: "warning", label: "Warning & above (default)" },
  { value: "high", label: "High & above" },
  { value: "critical", label: "Critical only" },
];

function NotificationsTab() {
  const { data, refetch } = useQuery({
    queryKey: ["notification-settings"],
    queryFn: fetchNotificationSettings,
  });

  const [urls, setUrls] = useState<string[]>([]);
  const [minSeverity, setMinSeverity] = useState("warning");
  const [newUrl, setNewUrl] = useState("");
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [loaded, setLoaded] = useState(false);

  // Sync state from server on first load
  if (data && !loaded) {
    setUrls(data.urls);
    setMinSeverity(data.min_severity);
    setLoaded(true);
  }

  const addUrl = () => {
    const trimmed = newUrl.trim();
    if (trimmed && !urls.includes(trimmed)) {
      setUrls([...urls, trimmed]);
      setNewUrl("");
    }
  };

  const removeUrl = (index: number) => {
    setUrls(urls.filter((_, i) => i !== index));
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await updateNotificationSettings({ urls, min_severity: minSeverity });
      refetch();
      toast.success("Notification settings saved");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    setTesting(true);
    try {
      await testNotification();
      toast.success("Test notification sent");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Test failed");
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-base font-semibold mb-1">Notifications</h3>
        <p className="text-sm text-muted-foreground">
          Send alerts to Telegram, Discord, Slack, email, webhooks, and 90+ other services via{" "}
          <span className="font-medium text-foreground">Apprise</span> URLs.
        </p>
      </div>
      <Separator />

      {/* Minimum severity */}
      <div className="space-y-2">
        <h4 className="text-sm font-semibold">Minimum Severity</h4>
        <p className="text-xs text-muted-foreground">Only findings at or above this level will trigger a notification.</p>
        <Select value={minSeverity} onValueChange={setMinSeverity}>
          <SelectTrigger className="w-64">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {SEVERITY_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <Separator />

      {/* URL list */}
      <div className="space-y-3">
        <h4 className="text-sm font-semibold">Notification URLs</h4>
        <p className="text-xs text-muted-foreground">
          Add Apprise-compatible URLs. Examples: <code className="text-[11px] bg-secondary px-1 py-0.5 rounded">tgram://bottoken/ChatID</code>{" "}
          <code className="text-[11px] bg-secondary px-1 py-0.5 rounded">discord://WebhookID/WebhookToken</code>{" "}
          <code className="text-[11px] bg-secondary px-1 py-0.5 rounded">slack://TokenA/TokenB/TokenC</code>
        </p>

        {urls.length > 0 && (
          <div className="space-y-2">
            {urls.map((url, i) => (
              <div key={i} className="flex items-center gap-2 rounded-lg bg-secondary/50 border border-border px-3 py-2">
                <span className="flex-1 text-sm font-mono break-all">{url}</span>
                <button
                  onClick={() => removeUrl(i)}
                  className="shrink-0 p-1 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
                  title="Remove"
                >
                  <X size={14} />
                </button>
              </div>
            ))}
          </div>
        )}

        <div className="flex gap-2">
          <Input
            value={newUrl}
            onChange={(e) => setNewUrl(e.target.value)}
            placeholder="e.g. tgram://bottoken/ChatID"
            className="font-mono text-sm bg-secondary border-border"
            onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addUrl(); } }}
          />
          <Button variant="outline" size="sm" onClick={addUrl} disabled={!newUrl.trim()}>
            <Plus size={14} className="mr-1" /> Add
          </Button>
        </div>

        {urls.length === 0 && (
          <div className="rounded-lg border border-dashed border-border py-8 text-center text-sm text-muted-foreground">
            No notification URLs configured. Add one above to start receiving alerts.
          </div>
        )}
      </div>

      <Separator />

      {/* Actions */}
      <div className="flex gap-3">
        <Button onClick={handleSave} disabled={saving}>
          <Save size={14} className="mr-1.5" />
          {saving ? "Saving..." : "Save Notifications"}
        </Button>
        <Button variant="outline" onClick={handleTest} disabled={testing || urls.length === 0}>
          <Send size={14} className="mr-1.5" />
          {testing ? "Sending..." : "Send Test"}
        </Button>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════
//  Appearance Tab
// ═══════════════════════════════════════════

function AppearanceTab() {
  const { appearance, updateAppearance, resetAppearance } = useTheme();

  const FONT_OPTIONS = [
    { value: "system", label: "System Default", preview: "ui-sans-serif, system-ui" },
    { value: "inter", label: "Inter", preview: "'Inter', sans-serif" },
    { value: "mono", label: "Monospace", preview: "ui-monospace, Consolas" },
  ];

  const SIZE_OPTIONS = [
    { value: 13, label: "Small (13px)" },
    { value: 14, label: "Compact (14px)" },
    { value: 15, label: "Default (15px)" },
    { value: 16, label: "Large (16px)" },
    { value: 18, label: "Extra Large (18px)" },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-base font-semibold mb-1">Appearance</h3>
        <p className="text-sm text-muted-foreground">Customize the look and feel of the Leetha dashboard. Changes apply instantly.</p>
      </div>
      <Separator />

      {/* Theme */}
      <div className="space-y-3">
        <h4 className="text-sm font-semibold">Theme</h4>
        <div className="flex gap-3">
          <button
            onClick={() => updateAppearance({ theme: "dark" })}
            className={cn(
              "flex-1 rounded-lg border-2 p-4 text-center transition-all",
              appearance.theme === "dark" ? "border-primary bg-primary/5" : "border-border hover:border-primary/30"
            )}
          >
            <div className="w-full h-16 rounded bg-black border border-gray-800 mb-2 flex items-center justify-center">
              <div className="w-8 h-1 bg-blue-500 rounded" />
            </div>
            <span className="text-xs font-medium">Dark</span>
          </button>
          <button
            onClick={() => updateAppearance({ theme: "light" })}
            className={cn(
              "flex-1 rounded-lg border-2 p-4 text-center transition-all",
              appearance.theme === "light" ? "border-primary bg-primary/5" : "border-border hover:border-primary/30"
            )}
          >
            <div className="w-full h-16 rounded bg-white border border-gray-200 mb-2 flex items-center justify-center">
              <div className="w-8 h-1 bg-blue-500 rounded" />
            </div>
            <span className="text-xs font-medium">Light</span>
          </button>
        </div>
      </div>

      <Separator />

      {/* Accent Color */}
      <div className="space-y-3">
        <h4 className="text-sm font-semibold">Accent Color</h4>
        <p className="text-xs text-muted-foreground">Used for active states, buttons, links, and highlights.</p>
        <div className="flex flex-wrap gap-2">
          {ACCENT_PRESETS.map((preset) => (
            <button
              key={preset.value}
              onClick={() => updateAppearance({ accentColor: preset.value })}
              className={cn(
                "w-10 h-10 rounded-lg border-2 transition-all hover:scale-110",
                appearance.accentColor === preset.value ? "border-foreground scale-110" : "border-transparent"
              )}
              style={{ background: preset.preview }}
              title={preset.name}
            />
          ))}
        </div>
        <p className="text-[10px] text-muted-foreground">
          Active: <span className="font-mono" style={{ color: `hsl(${appearance.accentColor})` }}>{ACCENT_PRESETS.find((p) => p.value === appearance.accentColor)?.name ?? "Custom"}</span>
        </p>
      </div>

      <Separator />

      {/* Font */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="space-y-3">
          <h4 className="text-sm font-semibold">Font Family</h4>
          <div className="space-y-1.5">
            {FONT_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                onClick={() => updateAppearance({ fontFamily: opt.value as "system" | "inter" | "mono" })}
                className={cn(
                  "w-full text-left rounded-lg border px-4 py-2.5 transition-all",
                  appearance.fontFamily === opt.value ? "border-primary bg-primary/5" : "border-border hover:border-primary/30"
                )}
              >
                <div className="text-sm font-medium">{opt.label}</div>
                <div className="text-[10px] text-muted-foreground font-mono">{opt.preview}</div>
              </button>
            ))}
          </div>
        </div>

        <div className="space-y-3">
          <h4 className="text-sm font-semibold">Font Size</h4>
          <div className="space-y-1.5">
            {SIZE_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                onClick={() => updateAppearance({ fontSize: opt.value })}
                className={cn(
                  "w-full text-left rounded-lg border px-4 py-2.5 transition-all",
                  appearance.fontSize === opt.value ? "border-primary bg-primary/5" : "border-border hover:border-primary/30"
                )}
              >
                <span className="text-sm">{opt.label}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      <Separator />

      {/* Display Options */}
      <div className="space-y-4">
        <h4 className="text-sm font-semibold">Display Options</h4>

        <div className="flex items-center justify-between rounded-lg bg-secondary/30 border border-border px-4 py-3">
          <div>
            <div className="text-sm font-medium">Animations</div>
            <div className="text-xs text-muted-foreground">Enable hover animations and transitions</div>
          </div>
          <Switch checked={appearance.animationsEnabled} onCheckedChange={(v) => updateAppearance({ animationsEnabled: v })} />
        </div>

        <div className="flex items-center justify-between rounded-lg bg-secondary/30 border border-border px-4 py-3">
          <div>
            <div className="text-sm font-medium">High Contrast</div>
            <div className="text-xs text-muted-foreground">Increase text and border contrast for better readability</div>
          </div>
          <Switch checked={appearance.highContrast} onCheckedChange={(v) => updateAppearance({ highContrast: v })} />
        </div>
      </div>

      <Separator />

      {/* Reset */}
      <div className="flex items-center justify-between">
        <div>
          <div className="text-sm font-medium">Reset Appearance</div>
          <div className="text-xs text-muted-foreground">Restore all appearance settings to defaults</div>
        </div>
        <Button variant="outline" size="sm" onClick={() => { resetAppearance(); toast.success("Appearance reset to defaults"); }}>
          <RotateCcw size={14} className="mr-1.5" /> Reset
        </Button>
      </div>
    </div>
  );
}

function SettingField({ label, hint, type = "text", value, onChange, mono, placeholder, step }: {
  label: string; hint?: string; type?: string; value: string | number; onChange: (v: string) => void; mono?: boolean; placeholder?: string; step?: string;
}) {
  return (
    <div>
      <div className="text-sm font-medium mb-1">{label}</div>
      {hint && <div className="text-xs text-muted-foreground mb-1.5">{hint}</div>}
      <Input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={cn("bg-secondary border-border", mono && "font-mono")}
        placeholder={placeholder}
        step={step}
      />
    </div>
  );
}

function FileBrowserDialog({ open, onOpenChange, onSelect, title, filter }: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSelect: (path: string) => void;
  title: string;
  filter?: (name: string) => boolean;
}) {
  const [browsePath, setBrowsePath] = useState<string>("");
  const [browseData, setBrowseData] = useState<BrowseResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const loadDir = useCallback(async (path?: string) => {
    setLoading(true);
    setError("");
    try {
      const data = await browseFilesystem(path);
      setBrowseData(data);
      setBrowsePath(data.current);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to browse");
    } finally {
      setLoading(false);
    }
  }, []);

  // Load initial directory when opened
  const prevOpen = useRef(false);
  if (open && !prevOpen.current) {
    prevOpen.current = true;
    loadDir();
  }
  if (!open && prevOpen.current) {
    prevOpen.current = false;
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>Navigate to select a file</DialogDescription>
        </DialogHeader>

        {/* Current path */}
        <div className="flex items-center gap-2">
          <Input
            value={browsePath}
            onChange={(e) => setBrowsePath(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") loadDir(browsePath); }}
            className="font-mono text-xs bg-secondary border-border"
            placeholder="/path/to/directory"
          />
          <Button variant="outline" size="sm" onClick={() => loadDir(browsePath)}>Go</Button>
        </div>

        {error && <div className="text-sm text-destructive">{error}</div>}

        {/* File listing */}
        <ScrollArea className="h-72 rounded-md border border-border">
          {loading ? (
            <div className="flex items-center justify-center h-full text-sm text-muted-foreground">Loading...</div>
          ) : browseData ? (
            <div className="p-1">
              {browseData.parent && (
                <button
                  onClick={() => loadDir(browseData.parent!)}
                  className="flex items-center gap-2 w-full rounded-md px-3 py-2 text-sm hover:bg-secondary/80 transition-colors text-muted-foreground"
                >
                  <ChevronUp className="h-4 w-4" />
                  <span>..</span>
                </button>
              )}
              {browseData.entries.map((entry) => (
                <button
                  key={entry.path}
                  onClick={() => {
                    if (entry.is_dir) {
                      loadDir(entry.path);
                    } else {
                      onSelect(entry.path);
                      onOpenChange(false);
                    }
                  }}
                  className={cn(
                    "flex items-center gap-2 w-full rounded-md px-3 py-2 text-sm hover:bg-secondary/80 transition-colors text-left",
                    !entry.is_dir && filter && !filter(entry.name) && "opacity-40"
                  )}
                >
                  {entry.is_dir ? (
                    <Folder className="h-4 w-4 text-blue-400 shrink-0" />
                  ) : (
                    <FileText className="h-4 w-4 text-muted-foreground shrink-0" />
                  )}
                  <span className="truncate font-mono text-xs">{entry.name}</span>
                  {!entry.is_dir && entry.size != null && (
                    <span className="ml-auto text-xs text-muted-foreground shrink-0">
                      {entry.size < 1024 ? `${entry.size} B` : `${(entry.size / 1024).toFixed(1)} KB`}
                    </span>
                  )}
                </button>
              ))}
              {browseData.entries.length === 0 && (
                <div className="text-sm text-muted-foreground text-center py-8">Empty directory</div>
              )}
            </div>
          ) : null}
        </ScrollArea>

        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline" size="sm">Cancel</Button>
          </DialogClose>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function FilePathField({ label, hint, value, onChange, placeholder, browseTitle }: {
  label: string;
  hint?: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  browseTitle: string;
}) {
  const [browserOpen, setBrowserOpen] = useState(false);
  const certFilter = (name: string) => /\.(pem|crt|cer|key|pub)$/i.test(name);

  return (
    <div>
      <div className="text-sm font-medium mb-1">{label}</div>
      {hint && <div className="text-xs text-muted-foreground mb-1.5">{hint}</div>}
      <div className="flex gap-2">
        <Input
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="bg-secondary border-border font-mono flex-1"
          placeholder={placeholder}
        />
        <Button variant="outline" size="icon" onClick={() => setBrowserOpen(true)} title="Browse...">
          <FolderOpen className="h-4 w-4" />
        </Button>
      </div>
      <FileBrowserDialog
        open={browserOpen}
        onOpenChange={setBrowserOpen}
        onSelect={onChange}
        title={browseTitle}
        filter={certFilter}
      />
    </div>
  );
}

function InfoCard({ icon, label, value, mono, copyable }: {
  icon: React.ReactNode; label: string; value: string; mono?: boolean; copyable?: boolean;
}) {
  const handleCopy = () => {
    navigator.clipboard.writeText(value);
    toast.success("Copied to clipboard");
  };

  return (
    <div className="rounded-lg bg-secondary/50 border border-border p-4">
      <div className="flex items-center gap-1.5 mb-2">
        <span className="text-muted-foreground">{icon}</span>
        <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">{label}</span>
      </div>
      <div className="flex items-center gap-1.5">
        <span className={cn("text-sm font-medium break-all", mono && "font-mono text-xs")}>{value}</span>
        {copyable && (
          <button onClick={handleCopy} className="shrink-0 p-0.5 rounded hover:bg-accent transition-colors" title="Copy">
            <Copy size={12} className="text-muted-foreground" />
          </button>
        )}
      </div>
    </div>
  );
}
