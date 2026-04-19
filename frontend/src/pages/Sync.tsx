import { useState, useCallback, useRef, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  fetchSyncSources,
  triggerValidation,
  fetchValidationReport,
  type SyncProgressEvent,
} from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { InventorySources } from "@/components/InventorySources";
import { cn } from "@/lib/utils";
import {
  RefreshCw,
  CheckCircle,
  XCircle,
  Loader2,
  ShieldCheck,
} from "lucide-react";

function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null) return "?";
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

const TYPE_COLORS: Record<string, string> = {
  csv: "text-green-400 border-green-400/30",
  json: "text-amber-400 border-amber-400/30",
  text: "text-blue-400 border-blue-400/30",
  git_multifile: "text-purple-400 border-purple-400/30",
};

interface SourceSyncState {
  status: "idle" | "syncing" | "downloading" | "parsing" | "complete" | "error";
  progress: number;
  detail: string;
}

const defaultState: SourceSyncState = { status: "idle", progress: 0, detail: "" };

export default function Sync() {
  const { data: sourcesData } = useQuery({
    queryKey: ["sync-sources"],
    queryFn: fetchSyncSources,
  });

  const sources = sourcesData?.sources ?? [];

  const [syncStates, setSyncStates] = useState<Record<string, SourceSyncState>>({});
  const [syncAllRunning, setSyncAllRunning] = useState(false);
  const [syncAllProgress, setSyncAllProgress] = useState({ completed: 0, total: 0, detail: "" });
  const [validating, setValidating] = useState(false);
  const [validationReport, setValidationReport] = useState<Record<string, unknown> | null>(null);
  const esRef = useRef<Map<string, EventSource>>(new Map());

  useEffect(() => {
    return () => {
      esRef.current.forEach((es) => es.close());
      esRef.current.clear();
    };
  }, []);

  const getState = (name: string): SourceSyncState => syncStates[name] ?? defaultState;

  const updateState = useCallback((name: string, update: Partial<SourceSyncState>) => {
    setSyncStates((prev) => ({
      ...prev,
      [name]: { ...(prev[name] ?? defaultState), ...update },
    }));
  }, []);

  // Load existing validation report on mount
  useEffect(() => {
    fetchValidationReport()
      .then((r) => setValidationReport(r))
      .catch(() => {});
  }, []);

  const handleSyncSource = useCallback(
    (sourceName: string) => {
      const existing = esRef.current.get(sourceName);
      if (existing) existing.close();

      updateState(sourceName, { status: "syncing", progress: 0, detail: "Connecting..." });

      const token = localStorage.getItem("leetha_token");
      const tokenParam = token ? `?token=${encodeURIComponent(token)}` : "";
      const es = new EventSource(`/api/sync/${encodeURIComponent(sourceName)}/stream${tokenParam}`);
      esRef.current.set(sourceName, es);

      es.onmessage = (e) => {
        try {
          const data: SyncProgressEvent = JSON.parse(e.data);
          if (data.event === "start") {
            updateState(sourceName, { status: "syncing", detail: `Connecting to ${data.url ?? "source"}` });
          } else if (data.event === "downloading") {
            const downloaded = data.downloaded ?? 0;
            const total = data.total ?? 0;
            const pct = total > 0 ? Math.min(100, (downloaded / total) * 100) : 0;
            let detail: string;
            if (data.unit === "files") {
              detail = `Downloading: ${downloaded}/${total} files (${pct.toFixed(0)}%)${data.current_file ? ` — ${data.current_file}` : ""}`;
            } else if (total > 0) {
              detail = `Downloading: ${formatBytes(downloaded)} / ${formatBytes(total)} (${pct.toFixed(0)}%)`;
            } else {
              detail = `Downloading: ${formatBytes(downloaded)}`;
            }
            updateState(sourceName, { status: "downloading", progress: pct, detail });
          } else if (data.event === "parsing") {
            updateState(sourceName, { status: "parsing", progress: 50, detail: "Parsing data..." });
          } else if (data.event === "complete") {
            const detail = `${(data.entries ?? 0).toLocaleString()} entries (${formatBytes(data.size)})`;
            updateState(sourceName, { status: "complete", progress: 100, detail });
            es.close();
            esRef.current.delete(sourceName);
          } else if (data.event === "error") {
            updateState(sourceName, { status: "error", progress: 100, detail: data.error ?? "Failed" });
            es.close();
            esRef.current.delete(sourceName);
          }
        } catch {
          // ignore
        }
      };

      es.onerror = () => {
        es.close();
        esRef.current.delete(sourceName);
        setSyncStates((prev) => {
          const cur = prev[sourceName];
          if (cur && cur.status !== "complete" && cur.status !== "error") {
            return { ...prev, [sourceName]: { ...cur, status: "error", detail: "Connection lost" } };
          }
          return prev;
        });
      };
    },
    [updateState]
  );

  const handleSyncAll = useCallback(() => {
    setSyncAllRunning(true);
    setSyncAllProgress({ completed: 0, total: 0, detail: "" });

    const token = localStorage.getItem("leetha_token");
    const tokenParam = token ? `?token=${encodeURIComponent(token)}` : "";
    const es = new EventSource(`/api/sync/stream${tokenParam}`);

    es.onmessage = (e) => {
      try {
        const data: SyncProgressEvent = JSON.parse(e.data);

        if (data.event === "sync_start") {
          setSyncAllProgress({ completed: 0, total: data.total_sources ?? 0, detail: "" });
          // Mark all as queued
          const reset: Record<string, SourceSyncState> = {};
          for (const s of sources) {
            reset[s.name] = { status: "syncing", progress: 0, detail: "Queued..." };
          }
          setSyncStates(reset);
        } else if (data.event === "start" && data.source) {
          updateState(data.source, { status: "syncing", detail: `Connecting to ${data.url ?? "source"}` });
        } else if (data.event === "downloading" && data.source) {
          const downloaded = data.downloaded ?? 0;
          const total = data.total ?? 0;
          const pct = total > 0 ? Math.min(100, (downloaded / total) * 100) : 0;
          let detail: string;
          if (data.unit === "files") {
            detail = `${downloaded}/${total} files`;
          } else if (total > 0) {
            detail = `${formatBytes(downloaded)} / ${formatBytes(total)} (${pct.toFixed(0)}%)`;
          } else {
            detail = formatBytes(downloaded);
          }
          updateState(data.source, { status: "downloading", progress: pct, detail });
        } else if (data.event === "parsing" && data.source) {
          updateState(data.source, { status: "parsing", detail: "Parsing data..." });
        } else if (data.event === "complete" && data.source) {
          const detail = `${(data.entries ?? 0).toLocaleString()} entries (${formatBytes(data.size)})`;
          updateState(data.source, { status: "complete", progress: 100, detail });
          setSyncAllProgress((prev) => ({ ...prev, completed: prev.completed + 1 }));
        } else if (data.event === "error" && data.source) {
          updateState(data.source, { status: "error", detail: data.error ?? "Failed" });
          setSyncAllProgress((prev) => ({ ...prev, completed: prev.completed + 1 }));
        } else if (data.event === "sync_complete") {
          setSyncAllProgress((prev) => ({
            ...prev,
            detail: `${data.succeeded ?? 0} succeeded, ${data.failed ?? 0} failed`,
          }));
          setSyncAllRunning(false);
          es.close();
          toast.success("All sources synced");
        }
      } catch {
        // ignore
      }
    };

    es.onerror = () => {
      es.close();
      setSyncAllRunning(false);
      toast.error("Connection lost during sync");
    };
  }, [sources, updateState]);

  const handleValidation = useCallback(async () => {
    setValidating(true);
    try {
      const report = await triggerValidation();
      setValidationReport(report as Record<string, unknown>);
      toast.success("Validation complete");
    } catch {
      // Try fetching the report separately
      try {
        const report = await fetchValidationReport();
        setValidationReport(report);
        toast.success("Validation complete");
      } catch (err) {
        toast.error(`Validation failed: ${err instanceof Error ? err.message : "unknown"}`);
      }
    } finally {
      setValidating(false);
    }
  }, []);

  const isBusy = (name: string) => {
    const s = getState(name);
    return s.status === "syncing" || s.status === "downloading" || s.status === "parsing";
  };

  return (
    <div className="space-y-6">
      {/* Phase A.3 — inventory-source uploads */}
      <InventorySources />

      {/* Header */}
      <div className="flex items-start justify-between">
        <p className="text-sm text-muted-foreground max-w-xl">
          Manage the reference databases used for passive device fingerprinting.
          Sync sources to update OUI lookups, DHCP fingerprints, JA3/JA4 hashes, and more.
        </p>
        <div className="flex items-center gap-3 shrink-0">
          {syncAllRunning && syncAllProgress.total > 0 && (
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground whitespace-nowrap">
                {syncAllProgress.detail || `${syncAllProgress.completed} / ${syncAllProgress.total}`}
              </span>
              <div className="w-24 h-1 bg-muted rounded-full overflow-hidden">
                <div
                  className={cn(
                    "h-full rounded-full transition-all",
                    syncAllProgress.detail ? "bg-success" : "bg-primary"
                  )}
                  style={{
                    width: syncAllProgress.total > 0
                      ? `${(syncAllProgress.completed / syncAllProgress.total) * 100}%`
                      : "0%",
                  }}
                />
              </div>
            </div>
          )}
          <Button onClick={handleSyncAll} disabled={syncAllRunning}>
            {syncAllRunning ? (
              <Loader2 size={16} className="mr-2 animate-spin" />
            ) : (
              <RefreshCw size={16} className="mr-2" />
            )}
            Refresh All Feeds
          </Button>
        </div>
      </div>

      {/* Sources list */}
      <div className="rounded-xl bg-card border border-border overflow-hidden">
        <div className="flex items-center justify-between px-5 py-3 border-b border-border">
          <h3 className="text-sm font-semibold">Available Sources</h3>
          <span className="text-xs text-muted-foreground">{sources.length} sources</span>
        </div>

        <div className="divide-y divide-border">
          {sources.map((source) => {
            const state = getState(source.name);
            const busy = isBusy(source.name);
            return (
              <div
                key={source.name}
                className={cn(
                  "flex items-start justify-between px-5 py-4",
                  state.status === "complete" && "bg-success/[0.03]",
                  state.status === "error" && "bg-destructive/[0.03]",
                  busy && "bg-primary/[0.03]"
                )}
              >
                <div className="space-y-1 min-w-0 flex-1 mr-4">
                  <div className="flex items-center gap-3">
                    <span className="font-semibold text-sm">{source.display_name}</span>
                    <Badge
                      variant="outline"
                      className={cn(
                        "text-[10px] uppercase font-semibold px-1.5",
                        TYPE_COLORS[source.source_type] ?? "text-muted-foreground"
                      )}
                    >
                      {source.source_type === "git_multifile" ? "multi" : source.source_type}
                    </Badge>
                    {state.status === "complete" && <CheckCircle size={14} className="text-success" />}
                    {state.status === "error" && <XCircle size={14} className="text-destructive" />}
                  </div>
                  <div className="text-xs font-mono text-muted-foreground/60 truncate max-w-[700px]">
                    {source.url}
                  </div>
                  <div className="text-xs text-muted-foreground">{source.description}</div>

                  {/* Progress bar */}
                  {(busy || state.status === "complete" || state.status === "error") && state.detail && (
                    <div className="mt-2 space-y-1">
                      {busy && (
                        <div className="w-full h-1.5 bg-muted rounded-full overflow-hidden">
                          <div
                            className={cn(
                              "h-full rounded-full transition-all",
                              state.status === "downloading" || state.status === "syncing"
                                ? state.progress > 0 ? "bg-primary" : "bg-primary animate-pulse w-[30%]"
                                : "bg-primary"
                            )}
                            style={state.progress > 0 ? { width: `${state.progress}%` } : undefined}
                          />
                        </div>
                      )}
                      <p className={cn(
                        "text-[11px] font-mono",
                        state.status === "complete" ? "text-success" : state.status === "error" ? "text-destructive" : "text-muted-foreground/60"
                      )}>
                        {state.detail}
                      </p>
                    </div>
                  )}
                </div>

                <Button
                  variant="ghost"
                  size="sm"
                  disabled={busy || syncAllRunning}
                  onClick={() => handleSyncSource(source.name)}
                  className="shrink-0"
                >
                  {busy ? (
                    <Loader2 size={14} className="animate-spin" />
                  ) : (
                    "Sync"
                  )}
                </Button>
              </div>
            );
          })}
        </div>
      </div>

      {/* Validation section */}
      <div className="rounded-xl bg-card border border-border overflow-hidden">
        <div className="flex items-center justify-between px-5 py-3 border-b border-border">
          <div className="flex items-center gap-2">
            <ShieldCheck size={16} />
            <h3 className="text-sm font-semibold">Data Integrity</h3>
          </div>
          <Button variant="outline" size="sm" onClick={handleValidation} disabled={validating}>
            {validating ? <Loader2 size={14} className="mr-2 animate-spin" /> : null}
            {validating ? "Running..." : "Run Integrity Check"}
          </Button>
        </div>
        <div className="px-5 py-4">
          {validationReport ? (
            <ValidationReport report={validationReport} />
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <CheckCircle size={24} className="mx-auto mb-2 text-success" />
              <p className="text-sm font-medium">No integrity report available</p>
              <p className="text-xs">Run an integrity check to verify data quality against IEEE OUI and RFC specs.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ValidationReport({ report }: { report: Record<string, unknown> }) {
  const timestamp = report.timestamp as string | undefined;
  const checks = (report.checks ?? {}) as Record<string, {
    count?: number;
    passed?: number;
    failed?: number;
    details?: unknown[];
  }>;

  return (
    <div className="space-y-3">
      {timestamp && (
        <p className="text-xs text-muted-foreground">Report generated: {timestamp}</p>
      )}
      {Object.entries(checks).map(([name, check]) => (
        <div key={name} className="rounded-lg bg-secondary/50 p-3">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium">{name.replace(/_/g, " ")}</span>
            {check.count !== undefined ? (
              <span className={cn("text-xs font-semibold", check.count === 0 ? "text-success" : "text-warning")}>
                {check.count} issues
              </span>
            ) : (
              <span className={cn("text-xs font-semibold", (check.failed ?? 0) === 0 ? "text-success" : "text-destructive")}>
                {(check.failed ?? 0) === 0 ? "PASS" : "FAIL"}
                {" "}({check.passed ?? 0} passed, {check.failed ?? 0} failed)
              </span>
            )}
          </div>
          {check.details && check.details.length > 0 && (
            <details className="mt-2">
              <summary className="text-xs text-muted-foreground cursor-pointer">
                Details ({check.details.length})
              </summary>
              <div className="mt-1 space-y-1 max-h-40 overflow-auto">
                {check.details.slice(0, 10).map((d, i) => (
                  <div key={i} className="text-[11px] font-mono text-muted-foreground p-1 border-b border-border">
                    {JSON.stringify(d)}
                  </div>
                ))}
                {check.details.length > 10 && (
                  <p className="text-[11px] text-muted-foreground">... and {check.details.length - 10} more</p>
                )}
              </div>
            </details>
          )}
        </div>
      ))}
    </div>
  );
}
