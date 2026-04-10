// frontend/src/pages/Devices.tsx
import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { fetchDevices, fetchFilterOptions, type Device } from "@/lib/api";
import { DeviceDrawer } from "@/components/shared/DeviceDrawer";
import { getDeviceTypeColor } from "@/lib/constants";
import { cn } from "@/lib/utils";
import {
  ArrowUp,
  ArrowDown,
  Search,
  Download,
  Monitor,
  ChevronRight,
  ChevronLeft,
  X,
} from "lucide-react";
import type { WsStatus, WsMessage } from "@/hooks/use-websocket";

const STATUS_FILTERS = ["all", "new", "known", "suspicious"] as const;
const STATUS_LABELS: Record<string, string> = {
  all: "All",
  new: "Unseen",
  known: "Recognized",
  suspicious: "Flagged",
};
const PAGE_SIZES = [25, 50, 100] as const;
const CONFIDENCE_OPTIONS = [
  { label: "Any", value: "" },
  { label: "50+", value: "50" },
  { label: "80+", value: "80" },
  { label: "95+", value: "95" },
] as const;

interface DevicesProps {
  wsStatus: WsStatus;
  subscribe: (handler: (msg: WsMessage) => void) => () => void;
}

function formatDateTime(ts: string | null): string {
  if (!ts) return "--";
  try {
    const d = new Date(ts);
    return d.toLocaleString(undefined, {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return ts;
  }
}

// Build pagination range with ellipsis
function getPaginationRange(
  current: number,
  total: number
): (number | "...")[] {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  const pages: (number | "...")[] = [];
  pages.push(1);
  if (current > 3) pages.push("...");
  const start = Math.max(2, current - 1);
  const end = Math.min(total - 1, current + 1);
  for (let i = start; i <= end; i++) pages.push(i);
  if (current < total - 2) pages.push("...");
  pages.push(total);
  return pages;
}

export default function Devices({ subscribe }: DevicesProps) {
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const [drawerMac, setDrawerMac] = useState<string | null>(null);
  const [searchInput, setSearchInput] = useState(searchParams.get("q") ?? "");
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // --- Read URL state ---
  const page = Number(searchParams.get("page")) || 1;
  const perPage =
    (Number(searchParams.get("per_page")) as 25 | 50 | 100) || 50;
  const sort = searchParams.get("sort") ?? "ip_v4";
  const order = searchParams.get("order") ?? "asc";
  const q = searchParams.get("q") ?? "";
  const deviceType = searchParams.get("device_type") ?? "";
  const osFamily = searchParams.get("os_family") ?? "";
  const manufacturer = searchParams.get("manufacturer") ?? "";
  const statusFilter = searchParams.get("status") ?? "all";
  const confidenceMin = searchParams.get("confidence_min") ?? "";

  // Helper to update URL params
  const setParam = useCallback(
    (updates: Record<string, string>) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        for (const [k, v] of Object.entries(updates)) {
          if (v === "" || v === "all") {
            next.delete(k);
          } else {
            next.set(k, v);
          }
        }
        return next;
      });
    },
    [setSearchParams]
  );

  // Debounced search
  const handleSearchChange = useCallback(
    (value: string) => {
      setSearchInput(value);
      if (debounceRef.current) clearTimeout(debounceRef.current);
      debounceRef.current = setTimeout(() => {
        setParam({ q: value, page: "1" });
      }, 300);
    },
    [setParam]
  );

  // Clear all filters
  const clearFilters = useCallback(() => {
    setSearchInput("");
    setSearchParams(new URLSearchParams());
  }, [setSearchParams]);

  // Has any active filter?
  const hasFilters =
    q || deviceType || osFamily || manufacturer || statusFilter !== "all" || confidenceMin;

  // --- Fetch filter options ---
  const { data: filterOpts } = useQuery({
    queryKey: ["filter-options"],
    queryFn: fetchFilterOptions,
    staleTime: 60000,
  });

  // --- Fetch devices (server-side) ---
  const queryParams = useMemo(
    () => ({
      page,
      per_page: perPage,
      sort,
      order,
      raw: true as const,
      ...(q ? { q } : {}),
      ...(deviceType ? { device_type: deviceType } : {}),
      ...(osFamily ? { os_family: osFamily } : {}),
      ...(manufacturer ? { manufacturer } : {}),
      ...(statusFilter !== "all" ? { alert_status: statusFilter } : {}),
      ...(confidenceMin ? { confidence_min: Number(confidenceMin) } : {}),
    }),
    [page, perPage, sort, order, q, deviceType, osFamily, manufacturer, statusFilter, confidenceMin]
  );

  const { data: deviceData, isFetching, isError, error } = useQuery({
    queryKey: ["devices", queryParams],
    queryFn: () => fetchDevices(queryParams),
    placeholderData: (prev) => prev,
    refetchInterval: 60000,  // Refresh every 60s — status indicators use last_seen timestamps
    staleTime: 30000,
  });

  const devices = deviceData?.devices ?? [];
  const total = deviceData?.total ?? 0;
  const totalPages = deviceData?.pages ?? 1;

  // --- WebSocket: throttled invalidation ---
  const lastInvalidate = useRef(0);
  const invalidateTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return subscribe((msg) => {
      if (msg.device) {
        const now = Date.now();
        if (now - lastInvalidate.current > 10000) {
          lastInvalidate.current = now;
          queryClient.invalidateQueries({ queryKey: ["devices"] });
        } else if (!invalidateTimer.current) {
          invalidateTimer.current = setTimeout(() => {
            invalidateTimer.current = null;
            lastInvalidate.current = Date.now();
            queryClient.invalidateQueries({ queryKey: ["devices"] });
          }, 10000);
        }
      }
    });
  }, [subscribe, queryClient]);

  // Sorting handler
  const handleSort = useCallback(
    (col: string) => {
      if (sort === col) {
        setParam({ order: order === "asc" ? "desc" : "asc", page: "1" });
      } else {
        setParam({ sort: col, order: "desc", page: "1" });
      }
    },
    [sort, order, setParam]
  );

  // Column sort icon
  function SortIcon({ col }: { col: string }) {
    if (sort !== col)
      return <ArrowUp size={11} className="text-muted-foreground/30" />;
    if (order === "asc")
      return <ArrowUp size={11} className="text-primary" />;
    return <ArrowDown size={11} className="text-primary" />;
  }

  const showStart = total === 0 ? 0 : (page - 1) * perPage + 1;
  const showEnd = Math.min(page * perPage, total);

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <Monitor size={18} className="text-primary" />
            <h2 className="text-lg font-semibold">Devices</h2>
          </div>
          <span className="text-sm text-muted-foreground">
            <span className="font-semibold text-foreground">
              {total.toLocaleString()}
            </span>{" "}
            total
          </span>
          {isFetching && (
            <span className="text-[11px] text-muted-foreground animate-pulse">
              Loading...
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Select
            value={String(perPage)}
            onValueChange={(v) => setParam({ per_page: v, page: "1" })}
          >
            <SelectTrigger size="sm" className="w-20 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PAGE_SIZES.map((s) => (
                <SelectItem key={s} value={String(s)}>
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="outline" size="sm" className="text-xs gap-1.5" asChild>
            <a href="/api/devices/export?format=csv">
              <Download size={13} /> Download CSV
            </a>
          </Button>
          <Button variant="outline" size="sm" className="text-xs gap-1.5" asChild>
            <a href="/api/devices/export?format=json">
              <Download size={13} /> Download JSON
            </a>
          </Button>
        </div>
      </div>

      {/* Filter bar */}
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          {/* Search */}
          <div className="relative flex-1 min-w-[200px] max-w-md">
            <Search
              size={15}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground"
            />
            <Input
              placeholder="Search address, IP, hostname, vendor..."
              value={searchInput}
              onChange={(e) => handleSearchChange(e.target.value)}
              className="pl-9 bg-card border-border h-9"
            />
          </div>

          {/* Device type */}
          <Select
            value={deviceType || "__all__"}
            onValueChange={(v) =>
              setParam({ device_type: v === "__all__" ? "" : v, page: "1" })
            }
          >
            <SelectTrigger size="sm" className="w-36 text-xs">
              <SelectValue placeholder="Host Category" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="__all__">All Categories</SelectItem>
              {(filterOpts?.device_types ?? []).map((t) => (
                <SelectItem key={t} value={t}>
                  {t.replace(/_/g, " ")}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          {/* OS family */}
          <Select
            value={osFamily || "__all__"}
            onValueChange={(v) =>
              setParam({ os_family: v === "__all__" ? "" : v, page: "1" })
            }
          >
            <SelectTrigger size="sm" className="w-36 text-xs">
              <SelectValue placeholder="Platform" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="__all__">All Platforms</SelectItem>
              {(filterOpts?.os_families ?? []).map((o) => (
                <SelectItem key={o} value={o}>
                  {o}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          {/* Manufacturer */}
          <Select
            value={manufacturer || "__all__"}
            onValueChange={(v) =>
              setParam({
                manufacturer: v === "__all__" ? "" : v,
                page: "1",
              })
            }
          >
            <SelectTrigger size="sm" className="w-40 text-xs">
              <SelectValue placeholder="Vendor" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="__all__">All Vendors</SelectItem>
              {(filterOpts?.manufacturers ?? []).map((m) => (
                <SelectItem key={m} value={m}>
                  {m}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          {/* Confidence */}
          <Select
            value={confidenceMin || "__any__"}
            onValueChange={(v) =>
              setParam({ confidence_min: v === "__any__" ? "" : v, page: "1" })
            }
          >
            <SelectTrigger size="sm" className="w-28 text-xs">
              <SelectValue placeholder="Certainty" />
            </SelectTrigger>
            <SelectContent>
              {CONFIDENCE_OPTIONS.map((o) => (
                <SelectItem key={o.value || "any"} value={o.value || "__any__"}>
                  {o.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          {/* Clear */}
          {hasFilters && (
            <Button
              variant="ghost"
              size="sm"
              className="text-xs gap-1 text-muted-foreground"
              onClick={clearFilters}
            >
              <X size={12} /> Clear
            </Button>
          )}
        </div>

        {/* Status filter buttons */}
        <div className="flex gap-1.5">
          {STATUS_FILTERS.map((f) => (
            <button
              key={f}
              onClick={() => setParam({ status: f, page: "1" })}
              className={cn(
                "text-xs font-medium px-3 py-1.5 rounded-lg border transition-colors",
                statusFilter === f || (f === "all" && !statusFilter)
                  ? "bg-primary text-primary-foreground border-primary"
                  : "bg-card text-muted-foreground border-border hover:text-foreground hover:border-foreground/20"
              )}
            >
              {STATUS_LABELS[f] ?? f}
            </button>
          ))}
        </div>
      </div>

      {/* Error banner */}
      {isError && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          Failed to load devices{error instanceof Error ? `: ${error.message}` : ""}. Retrying...
        </div>
      )}

      {/* Table */}
      <div className="rounded-xl border border-border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="bg-card border-b border-border">
                {[
                  { key: "mac", label: "Hardware Address" },
                  { key: "ip_v4", label: "Network Address" },
                  { key: "manufacturer", label: "Vendor" },
                  { key: "device_type", label: "Category" },
                  { key: "os_family", label: "Platform" },
                  { key: "hostname", label: "Hostname" },
                  { key: "confidence", label: "Certainty" },
                  { key: "alert_status", label: "Disposition" },
                  { key: "first_seen", label: "Discovered" },
                  { key: "last_seen", label: "Last Active" },
                ].map((col) => (
                  <th
                    key={col.key}
                    className="px-4 py-3 text-left text-[11px] text-muted-foreground uppercase tracking-wider font-semibold whitespace-nowrap"
                  >
                    <button
                      className="flex items-center gap-1.5 group"
                      onClick={() => handleSort(col.key)}
                    >
                      {col.label} <SortIcon col={col.key} />
                    </button>
                  </th>
                ))}
                <th className="w-8" />
              </tr>
            </thead>
            <tbody>
              {devices.length > 0 ? (
                devices.map((d: Device, i: number) => {
                  const mac = d.primary_mac || d.mac;
                  const conf = d.confidence;
                  const confClr = conf >= 80 ? "#10b981" : conf >= 50 ? "#f59e0b" : conf >= 25 ? "#f97316" : "#ef4444";
                  const confLabel = conf >= 80 ? "High" : conf >= 50 ? "Medium" : conf >= 25 ? "Low" : "Very Low";

                  // Live status based on last_seen time + alert_status
                  const lastSeenMs = d.last_seen ? Date.now() - new Date(d.last_seen).getTime() : Infinity;
                  const firstSeenMs = d.first_seen ? Date.now() - new Date(d.first_seen).getTime() : Infinity;
                  const baseStatus = d.alert_status ?? "new";

                  let liveStatus: { label: string; dotClass: string; textClass: string; };
                  if (baseStatus === "suspicious") {
                    liveStatus = { label: "Flagged", dotClass: "bg-red-500 animate-pulse", textClass: "text-red-400" };
                  } else if (baseStatus === "self") {
                    liveStatus = { label: "Self", dotClass: "bg-cyan-400", textClass: "text-cyan-400" };
                  } else if (firstSeenMs < 3600000) {
                    liveStatus = { label: "New", dotClass: "bg-blue-400 animate-pulse", textClass: "text-blue-400" };
                  } else if (lastSeenMs < 300000) {
                    liveStatus = { label: "Online", dotClass: "bg-green-500", textClass: "text-green-400" };
                  } else if (lastSeenMs < 1800000) {
                    liveStatus = { label: "Idle", dotClass: "bg-yellow-500", textClass: "text-yellow-400" };
                  } else {
                    liveStatus = { label: "Offline", dotClass: "bg-gray-500", textClass: "text-muted-foreground" };
                  }
                  return (
                    <tr
                      key={mac}
                      onClick={() => setDrawerMac(mac)}
                      className={cn(
                        "cursor-pointer transition-colors group",
                        i % 2 === 0 ? "bg-background" : "bg-card/50",
                        "hover:bg-primary/[0.04]"
                      )}
                    >
                      <td className="px-4 py-3.5 text-sm whitespace-nowrap border-b border-border/50">
                        <div className="flex items-center gap-2">
                          <span className="font-data text-[13px] text-foreground">
                            {/* Only show MAC addresses, not IPv6 */}
                            {mac.includes(":") && mac.split(":").length === 6 ? mac : d.mac}
                          </span>
                          {d.is_randomized_mac && (
                            <span className="text-[9px] font-bold px-1 py-0 rounded bg-purple-500/15 text-purple-400">
                              R
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3.5 text-sm border-b border-border/50">
                        <div className="font-data text-[13px] space-y-0.5">
                          {d.ip_v4 ? (
                            <div>{d.ip_v4}</div>
                          ) : null}
                          {d.ip_v6 ? (
                            <div className="text-[11px] text-muted-foreground truncate max-w-[200px]" title={d.ip_v6}>{d.ip_v6}</div>
                          ) : null}
                          {!d.ip_v4 && !d.ip_v6 && (
                            <span className="text-muted-foreground/40">--</span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3.5 text-sm whitespace-nowrap border-b border-border/50">
                        <span
                          className={
                            d.manufacturer
                              ? "text-foreground"
                              : "text-muted-foreground/40 italic"
                          }
                        >
                          {d.manufacturer || "Unknown"}
                        </span>
                      </td>
                      <td className="px-4 py-3.5 text-sm whitespace-nowrap border-b border-border/50">
                        <div className="flex items-center gap-2">
                          <span
                            className="w-2.5 h-2.5 rounded-full shrink-0 ring-2 ring-background"
                            style={{
                              background: getDeviceTypeColor(d.device_type),
                            }}
                          />
                          <span>
                            {d.device_type ?? (
                              <span className="text-muted-foreground/40">
                                unknown
                              </span>
                            )}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3.5 text-sm whitespace-nowrap border-b border-border/50">
                        {d.os_family || (
                          <span className="text-muted-foreground/40">--</span>
                        )}
                      </td>
                      <td className="px-4 py-3.5 text-sm whitespace-nowrap border-b border-border/50">
                        <span
                          className={
                            d.hostname
                              ? "text-cyan-400"
                              : "text-muted-foreground/40"
                          }
                        >
                          {d.hostname || "--"}
                        </span>
                      </td>
                      <td className="px-4 py-3.5 text-sm whitespace-nowrap border-b border-border/50">
                        <div className="flex items-center gap-2 min-w-[110px]">
                          <div className="flex flex-col items-end gap-0.5">
                            <span className="text-[13px] font-bold tabular-nums" style={{ color: confClr }}>{conf}%</span>
                            <span className="text-[9px] uppercase tracking-wide font-semibold" style={{ color: confClr }}>{confLabel}</span>
                          </div>
                          <div className="flex-1 min-w-[50px] max-w-[70px]">
                            <div className="h-2 bg-muted/40 rounded-full overflow-hidden">
                              <div className="h-full rounded-full transition-all" style={{ width: `${conf}%`, background: confClr }} />
                            </div>
                            {/* Source count indicator */}
                            <div className="flex gap-px mt-1">
                              {[20, 40, 60, 80, 100].map((threshold) => (
                                <div key={threshold} className="flex-1 h-0.5 rounded-full" style={{ background: conf >= threshold ? confClr : "hsl(var(--muted))" }} />
                              ))}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3.5 text-sm whitespace-nowrap border-b border-border/50">
                        <div className="flex items-center gap-2">
                          <span className={cn("w-2 h-2 rounded-full shrink-0", liveStatus.dotClass)} />
                          <span className={cn("text-[11px] font-semibold", liveStatus.textClass)}>{liveStatus.label}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3.5 text-sm whitespace-nowrap border-b border-border/50">
                        <span className="text-[12px] text-muted-foreground font-data">
                          {formatDateTime(d.first_seen)}
                        </span>
                      </td>
                      <td className="px-4 py-3.5 text-sm whitespace-nowrap border-b border-border/50">
                        <span className="text-[12px] text-muted-foreground font-data">
                          {formatDateTime(d.last_seen)}
                        </span>
                      </td>
                      <td className="px-2 py-3.5 border-b border-border/50">
                        <ChevronRight
                          size={14}
                          className="text-muted-foreground/30 group-hover:text-muted-foreground transition-colors"
                        />
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td
                    colSpan={11}
                    className="px-4 py-16 text-center text-muted-foreground"
                  >
                    <Monitor size={32} className="mx-auto mb-3 opacity-20" />
                    <p className="text-sm font-medium">
                      {hasFilters
                        ? "No hosts match current criteria"
                        : "No hosts identified yet"}
                    </p>
                    {!hasFilters && (
                      <p className="text-xs mt-1">
                        Make sure packet capture is running.
                      </p>
                    )}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination footer */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between flex-wrap gap-3">
          <span className="text-sm text-muted-foreground">
            Showing{" "}
            <span className="font-semibold text-foreground">
              {showStart.toLocaleString()}-{showEnd.toLocaleString()}
            </span>{" "}
            of{" "}
            <span className="font-semibold text-foreground">
              {total.toLocaleString()}
            </span>{" "}
            hosts
          </span>

          <div className="flex items-center gap-1">
            <Button
              variant="outline"
              size="sm"
              disabled={page <= 1}
              onClick={() => setParam({ page: String(page - 1) })}
              className="text-xs gap-1"
            >
              <ChevronLeft size={14} /> Previous
            </Button>

            {getPaginationRange(page, totalPages).map((p, idx) =>
              p === "..." ? (
                <span
                  key={`ellipsis-${idx}`}
                  className="px-2 text-muted-foreground text-sm"
                >
                  ...
                </span>
              ) : (
                <Button
                  key={p}
                  variant={p === page ? "default" : "outline"}
                  size="sm"
                  className="text-xs min-w-[32px]"
                  onClick={() => setParam({ page: String(p) })}
                >
                  {p.toLocaleString()}
                </Button>
              )
            )}

            <Button
              variant="outline"
              size="sm"
              disabled={page >= totalPages}
              onClick={() => setParam({ page: String(page + 1) })}
              className="text-xs gap-1"
            >
              Next <ChevronRight size={14} />
            </Button>
          </div>

          <Select
            value={String(perPage)}
            onValueChange={(v) => setParam({ per_page: v, page: "1" })}
          >
            <SelectTrigger size="sm" className="w-20 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PAGE_SIZES.map((s) => (
                <SelectItem key={s} value={String(s)}>
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}

      <DeviceDrawer
        mac={drawerMac}
        open={!!drawerMac}
        onClose={() => setDrawerMac(null)}
      />
    </div>
  );
}
