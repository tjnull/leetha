// frontend/src/components/layout/Sidebar.tsx
import { useState, useEffect } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { useTheme } from "@/providers/theme-provider";
import { useQuery } from "@tanstack/react-query";
import { fetchStats } from "@/lib/api";
import { isAdmin, isAuthenticated, clearAuth } from "@/lib/auth";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { Moon, Sun, LogOut } from "lucide-react";
import {
  IconDashboard, IconNetworkThreats, IconDevices, IconAttackPaths,
  IconTopology, IconConsole, IconSources, IconPatterns, IconInterfaces,
  IconSettings, IconDocumentation,
} from "./SidebarIcons";
import type { WsStatus } from "@/hooks/use-websocket";

// --- Animated Network Pulse Logo ---

function NetworkPulseLogo({ size = 32, className }: { size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 40 40"
      fill="none"
      className={className}
    >
      <circle cx="20" cy="20" r="18" stroke="currentColor" strokeWidth="0.5" opacity="0.15">
        <animate attributeName="r" values="14;18;14" dur="3s" repeatCount="indefinite" />
        <animate attributeName="opacity" values="0.3;0.05;0.3" dur="3s" repeatCount="indefinite" />
      </circle>
      <circle cx="20" cy="20" r="14" stroke="currentColor" strokeWidth="0.5" opacity="0.2">
        <animate attributeName="r" values="11;15;11" dur="3s" repeatCount="indefinite" begin="0.5s" />
        <animate attributeName="opacity" values="0.4;0.1;0.4" dur="3s" repeatCount="indefinite" begin="0.5s" />
      </circle>
      <line x1="20" y1="20" x2="20" y2="7" stroke="currentColor" strokeWidth="1" opacity="0.3">
        <animate attributeName="opacity" values="0.15;0.5;0.15" dur="2s" repeatCount="indefinite" />
      </line>
      <line x1="20" y1="20" x2="31" y2="12" stroke="currentColor" strokeWidth="1" opacity="0.3">
        <animate attributeName="opacity" values="0.15;0.5;0.15" dur="2s" repeatCount="indefinite" begin="0.3s" />
      </line>
      <line x1="20" y1="20" x2="33" y2="24" stroke="currentColor" strokeWidth="1" opacity="0.3">
        <animate attributeName="opacity" values="0.15;0.5;0.15" dur="2s" repeatCount="indefinite" begin="0.6s" />
      </line>
      <line x1="20" y1="20" x2="26" y2="33" stroke="currentColor" strokeWidth="1" opacity="0.3">
        <animate attributeName="opacity" values="0.15;0.5;0.15" dur="2s" repeatCount="indefinite" begin="0.9s" />
      </line>
      <line x1="20" y1="20" x2="10" y2="31" stroke="currentColor" strokeWidth="1" opacity="0.3">
        <animate attributeName="opacity" values="0.15;0.5;0.15" dur="2s" repeatCount="indefinite" begin="1.2s" />
      </line>
      <line x1="20" y1="20" x2="7" y2="17" stroke="currentColor" strokeWidth="1" opacity="0.3">
        <animate attributeName="opacity" values="0.15;0.5;0.15" dur="2s" repeatCount="indefinite" begin="1.5s" />
      </line>
      <circle cx="20" cy="7" r="2" fill="currentColor" opacity="0.6">
        <animate attributeName="opacity" values="0.3;0.8;0.3" dur="2s" repeatCount="indefinite" />
      </circle>
      <circle cx="31" cy="12" r="1.5" fill="currentColor" opacity="0.5">
        <animate attributeName="opacity" values="0.3;0.7;0.3" dur="2s" repeatCount="indefinite" begin="0.3s" />
      </circle>
      <circle cx="33" cy="24" r="1.5" fill="currentColor" opacity="0.5">
        <animate attributeName="opacity" values="0.3;0.7;0.3" dur="2s" repeatCount="indefinite" begin="0.6s" />
      </circle>
      <circle cx="26" cy="33" r="2" fill="currentColor" opacity="0.6">
        <animate attributeName="opacity" values="0.3;0.8;0.3" dur="2s" repeatCount="indefinite" begin="0.9s" />
      </circle>
      <circle cx="10" cy="31" r="1.5" fill="currentColor" opacity="0.5">
        <animate attributeName="opacity" values="0.3;0.7;0.3" dur="2s" repeatCount="indefinite" begin="1.2s" />
      </circle>
      <circle cx="7" cy="17" r="1.5" fill="currentColor" opacity="0.5">
        <animate attributeName="opacity" values="0.3;0.7;0.3" dur="2s" repeatCount="indefinite" begin="1.5s" />
      </circle>
      <circle cx="20" cy="20" r="4" fill="currentColor" opacity="0.9">
        <animate attributeName="r" values="3.5;4.5;3.5" dur="2s" repeatCount="indefinite" />
      </circle>
      <circle cx="20" cy="20" r="2" fill="hsl(0 0% 0%)" />
      <circle cx="20" cy="20" r="1.5" fill="currentColor" opacity="1" />
    </svg>
  );
}

// --- Custom icon map ---

const ICONS: Record<string, React.ElementType> = {
  IconDashboard, IconNetworkThreats, IconDevices, IconAttackPaths,
  IconTopology, IconConsole, IconSources, IconPatterns, IconInterfaces,
  IconSettings, IconDocumentation,
};

const STORAGE_KEY = "leetha-sidebar-collapsed";

interface SidebarProps {
  wsStatus: WsStatus;
}

export function Sidebar({ wsStatus }: SidebarProps) {
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem(STORAGE_KEY) === "1"
  );
  const { theme, toggleTheme } = useTheme();
  const location = useLocation();

  const { data: stats } = useQuery({
    queryKey: ["stats"],
    queryFn: fetchStats,
    refetchInterval: 30000,
    staleTime: 15000,
  });

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, collapsed ? "1" : "0");
  }, [collapsed]);

  const deviceCount = stats?.device_count ?? 0;
  const alertCount = stats?.alert_count ?? 0;
  const capturingCount = stats?.capturing_count ?? 0;

  const navSections: Array<{
    label: string;
    items: Array<{ path: string; label: string; icon: string; badge?: number; badgeDanger?: boolean }>;
  }> = [
    {
      label: "",
      items: [
        { path: "/", label: "Overview", icon: "IconDashboard" },
      ],
    },
    {
      label: "Recon",
      items: [
        { path: "/inventory", label: "Inventory", icon: "IconDevices", badge: deviceCount },
        { path: "/detections", label: "Detections", icon: "IconNetworkThreats", badge: alertCount, badgeDanger: true },
        { path: "/exposure", label: "Exposure", icon: "IconAttackPaths" },
        { path: "/topology", label: "Topology", icon: "IconTopology" },
        { path: "/stream", label: "Stream", icon: "IconConsole" },
      ],
    },
    {
      label: "Intel",
      items: [
        { path: "/feeds", label: "Sources", icon: "IconSources" },
        { path: "/rules", label: "Rules", icon: "IconPatterns" },
      ],
    },
    {
      label: "System",
      items: [
        { path: "/adapters", label: "Adapters", icon: "IconInterfaces" },
        { path: "/settings", label: "Settings", icon: "IconSettings" },
        { path: "/docs", label: "Docs", icon: "IconDocumentation" },
      ],
    },
  ];

  return (
    <aside
      className={cn(
        "flex flex-col bg-sidebar text-sidebar-foreground transition-all duration-300",
        collapsed ? "w-14" : "w-48"
      )}
    >
      {/* Brand */}
      <div className="flex items-center gap-2.5 px-2.5 h-12">
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="shrink-0 p-0.5 rounded-lg hover:bg-accent/50 transition-all duration-200 group"
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          aria-label="Toggle sidebar"
        >
          <NetworkPulseLogo
            size={collapsed ? 28 : 26}
            className="text-primary transition-transform duration-300 group-hover:scale-110"
          />
        </button>
        {!collapsed && (
          <div className="flex flex-col leading-none min-w-0">
            <span className="font-bold text-xs tracking-[0.2em]">LEETHA</span>
            <span className="text-[8px] text-muted-foreground/50 tracking-wide">Mapping the Unseen</span>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-1">
        {navSections.map((section, si) => (
          <div key={section.label || si} className="mb-0.5">
            {!collapsed && section.label && (
              <div className="px-3 pt-3 pb-1 text-[8px] font-bold uppercase tracking-[0.2em] text-muted-foreground/40">
                {section.label}
              </div>
            )}
            {collapsed && si > 0 && (
              <div className="mx-2.5 my-1 border-t border-border/30" />
            )}
            {section.items.filter((item) => item.path !== "/settings" || isAdmin()).map((item) => {
              const Icon = ICONS[item.icon];
              const isActive =
                item.path === "/"
                  ? location.pathname === "/"
                  : location.pathname.startsWith(item.path);
              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  className={cn(
                    "group relative flex items-center gap-2.5 mx-1.5 px-2.5 py-1.5 rounded-md text-[13px] transition-all duration-150",
                    isActive
                      ? "bg-primary/10 text-primary font-medium"
                      : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
                  )}
                  title={item.label}
                >
                  {Icon && (
                    <Icon
                      size={16}
                      className={cn(
                        "shrink-0 transition-all duration-300",
                        isActive && "text-primary"
                      )}
                    />
                  )}
                  {!collapsed && (
                    <>
                      <span className="flex-1 truncate">{item.label}</span>
                      {item.badge !== undefined && item.badge > 0 && (
                        <Badge
                          variant={item.badgeDanger ? "destructive" : "secondary"}
                          className="text-[9px] px-1.5 py-0 min-w-[18px] justify-center h-4"
                        >
                          {item.badge > 999 ? `${Math.floor(item.badge / 1000)}k` : item.badge}
                        </Badge>
                      )}
                    </>
                  )}
                  {collapsed && item.badge !== undefined && item.badge > 0 && (
                    <span className={cn(
                      "absolute right-1 top-1 w-1.5 h-1.5 rounded-full",
                      item.badgeDanger ? "bg-destructive" : "bg-primary"
                    )} />
                  )}
                </NavLink>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Footer — compact */}
      <div className="px-2.5 py-2 space-y-1.5">
        {/* Status + theme row */}
        <div className="flex items-center justify-between px-1">
          <div className="flex items-center gap-2.5">
            {/* Capture status */}
            <div className="flex items-center gap-1.5" title={capturingCount > 0 ? `${capturingCount} interface(s) capturing` : "No active capture"}>
              <span
                className={cn(
                  "w-1.5 h-1.5 rounded-full shrink-0",
                  capturingCount > 0 ? "bg-success animate-pulse" : "bg-muted-foreground/40"
                )}
              />
              {!collapsed && (
                <span className="text-[10px] text-muted-foreground/60">
                  {capturingCount > 0 ? `${capturingCount} active` : "Idle"}
                </span>
              )}
            </div>
            {/* WS live indicator */}
            {!collapsed && (
              <div className="flex items-center gap-1.5" title={`WebSocket: ${wsStatus}`}>
                <span
                  className={cn(
                    "w-1.5 h-1.5 rounded-full shrink-0",
                    wsStatus === "connected" ? "bg-primary" :
                    wsStatus === "connecting" || wsStatus === "reconnecting" ? "bg-warning animate-pulse" :
                    "bg-muted-foreground/40"
                  )}
                />
                <span className="text-[10px] text-muted-foreground/60">
                  {wsStatus === "connected" ? "Live" : wsStatus === "idle" ? "Off" : wsStatus === "connecting" ? "..." : "Retry"}
                </span>
              </div>
            )}
          </div>
          <button
            onClick={toggleTheme}
            className="p-1 rounded hover:bg-accent/50 transition-colors"
            title="Toggle theme"
          >
            {theme === "dark" ? <Moon size={13} className="text-muted-foreground/50" /> : <Sun size={13} className="text-muted-foreground/50" />}
          </button>
        </div>

        {/* Sign out */}
        {isAuthenticated() && !collapsed && (
          <button
            onClick={() => { clearAuth(); window.location.href = "/login"; }}
            className="flex items-center gap-1.5 px-1 text-[10px] text-muted-foreground/40 hover:text-muted-foreground transition-colors"
          >
            <LogOut size={11} />
            Sign out
          </button>
        )}

        {/* Version */}
        {!collapsed && (
          <span className="text-[9px] text-muted-foreground/30 tracking-wider">v1.0.0</span>
        )}
      </div>
    </aside>
  );
}
