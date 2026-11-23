// frontend/src/App.tsx
import { lazy, Suspense, useEffect, useState } from "react";
import { Routes, Route, Navigate, useLocation } from "react-router-dom";
import { checkAuthStatus } from "@/lib/api";
import { isAuthenticated } from "@/lib/auth";
import { useWebSocket } from "@/hooks/use-websocket";
import { Shell } from "@/components/layout/Shell";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { StartupGate } from "@/components/StartupGate";

// Lazy-load all pages — only the visited page's code is downloaded
const Dashboard = lazy(() => import("@/pages/Dashboard"));
const Devices = lazy(() => import("@/pages/Devices"));
const Interfaces = lazy(() => import("@/pages/Interfaces"));
const Patterns = lazy(() => import("@/pages/Patterns"));
const Sync = lazy(() => import("@/pages/Sync"));
const ThreatDetection = lazy(() => import("@/pages/ThreatDetection"));
const AttackSurface = lazy(() => import("@/pages/AttackSurface"));
const Topology = lazy(() => import("@/pages/Topology"));
const Console = lazy(() => import("@/pages/Console"));
const Info = lazy(() => import("@/pages/Info"));
const Settings = lazy(() => import("@/pages/Settings"));
const Login = lazy(() => import("@/pages/Login"));

function PageLoader() {
  return (
    <div className="flex items-center justify-center h-64 text-muted-foreground text-sm">
      Loading...
    </div>
  );
}

function AuthGuard({ children }: { children: React.ReactNode }) {
  const [authRequired, setAuthRequired] = useState<boolean | null>(null);
  const location = useLocation();

  useEffect(() => {
    checkAuthStatus()
      .then((s) => setAuthRequired(s.auth_enabled))
      .catch(() => setAuthRequired(false));
  }, []);

  if (authRequired === null) return <PageLoader />;
  if (authRequired && !isAuthenticated() && location.pathname !== "/login") {
    return <Navigate to="/login" replace />;
  }
  // Signing in must stay possible while the capture engine warms up, so the
  // login route bypasses the startup gate.
  return (
    <StartupGate bypass={location.pathname === "/login"}>{children}</StartupGate>
  );
}

export default function App() {
  const { status: wsStatus, subscribe } = useWebSocket("/ws");

  return (
    <Suspense fallback={<PageLoader />}>
      <AuthGuard>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<Shell title="Overview" wsStatus={wsStatus}><ErrorBoundary><Dashboard wsStatus={wsStatus} subscribe={subscribe} /></ErrorBoundary></Shell>} />
          <Route path="/inventory" element={<Shell title="Host Inventory" wsStatus={wsStatus}><ErrorBoundary><Devices wsStatus={wsStatus} subscribe={subscribe} /></ErrorBoundary></Shell>} />
          <Route path="/alerts" element={<Navigate to="/detections" replace />} />
          <Route path="/detections" element={<Shell title="Detections" wsStatus={wsStatus}><ErrorBoundary><ThreatDetection /></ErrorBoundary></Shell>} />
          <Route path="/exposure" element={<Shell title="Exposure Map" wsStatus={wsStatus}><ErrorBoundary><AttackSurface subscribe={subscribe} /></ErrorBoundary></Shell>} />
          <Route path="/topology" element={<Shell title="Network Map" wsStatus={wsStatus}><ErrorBoundary><Topology subscribe={subscribe} /></ErrorBoundary></Shell>} />
          <Route path="/stream" element={<Shell title="Packet Stream" wsStatus={wsStatus}><ErrorBoundary><Console /></ErrorBoundary></Shell>} />
          <Route path="/feeds" element={<Shell title="Data Feeds" wsStatus={wsStatus}><ErrorBoundary><Sync /></ErrorBoundary></Shell>} />
          <Route path="/rules" element={<Shell title="Detection Rules" wsStatus={wsStatus}><ErrorBoundary><Patterns /></ErrorBoundary></Shell>} />
          <Route path="/adapters" element={<Shell title="Adapters" wsStatus={wsStatus}><ErrorBoundary><Interfaces /></ErrorBoundary></Shell>} />
          <Route path="/settings" element={<Shell title="Settings" wsStatus={wsStatus}><ErrorBoundary><Settings /></ErrorBoundary></Shell>} />
          <Route path="/docs" element={<Navigate to="/docs/home" replace />} />
          <Route path="/docs/:slug" element={<Shell title="Knowledge Base" wsStatus={wsStatus}><ErrorBoundary><Info /></ErrorBoundary></Shell>} />
          {/* Legacy route redirects */}
          <Route path="/devices" element={<Navigate to="/inventory" replace />} />
          <Route path="/threats" element={<Navigate to="/detections" replace />} />
          <Route path="/threat-detection" element={<Navigate to="/detections" replace />} />
          <Route path="/attack-surface" element={<Navigate to="/exposure" replace />} />
          <Route path="/console" element={<Navigate to="/stream" replace />} />
          <Route path="/sync" element={<Navigate to="/feeds" replace />} />
          <Route path="/patterns" element={<Navigate to="/rules" replace />} />
          <Route path="/interfaces" element={<Navigate to="/adapters" replace />} />
          <Route path="/info" element={<Navigate to="/docs/home" replace />} />
          <Route path="/info/:slug" element={<Navigate to="/docs/home" replace />} />
        </Routes>
      </AuthGuard>
    </Suspense>
  );
}
