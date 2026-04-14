// frontend/src/hooks/use-websocket.ts
import { useEffect, useRef, useState, useCallback } from "react";

export type WsStatus = "connecting" | "connected" | "reconnecting" | "idle";

export interface WsMessage {
  type?: string;
  device?: Record<string, unknown>;
  alerts?: Array<Record<string, unknown>>;
  packet?: Record<string, unknown>;
  matches?: Array<Record<string, unknown>>;
  finding?: {
    hw_addr: string;
    rule: string;
    severity: string;
    message: string;
    timestamp: string | null;
  };
  // Import progress
  filename?: string;
  processed?: number;
  total?: number;
  done?: boolean;
  errors?: number;
}

type WsHandler = (msg: WsMessage) => void;

/**
 * Lazy, throttled WebSocket hook.
 *
 * - Only connects when at least one subscriber exists
 * - Batches device updates, flushes max 1/sec
 * - Alerts flush immediately (they're rare)
 * - Single clean connection with reconnect
 */
export function useWebSocket(path = "/ws") {
  const [status, setStatus] = useState<WsStatus>("idle");
  const handlersRef = useRef<Set<WsHandler>>(new Set());
  const wsRef = useRef<WebSocket | null>(null);
  const retryTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const flushTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const batchDevice = useRef<Record<string, unknown> | null>(null);
  const mountedRef = useRef(true);
  const retryCount = useRef(0);
  const pathRef = useRef(path);
  pathRef.current = path;

  const dispatch = useCallback((msg: WsMessage) => {
    handlersRef.current.forEach((h) => {
      try { h(msg); } catch (e) { console.error("WS handler error:", e); }
    });
  }, []);

  const connectWs = useCallback(() => {
    if (wsRef.current) return; // already connected
    if (!mountedRef.current) return;

    setStatus("connecting");
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const token = localStorage.getItem("leetha_token");
    const wsUrl = `${proto}//${location.host}${pathRef.current}`;
    const ws = token
      ? new WebSocket(wsUrl, [`auth.${token}`, "leetha-v1"])
      : new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      retryCount.current = 0;  // reset backoff on successful connection
      if (mountedRef.current) setStatus("connected");
    };

    ws.onclose = (event) => {
      wsRef.current = null;
      if (!mountedRef.current) return;
      // Don't reconnect on auth rejection — token is invalid
      if (event.code === 1008) {
        setStatus("idle");
        return;
      }
      // Only reconnect if there are subscribers
      if (handlersRef.current.size > 0) {
        setStatus("reconnecting");
        // Exponential backoff with jitter (3s → 6s → 12s → max 30s)
        const base = Math.min(3000 * Math.pow(2, retryCount.current), 30000);
        const jitter = Math.random() * 1000;
        retryCount.current += 1;
        retryTimer.current = setTimeout(connectWs, base + jitter);
      } else {
        setStatus("idle");
      }
    };

    ws.onerror = () => { /* onclose handles it */ };

    ws.onmessage = (event) => {
      if (!mountedRef.current) return;
      let data: WsMessage;
      try { data = JSON.parse(event.data); } catch { return; }

      // Alerts — dispatch immediately
      if (data.alerts && data.alerts.length > 0) {
        dispatch({ alerts: data.alerts });
      }

      // Findings — dispatch immediately
      if (data.type === "finding_created" && data.finding) {
        dispatch(data);
      }

      // Device — batch, flush max 1/sec
      if (data.device) {
        batchDevice.current = data.device;
        if (!flushTimer.current) {
          flushTimer.current = setTimeout(() => {
            flushTimer.current = null;
            const dev = batchDevice.current;
            batchDevice.current = null;
            if (dev && mountedRef.current) {
              dispatch({ device: dev });
            }
          }, 1000);
        }
      }
    };
  }, [dispatch]);

  const disconnectWs = useCallback(() => {
    if (retryTimer.current) { clearTimeout(retryTimer.current); retryTimer.current = null; }
    if (flushTimer.current) { clearTimeout(flushTimer.current); flushTimer.current = null; }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setStatus("idle");
  }, []);

  // Cleanup on unmount
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      disconnectWs();
    };
  }, [disconnectWs]);

  const subscribe = useCallback((handler: WsHandler) => {
    handlersRef.current.add(handler);
    // Connect on first subscriber
    if (handlersRef.current.size === 1 && !wsRef.current) {
      connectWs();
    }
    return () => {
      handlersRef.current.delete(handler);
      // Disconnect when last subscriber leaves
      if (handlersRef.current.size === 0) {
        disconnectWs();
      }
    };
  }, [connectWs, disconnectWs]);

  return { status, subscribe };
}
