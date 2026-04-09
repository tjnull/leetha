import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { WsMessage } from "@/hooks/use-websocket";
import {
  ReactFlow,
  Controls,
  MiniMap,
  Background,
  useNodesState,
  useEdgesState,
  useReactFlow,
  ReactFlowProvider,
  type Node,
  type Edge,
  type NodeMouseHandler,
  type Connection,
  BackgroundVariant,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import ELK from "elkjs/lib/elk.bundled.js";
import { fetchTopology, createTopologyOverride, deleteTopologyOverride } from "@/lib/api";
import { toast } from "sonner";
import { TopologyNode } from "@/components/topology/TopologyNode";
import { DeviceDrawer } from "@/components/shared/DeviceDrawer";
import { DEVICE_TYPE_COLORS } from "@/lib/constants";
import { Loader2, Filter, ChevronDown, Maximize, X } from "lucide-react";
import { Button } from "@/components/ui/button";

const elk = new ELK();

const nodeTypes = { topology: TopologyNode };

async function computeElkLayout(
  nodes: Node[],
  edges: Edge[],
  containerWidth: number,
  containerHeight: number,
): Promise<Node[]> {
  // Target a balanced aspect ratio closer to the viewport
  const ratio = Math.max(containerWidth / Math.max(containerHeight, 1), 0.8);
  // Limit columns for client nodes to prevent ultra-wide single rows
  // Map tiers to partition indices for strict layer ordering
  const TIER_PARTITION: Record<string, number> = {
    internet: 0,
    gateway: 1,
    vlan: 2,
    infrastructure: 3,
    client: 4,
  };

  const elkGraph = {
    id: "root",
    layoutOptions: {
      "elk.algorithm": "layered",
      "elk.direction": "DOWN",
      "elk.spacing.nodeNode": "40",
      "elk.layered.spacing.baseValue": "70",
      "elk.spacing.edgeNode": "25",
      "elk.edgeRouting": "ORTHOGONAL",
      "elk.layered.mergeEdges": "true",
      "elk.layered.wrapping.strategy": "MULTI_EDGE",
      "elk.layered.wrapping.additionalEdgeSpacing": "15",
      "elk.layered.wrapping.correctionFactor": "1.5",
      "elk.aspectRatio": String(Math.min(ratio, 1.2)),
      "elk.layered.compaction.postCompaction.strategy": "EDGE_LENGTH",
      "elk.layered.nodePlacement.strategy": "NETWORK_SIMPLEX",
      "elk.partitioning.activate": "true",
    },
    children: nodes.map((n) => {
      const tier = n.data?.tier as string | undefined;
      const partition = TIER_PARTITION[tier ?? ""] ?? 4;
      const opts = { "elk.partitioning.partition": String(partition) };
      if (n.id === "internet") return { id: n.id, width: 160, height: 130, layoutOptions: opts };
      if (n.data.is_gateway) return { id: n.id, width: 200, height: 160, layoutOptions: opts };
      if (n.data.is_infrastructure) return { id: n.id, width: 185, height: 140, layoutOptions: opts };
      return { id: n.id, width: 170, height: 130, layoutOptions: opts };
    }),
    edges: edges.map((e, i) => ({
      id: `elk-${i}`,
      sources: [e.source],
      targets: [e.target],
    })),
  };

  try {
    const layout = await elk.layout(elkGraph);
    return nodes.map((node) => {
      const elkNode = layout.children?.find((n) => n.id === node.id);
      return {
        ...node,
        position: { x: elkNode?.x ?? 0, y: elkNode?.y ?? 0 },
      };
    });
  } catch {
    // Fallback: simple grid layout if ELK fails
    const cols = Math.max(Math.ceil(Math.sqrt(nodes.length)), 3);
    return nodes.map((node, i) => ({
      ...node,
      position: { x: (i % cols) * 200, y: Math.floor(i / cols) * 150 },
    }));
  }
}

interface TopologyInnerProps {
  subscribe: (handler: (msg: WsMessage) => void) => () => void;
}

function TopologyInner({ subscribe }: TopologyInnerProps) {
  const queryClient = useQueryClient();

  useEffect(() => {
    return subscribe((msg) => {
      if (msg.device) {
        queryClient.invalidateQueries({ queryKey: ["topology"] });
      }
    });
  }, [subscribe, queryClient]);

  const { data, isLoading } = useQuery({
    queryKey: ["topology"],
    queryFn: fetchTopology,
    refetchInterval: 15000,
  });

  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [drawerMac, setDrawerMac] = useState<string | null>(null);
  const [filterOpen, setFilterOpen] = useState(false);
  const filterRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const { fitView } = useReactFlow();

  // Filters
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set());
  const [hiddenSubnets, setHiddenSubnets] = useState<Set<string>>(new Set());

  // Context menu for manual edge deletion
  const [contextMenu, setContextMenu] = useState<{
    x: number; y: number; edgeId: string; childMac: string;
  } | null>(null);

  const activeFilterCount = hiddenTypes.size + hiddenSubnets.size;

  // Close filter dropdown when clicking outside
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (filterRef.current && !filterRef.current.contains(e.target as HTMLElement)) {
        setFilterOpen(false);
      }
    }
    if (filterOpen) document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [filterOpen]);

  const deviceTypes = useMemo(() => {
    if (!data) return [];
    const counts: Record<string, number> = {};
    for (const n of data.nodes) {
      const t = n.type || "unknown";
      counts[t] = (counts[t] || 0) + 1;
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [data]);

  const subnets = useMemo(() => data?.subnets ?? [], [data]);

  useEffect(() => {
    if (!data) return;

    const visibleNodes = data.nodes.filter((n) => {
      if (hiddenTypes.has(n.type || "unknown")) return false;
      if (n.subnet && hiddenSubnets.has(n.subnet)) return false;
      return true;
    });

    const visibleIds = new Set(visibleNodes.map((n) => n.id));

    const rfNodes: Node[] = visibleNodes.map((n) => {
      const tier = (n as any).tier as string | undefined;
      return {
        id: n.id,
        type: "topology",
        position: { x: 0, y: 0 },
        data: {
          type: n.type,
          hostname: n.hostname,
          ip: n.ip,
          manufacturer: n.manufacturer,
          confidence: n.confidence,
          is_gateway: n.is_gateway,
          is_infrastructure: n.is_infrastructure,
          is_online: (n as any).is_online,
          os_family: n.os_family,
          connection_type: (n as any).connection_type,
          is_self: (n as any).is_self,
          tier,
        },
      };
    });

    const rfEdges: Edge[] = data.edges
      .filter((e) => visibleIds.has(e.source) && visibleIds.has(e.target))
      .map((e, i) => {
        const t = e.type;
        let stroke = "#475569";
        let strokeWidth = 1;
        let strokeDasharray: string | undefined;
        let animated = false;

        if (t === "wan_link") {
          stroke = "#f97316"; strokeWidth = 3; animated = true;  // Orange — Internet to gateway
        } else if (t === "trunk_link") {
          stroke = "#3b82f6"; strokeWidth = 3; animated = true;  // Blue thick — core infra
        } else if (t === "vlan_link") {
          stroke = "#3b82f6"; strokeWidth = 2; animated = true;
        } else if (t === "infra_link") {
          stroke = "#3b82f6"; strokeWidth = 2; animated = true;
        } else if (t === "lldp") {
          stroke = "#22d3ee"; strokeWidth = 2; animated = true;  // Cyan — LLDP neighbor
        } else if (t === "wireless_link") {
          stroke = "#22d3ee"; strokeWidth = 1.5; strokeDasharray = "6 3"; animated = true;  // Cyan dashed — wireless
        } else if (t === "vm_link") {
          stroke = "#a855f7"; strokeWidth = 1.5; strokeDasharray = "4 3"; animated = true;  // Purple dashed — VM to host
        } else if (t === "client_link") {
          stroke = "#64748b"; strokeWidth = 1.5; strokeDasharray = "5 4";  // Gray dashed — wired client
        } else if (t === "member") {
          stroke = "#475569"; strokeWidth = 1; strokeDasharray = "4 4";
        } else if (t === "manual_link") {
          stroke = "#ffffff"; strokeWidth = 2.5; animated = true;
        }

        const isManual = t === "manual_link";
        return {
          id: `e-${i}`,
          source: e.source,
          target: e.target,
          type: "smoothstep",
          style: { stroke, strokeWidth, strokeDasharray },
          animated,
          ...(isManual ? {
            label: "📌",
            labelStyle: { fontSize: 12 },
            labelBgStyle: { fill: "transparent" },
          } : {}),
        };
      });

    const cw = containerRef.current?.clientWidth ?? 1200;
    const ch = containerRef.current?.clientHeight ?? 800;
    computeElkLayout(rfNodes, rfEdges, cw, ch).then((layouted) => {
      setNodes(layouted);
      setEdges(rfEdges);
      setTimeout(() => fitView({ padding: 0.15, duration: 200 }), 50);
    });
  }, [data, hiddenTypes, hiddenSubnets]);

  const onNodeClick: NodeMouseHandler = useCallback((_event, node) => {
    // Only open drawer for actual device nodes
    if (!node.id.startsWith("subnet:") && node.id !== "internet") {
      setDrawerMac(node.id);
    }
  }, []);

  const onConnect = useCallback(
    async (connection: Connection) => {
      if (!connection.source || !connection.target) return;
      // User drags from child's bottom handle (source) to parent's top handle (target)
      const childMac = connection.source;
      const parentMac = connection.target;
      try {
        await createTopologyOverride(childMac, parentMac);
        queryClient.invalidateQueries({ queryKey: ["topology"] });
        toast.success("Connection override created");
      } catch (err) {
        toast.error(err instanceof Error ? err.message : "Failed to create connection");
      }
    },
    [queryClient],
  );

  const onEdgeContextMenu = useCallback(
    (event: React.MouseEvent, edge: Edge) => {
      event.preventDefault();
      // Only show context menu for manual edges (white stroke)
      const edgeStroke = (edge.style as Record<string, unknown> | undefined)?.stroke;
      if (edgeStroke !== "#ffffff") return;
      setContextMenu({ x: event.clientX, y: event.clientY, edgeId: edge.id, childMac: edge.target });
    },
    [],
  );

  const handleRemoveOverride = useCallback(async () => {
    if (!contextMenu) return;
    try {
      await deleteTopologyOverride(contextMenu.childMac);
      queryClient.invalidateQueries({ queryKey: ["topology"] });
      toast.success("Override removed");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to remove override");
    }
    setContextMenu(null);
  }, [contextMenu, queryClient]);

  // Close context menu on click anywhere
  useEffect(() => {
    if (!contextMenu) return;
    const handler = () => setContextMenu(null);
    window.addEventListener("click", handler);
    return () => window.removeEventListener("click", handler);
  }, [contextMenu]);

  const toggleType = (type: string) => {
    setHiddenTypes((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  };

  const toggleSubnet = (subnet: string) => {
    setHiddenSubnets((prev) => {
      const next = new Set(prev);
      if (next.has(subnet)) next.delete(subnet);
      else next.add(subnet);
      return next;
    });
  };

  const clearFilters = () => {
    setHiddenTypes(new Set());
    setHiddenSubnets(new Set());
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center flex-1 min-h-0 -m-6">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div ref={containerRef} className="relative flex-1 min-h-0 -m-6">
      {/* Full-width topology canvas */}
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        onConnect={onConnect}
        onEdgeContextMenu={onEdgeContextMenu}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2, maxZoom: 1.5 }}
        minZoom={0.15}
        maxZoom={3}
        colorMode="dark"
        proOptions={{ hideAttribution: true }}
        connectionLineStyle={{ stroke: "#ffffff", strokeWidth: 2 }}
      >
        <Controls position="bottom-left" />
        <MiniMap
          position="top-right"
          nodeColor={(n) => DEVICE_TYPE_COLORS[(n.data as any)?.type] ?? "#64748b"}
          maskColor="rgba(0,0,0,0.55)"
          nodeBorderRadius={3}
          nodeStrokeWidth={0}
          style={{
            background: "rgba(15, 15, 30, 0.85)",
            backdropFilter: "blur(8px)",
            borderRadius: "10px",
            border: "1px solid rgba(255,255,255,0.08)",
            boxShadow: "0 4px 20px rgba(0,0,0,0.4)",
            width: 180,
            height: 120,
          }}
        />
        <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#ffffff08" />
      </ReactFlow>

      {/* Right-click context menu for manual edges */}
      {contextMenu && (
        <div
          className="fixed z-50 rounded-lg border border-border bg-card shadow-xl py-1 min-w-[180px]"
          style={{ left: contextMenu.x, top: contextMenu.y }}
        >
          <button
            onClick={handleRemoveOverride}
            className="flex items-center gap-2 w-full px-3 py-2 text-sm text-left hover:bg-secondary/80 text-destructive"
          >
            <X size={14} />
            Remove override
          </button>
        </div>
      )}

      {/* Floating toolbar — top left */}
      <div className="absolute top-3 left-3 flex items-center gap-2 z-10">
        {/* Filter dropdown */}
        <div ref={filterRef} className="relative">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setFilterOpen(!filterOpen)}
            className="bg-card/90 backdrop-blur-sm border-border/60 shadow-lg gap-1.5"
          >
            <Filter className="h-3.5 w-3.5" />
            Filters
            {activeFilterCount > 0 && (
              <span className="ml-1 px-1.5 py-0.5 text-[10px] font-bold rounded-full bg-blue-500 text-white leading-none">
                {activeFilterCount}
              </span>
            )}
            <ChevronDown className={`h-3.5 w-3.5 transition-transform ${filterOpen ? "rotate-180" : ""}`} />
          </Button>

          {filterOpen && (
            <div className="absolute top-full left-0 mt-1 w-64 rounded-lg border border-border bg-card/95 backdrop-blur-md shadow-xl py-2 max-h-[70vh] overflow-y-auto">
              {/* Header */}
              <div className="flex items-center justify-between px-3 pb-2 border-b border-border mb-2">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Filters</span>
                {activeFilterCount > 0 && (
                  <button onClick={clearFilters} className="text-[10px] text-blue-400 hover:text-blue-300">
                    Clear all
                  </button>
                )}
              </div>

              {/* Device Types */}
              <div className="px-1 mb-2">
                <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider px-2 mb-1">
                  Device Types
                </div>
                {deviceTypes.map(([type, count]) => (
                  <label key={type} className="flex items-center gap-2 px-2 py-1 text-xs cursor-pointer hover:bg-secondary/50 rounded mx-1">
                    <input
                      type="checkbox"
                      checked={!hiddenTypes.has(type)}
                      onChange={() => toggleType(type)}
                      className="rounded h-3.5 w-3.5"
                    />
                    <span
                      className="w-2 h-2 rounded-full shrink-0"
                      style={{ background: DEVICE_TYPE_COLORS[type] ?? "#64748b" }}
                    />
                    <span className="truncate">{type.replace(/_/g, " ")}</span>
                    <span className="ml-auto text-[10px] text-muted-foreground">{count}</span>
                  </label>
                ))}
              </div>

              {/* Subnets */}
              {subnets.length > 0 && (
                <div className="px-1 mb-2 border-t border-border pt-2">
                  <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider px-2 mb-1">
                    Subnets
                  </div>
                  {subnets.map((subnet) => (
                    <label key={subnet} className="flex items-center gap-2 px-2 py-1 text-xs cursor-pointer hover:bg-secondary/50 rounded mx-1">
                      <input
                        type="checkbox"
                        checked={!hiddenSubnets.has(subnet)}
                        onChange={() => toggleSubnet(subnet)}
                        className="rounded h-3.5 w-3.5"
                      />
                      <span className="font-mono text-[11px]">{subnet}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Fit view button */}
        <Button
          variant="outline"
          size="sm"
          onClick={() => fitView({ padding: 0.2, duration: 300 })}
          className="bg-card/90 backdrop-blur-sm border-border/60 shadow-lg"
        >
          <Maximize className="h-3.5 w-3.5" />
        </Button>

        {/* Stats badge */}
        <div className="text-[11px] text-muted-foreground bg-card/80 backdrop-blur-sm rounded-md border border-border/40 px-2.5 py-1.5 shadow">
          {nodes.length} devices &middot; {edges.length} connections
        </div>
      </div>

      {/* Device drawer */}
      <DeviceDrawer
        mac={drawerMac}
        open={!!drawerMac}
        onClose={() => setDrawerMac(null)}
      />
    </div>
  );
}

interface TopologyProps {
  subscribe: (handler: (msg: WsMessage) => void) => () => void;
}

export default function Topology({ subscribe }: TopologyProps) {
  return (
    <ReactFlowProvider>
      <TopologyInner subscribe={subscribe} />
    </ReactFlowProvider>
  );
}
