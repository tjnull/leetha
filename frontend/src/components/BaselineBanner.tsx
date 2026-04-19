import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { authHeaders } from "@/lib/api";
import { toast } from "sonner";

interface BaselineStatus {
  approved: number;
  unapproved: number;
  rejected: number;
  last_baseline_at: string | null;
}

async function fetchBaseline(): Promise<BaselineStatus> {
  const res = await fetch("/api/baseline/status", { headers: authHeaders({}) });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

async function setBaseline(): Promise<{ touched: number }> {
  const res = await fetch("/api/baseline/set", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: "{}",
  });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

export function BaselineBanner() {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["baseline-status"],
    queryFn: fetchBaseline,
    staleTime: 30000,
  });
  if (isLoading || !data) return null;
  // Hide banner if the network is already largely approved, OR the baseline
  // has already been set at some point.
  if (data.last_baseline_at || data.approved >= 5 || data.unapproved === 0) return null;

  const onClick = async () => {
    try {
      const result = await setBaseline();
      toast.success(`Baseline set: ${result.touched} device(s) approved`);
      qc.invalidateQueries({ queryKey: ["baseline-status"] });
      qc.invalidateQueries({ queryKey: ["devices"] });
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Baseline failed");
    }
  };

  return (
    <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 flex items-center justify-between gap-4">
      <div className="text-sm">
        <div className="font-semibold text-amber-400">Authorization baseline not set</div>
        <div className="text-muted-foreground">
          {data.unapproved} device(s) are currently unapproved and will fire <span className="font-mono">new_host</span> findings at WARNING severity.
          Click "Set baseline" to approve all currently-discovered devices at once.
        </div>
      </div>
      <Button size="sm" onClick={onClick}>Set baseline</Button>
    </div>
  );
}
