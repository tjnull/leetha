import { useEffect, useState } from "react";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { authHeaders } from "@/lib/api";
import { toast } from "sonner";
import { PresenceDot } from "@/components/PresenceDot";

interface PresencePanelProps {
  mac: string;
  isOnline: boolean;
  offlineSince: string | null;
  thresholdSeconds: number;
  onChanged?: () => void;
}

const PRESETS: Array<{ label: string; value: number }> = [
  { label: "1m", value: 60 },
  { label: "5m", value: 300 },
  { label: "15m", value: 900 },
  { label: "1h", value: 3600 },
  { label: "4h", value: 14400 },
  { label: "24h", value: 86400 },
];

function formatSeconds(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.round(secs / 60)}m`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h`;
  return `${Math.round(secs / 86400)}d`;
}

async function patchThreshold(mac: string, seconds: number): Promise<void> {
  const res = await fetch(`/api/devices/${encodeURIComponent(mac)}`, {
    method: "PATCH",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ presence_threshold_seconds: seconds }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`PATCH failed: ${res.status} ${body}`);
  }
}

export function PresencePanel({
  mac, isOnline, offlineSince, thresholdSeconds, onChanged,
}: PresencePanelProps) {
  const [value, setValue] = useState<number>(thresholdSeconds);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setValue(thresholdSeconds);
  }, [thresholdSeconds]);

  const commit = async (next: number) => {
    if (next === thresholdSeconds) return;
    setSaving(true);
    try {
      await patchThreshold(mac, next);
      toast.success(`Presence threshold set to ${formatSeconds(next)}`);
      onChanged?.();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Save failed");
      setValue(thresholdSeconds);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-3 p-3 border rounded-md bg-muted/10">
      <div className="flex items-center justify-between">
        <div className="font-semibold text-sm flex items-center gap-2">
          <PresenceDot isOnline={isOnline} offlineSince={offlineSince} />
          Presence
        </div>
        <span className="text-xs text-muted-foreground">
          {isOnline ? "Online" : offlineSince ? `Offline since ${new Date(offlineSince).toLocaleString()}` : "Offline"}
        </span>
      </div>
      <div>
        <Label htmlFor="presence-threshold" className="text-xs">
          Offline threshold: <span className="font-mono">{formatSeconds(value)}</span>
        </Label>
        <input
          id="presence-threshold"
          type="range"
          min={30}
          max={86400}
          step={30}
          value={value}
          disabled={saving}
          onChange={(e) => setValue(Number(e.target.value))}
          onMouseUp={() => void commit(value)}
          onTouchEnd={() => void commit(value)}
          className="w-full accent-primary"
        />
        <div className="flex flex-wrap gap-1 mt-2">
          {PRESETS.map((p) => (
            <Button
              key={p.value}
              size="sm"
              variant={value === p.value ? "default" : "outline"}
              className="h-6 text-[11px] px-2"
              onClick={() => {
                setValue(p.value);
                void commit(p.value);
              }}
              disabled={saving}
            >
              {p.label}
            </Button>
          ))}
        </div>
      </div>
    </div>
  );
}
