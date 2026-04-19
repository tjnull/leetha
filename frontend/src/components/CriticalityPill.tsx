import { cn } from "@/lib/utils";

export type Criticality = "low" | "medium" | "high" | "critical" | null | undefined;

const CRIT_STYLES: Record<string, string> = {
  low: "bg-slate-500/10 text-slate-400 border-slate-500/30",
  medium: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
};

interface CriticalityPillProps {
  value: Criticality;
  className?: string;
}

export function CriticalityPill({ value, className }: CriticalityPillProps) {
  if (!value) return null;
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium capitalize",
        CRIT_STYLES[value] ?? "bg-muted text-muted-foreground border-border",
        className,
      )}
    >
      {value}
    </span>
  );
}
