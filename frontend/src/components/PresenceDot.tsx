import { cn } from "@/lib/utils";

interface PresenceDotProps {
  isOnline: boolean;
  offlineSince?: string | null;
  className?: string;
}

function formatOfflineDuration(isoTs: string): string {
  try {
    const then = new Date(isoTs).getTime();
    const ms = Date.now() - then;
    if (ms < 60_000) return "Offline for <1m";
    const mins = Math.floor(ms / 60_000);
    if (mins < 60) return `Offline for ${mins}m`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `Offline for ${hours}h`;
    const days = Math.floor(hours / 24);
    return `Offline for ${days}d`;
  } catch {
    return "Offline";
  }
}

export function PresenceDot({ isOnline, offlineSince, className }: PresenceDotProps) {
  const tooltip = isOnline
    ? "Online"
    : (offlineSince ? formatOfflineDuration(offlineSince) : "Offline");
  return (
    <span
      title={tooltip}
      aria-label={tooltip}
      className={cn(
        "inline-block w-2.5 h-2.5 rounded-full align-middle",
        isOnline
          ? "bg-emerald-500 shadow-[0_0_8px_rgba(52,211,153,0.6)]"
          : "bg-slate-500/70",
        className,
      )}
    />
  );
}
