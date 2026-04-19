import { cn } from "@/lib/utils";

export type AuthorizationState = "approved" | "unapproved" | "rejected";

const STATE_STYLES: Record<AuthorizationState, string> = {
  approved: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
  unapproved: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  rejected: "bg-red-500/10 text-red-400 border-red-500/30",
};

const STATE_LABELS: Record<AuthorizationState, string> = {
  approved: "Approved",
  unapproved: "Unapproved",
  rejected: "Rejected",
};

interface AuthorizationBadgeProps {
  value: AuthorizationState | null | undefined;
  className?: string;
}

export function AuthorizationBadge({ value, className }: AuthorizationBadgeProps) {
  const v = (value ?? "unapproved") as AuthorizationState;
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium",
        STATE_STYLES[v] ?? STATE_STYLES.unapproved,
        className,
      )}
    >
      {STATE_LABELS[v]}
    </span>
  );
}
