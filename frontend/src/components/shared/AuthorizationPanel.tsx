import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { authHeaders } from "@/lib/api";
import {
  AuthorizationBadge,
  type AuthorizationState,
} from "@/components/AuthorizationBadge";

interface AuthorizationPanelProps {
  mac: string;
  current: AuthorizationState | null | undefined;
  authorizedBy: string | null | undefined;
  authorizedAt: string | null | undefined;
  onChanged?: () => void;
}

async function postAction(mac: string, verb: string, reason?: string) {
  const res = await fetch(
    `/api/devices/${encodeURIComponent(mac)}/${verb}`,
    {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(reason ? { reason } : {}),
    },
  );
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export function AuthorizationPanel({
  mac,
  current,
  authorizedBy,
  authorizedAt,
  onChanged,
}: AuthorizationPanelProps) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);

  const act = async (verb: "approve" | "reject" | "revoke") => {
    setBusy(true);
    try {
      await postAction(mac, verb, reason || undefined);
      toast.success(`Device ${verb}d`);
      setReason("");
      onChanged?.();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Action failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3 p-3 border rounded-md bg-muted/10">
      <div className="flex items-center justify-between">
        <div className="font-semibold text-sm">Authorization</div>
        <AuthorizationBadge value={current ?? "unapproved"} />
      </div>
      {(authorizedBy || authorizedAt) && (
        <div className="text-xs text-muted-foreground">
          {authorizedBy && <span>by {authorizedBy}</span>}
          {authorizedBy && authorizedAt && <span> · </span>}
          {authorizedAt && <span>{new Date(authorizedAt).toLocaleString()}</span>}
        </div>
      )}
      <Input
        placeholder="Reason (optional)…"
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        maxLength={500}
      />
      <div className="flex gap-2">
        <Button
          size="sm"
          variant="default"
          disabled={busy || current === "approved"}
          onClick={() => act("approve")}
        >
          Approve
        </Button>
        <Button
          size="sm"
          variant="destructive"
          disabled={busy || current === "rejected"}
          onClick={() => act("reject")}
        >
          Reject
        </Button>
        <Button
          size="sm"
          variant="outline"
          disabled={busy || current === "unapproved" || !current}
          onClick={() => act("revoke")}
        >
          Revoke
        </Button>
      </div>
    </div>
  );
}
