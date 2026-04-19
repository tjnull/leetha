import { useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { authHeaders } from "@/lib/api";
import { toast } from "sonner";
import { Upload, FileText, CheckCircle, XCircle } from "lucide-react";

async function upload(file: File): Promise<{ imported: number; flavor: string | null }> {
  const fd = new FormData();
  fd.append("file", file);
  const res = await fetch("/api/inventory/dhcp-leases/upload", {
    method: "POST",
    headers: authHeaders({}),
    body: fd,
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

interface ImporterCardProps {
  name: string;
  title: string;
  description: string;
  children?: React.ReactNode;
}

function ImporterCard({ name, title, description, children }: ImporterCardProps) {
  return (
    <div className="rounded-lg border border-border bg-card p-4 space-y-3">
      <div className="flex items-start justify-between">
        <div>
          <div className="font-semibold text-sm">{title}</div>
          <div className="text-xs text-muted-foreground">{description}</div>
        </div>
        <Badge variant="outline" className="text-[10px] font-mono">{name}</Badge>
      </div>
      {children}
    </div>
  );
}

export function InventorySources() {
  const fileRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [lastResult, setLastResult] = useState<null | { imported: number; flavor: string | null; error?: string }>(null);

  const onFile = async (file: File) => {
    setBusy(true);
    try {
      const result = await upload(file);
      setLastResult(result);
      toast.success(`Imported ${result.imported} device(s)`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Upload failed";
      setLastResult({ imported: 0, flavor: null, error: msg });
      toast.error(msg);
    } finally {
      setBusy(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  return (
    <div className="rounded-xl border border-border bg-card/50 p-5 space-y-4">
      <div className="flex items-center gap-2">
        <FileText className="text-primary" size={18} />
        <h2 className="text-lg font-semibold">Inventory Sources</h2>
      </div>
      <p className="text-sm text-muted-foreground">
        External sources that describe devices the sensor hasn't seen yet. Imported devices appear with <span className="font-mono">passively_observed=false</span> until live traffic confirms them.
      </p>

      <ImporterCard
        name="dhcp_leases"
        title="DHCP lease file"
        description="Upload an ISC dhcpd.leases or dnsmasq.leases file. Devices are added with authorization=unapproved until you baseline."
      >
        <Input
          ref={fileRef}
          type="file"
          accept=".leases,.lease,.txt"
          disabled={busy}
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) void onFile(f);
          }}
        />
        {lastResult && (
          <div className="flex items-center gap-2 text-xs">
            {lastResult.error ? (
              <><XCircle className="text-destructive" size={14} /> <span className="text-destructive">{lastResult.error}</span></>
            ) : (
              <><CheckCircle className="text-emerald-400" size={14} />
                <span className="text-muted-foreground">
                  Imported {lastResult.imported} device(s){lastResult.flavor && `, flavor: ${lastResult.flavor}`}
                </span></>
            )}
          </div>
        )}
        <Button
          size="sm"
          variant="outline"
          className="gap-1.5"
          disabled={busy}
          onClick={() => fileRef.current?.click()}
        >
          <Upload size={14} /> {busy ? "Uploading…" : "Upload lease file"}
        </Button>
      </ImporterCard>
    </div>
  );
}
