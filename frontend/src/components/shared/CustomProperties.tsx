import { useEffect, useState } from "react";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { X } from "lucide-react";
import { authHeaders } from "@/lib/api";
import { toast } from "sonner";
import type { Criticality } from "@/components/CriticalityPill";

export interface CustomPropsValues {
  owner: string | null;
  location: string | null;
  criticality: Criticality;
  tags: string[];
  notes: string | null;
}

interface CustomPropertiesProps {
  mac: string;
  initial: CustomPropsValues;
  onSaved?: (next: CustomPropsValues) => void;
}

async function patchDevice(
  mac: string,
  body: Partial<CustomPropsValues>,
): Promise<CustomPropsValues> {
  const res = await fetch(`/api/devices/${encodeURIComponent(mac)}`, {
    method: "PATCH",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`PATCH failed: ${res.status} ${res.statusText}`);
  return res.json();
}

export function CustomProperties({ mac, initial, onSaved }: CustomPropertiesProps) {
  const [owner, setOwner] = useState(initial.owner ?? "");
  const [location, setLocation] = useState(initial.location ?? "");
  const [criticality, setCriticality] = useState<string>(initial.criticality ?? "");
  const [tags, setTags] = useState<string[]>(initial.tags ?? []);
  const [newTag, setNewTag] = useState("");
  const [notes, setNotes] = useState(initial.notes ?? "");

  useEffect(() => {
    setOwner(initial.owner ?? "");
    setLocation(initial.location ?? "");
    setCriticality(initial.criticality ?? "");
    setTags(initial.tags ?? []);
    setNotes(initial.notes ?? "");
  }, [initial]);

  const save = async (patch: Partial<CustomPropsValues>) => {
    try {
      const next = await patchDevice(mac, patch);
      onSaved?.(next);
      toast.success("Saved");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Save failed");
    }
  };

  const addTag = () => {
    const t = newTag.trim();
    if (!t || tags.includes(t)) {
      setNewTag("");
      return;
    }
    const next = [...tags, t];
    setTags(next);
    setNewTag("");
    void save({ tags: next });
  };

  const removeTag = (t: string) => {
    const next = tags.filter((x) => x !== t);
    setTags(next);
    void save({ tags: next });
  };

  return (
    <div className="space-y-3 p-3 border rounded-md bg-muted/10">
      <div className="font-semibold text-sm">Custom Properties</div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label htmlFor="cp-owner">Owner</Label>
          <Input
            id="cp-owner"
            value={owner}
            onChange={(e) => setOwner(e.target.value)}
            onBlur={() => {
              if ((owner || null) !== initial.owner) void save({ owner: owner || null });
            }}
          />
        </div>
        <div>
          <Label htmlFor="cp-location">Location</Label>
          <Input
            id="cp-location"
            value={location}
            onChange={(e) => setLocation(e.target.value)}
            onBlur={() => {
              if ((location || null) !== initial.location) void save({ location: location || null });
            }}
          />
        </div>
      </div>

      <div>
        <Label htmlFor="cp-criticality">Criticality</Label>
        <Select
          value={criticality || "__none__"}
          onValueChange={(v) => {
            const next = v === "__none__" ? "" : v;
            setCriticality(next);
            void save({ criticality: (next || null) as Criticality });
          }}
        >
          <SelectTrigger id="cp-criticality"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="__none__">—</SelectItem>
            <SelectItem value="low">low</SelectItem>
            <SelectItem value="medium">medium</SelectItem>
            <SelectItem value="high">high</SelectItem>
            <SelectItem value="critical">critical</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div>
        <Label>Tags</Label>
        <div className="flex flex-wrap gap-1 mb-2">
          {tags.map((t) => (
            <Badge key={t} variant="secondary" className="gap-1">
              {t}
              <button
                type="button"
                onClick={() => removeTag(t)}
                className="opacity-60 hover:opacity-100"
                aria-label={`Remove tag ${t}`}
              >
                <X className="w-3 h-3" />
              </button>
            </Badge>
          ))}
        </div>
        <div className="flex gap-2">
          <Input
            placeholder="Add tag…"
            value={newTag}
            onChange={(e) => setNewTag(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                addTag();
              }
            }}
          />
          <Button type="button" size="sm" onClick={addTag} disabled={!newTag.trim()}>
            Add
          </Button>
        </div>
      </div>

      <div>
        <Label htmlFor="cp-notes">Notes</Label>
        <textarea
          id="cp-notes"
          className="w-full rounded-md border bg-transparent px-3 py-2 text-sm"
          rows={3}
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          onBlur={() => {
            if ((notes || null) !== initial.notes) void save({ notes: notes || null });
          }}
        />
      </div>
    </div>
  );
}
