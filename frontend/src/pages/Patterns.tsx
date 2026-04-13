import { useState, useRef, useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  fetchPatterns,
  addPattern,
  updatePattern,
  deletePattern,
  reorderPatterns,
  resetPatternHits,
  testPattern,
  validatePattern,
  importPatterns,
  exportPatternsUrl,
  type PatternEntry,
  type PatternTestMatch,
} from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";
import {
  Trash2,
  Plus,
  Fingerprint,
  GripVertical,
  FlaskConical,
  RotateCcw,
  Download,
  Upload,
  Network,
  Wifi,
  Monitor,
} from "lucide-react";
import {
  DndContext,
  closestCenter,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent,
} from "@dnd-kit/core";
import {
  arrayMove,
  SortableContext,
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";

const PATTERN_TYPES = ["hostname", "dhcp_opt60", "mac_prefix", "dhcp_opt55"] as const;

const typeLabels: Record<string, string> = {
  hostname: "Hostname Patterns",
  dhcp_opt60: "DHCP Option 60 (Vendor Class)",
  mac_prefix: "MAC Prefix",
  dhcp_opt55: "DHCP Option 55",
};

const typeIcons: Record<string, React.ElementType> = {
  hostname: Monitor,
  dhcp_opt60: Network,
  mac_prefix: Wifi,
  dhcp_opt55: Network,
};

const typeDescriptions: Record<string, string> = {
  hostname: "Match devices by hostname using glob patterns (e.g., *printer*, hp-*)",
  dhcp_opt60: "Match DHCP vendor class identifiers",
  mac_prefix: "Match devices by MAC address prefix (e.g., aa:bb:cc)",
  dhcp_opt55: "Match DHCP parameter request lists",
};

const typePlaceholders: Record<string, string> = {
  hostname: "*printer*",
  dhcp_opt60: "MSFT 5.0",
  mac_prefix: "aa:bb:cc",
  dhcp_opt55: "1,3,6,15,31,33",
};

// --- Inline Editable Field ---

function InlineEdit({
  value,
  onSave,
  disabled,
  className,
  type = "text",
}: {
  value: string;
  onSave: (val: string) => void;
  disabled?: boolean;
  className?: string;
  type?: string;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (editing) inputRef.current?.focus();
  }, [editing]);

  if (disabled || !editing) {
    return (
      <span
        className={cn(
          "cursor-pointer hover:bg-muted/50 px-1 -mx-1 rounded transition-colors",
          disabled && "cursor-default hover:bg-transparent",
          className
        )}
        onClick={() => !disabled && setEditing(true)}
      >
        {value || "—"}
      </span>
    );
  }

  return (
    <Input
      ref={inputRef}
      type={type}
      value={draft}
      onChange={(e) => setDraft(e.target.value)}
      onBlur={() => {
        if (draft !== value) onSave(draft);
        setEditing(false);
      }}
      onKeyDown={(e) => {
        if (e.key === "Enter") {
          if (draft !== value) onSave(draft);
          setEditing(false);
        } else if (e.key === "Escape") {
          setDraft(value);
          setEditing(false);
        }
      }}
      className={cn("h-6 text-xs px-1 w-auto min-w-[60px]", className)}
    />
  );
}

// --- Sortable Pattern Row ---

function SortablePatternRow({
  id,
  entry,
  index,
  type,
  isCapturing,
  onUpdate,
  onDelete,
  onTest,
  onResetHits,
}: {
  id: string;
  entry: PatternEntry;
  index: number;
  type: string;
  isCapturing: boolean;
  onUpdate: (index: number, updated: PatternEntry) => void;
  onDelete: (index: number) => void;
  onTest: (entry: PatternEntry, type: string) => void;
  onResetHits: (index: number) => void;
}) {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id });

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
  };

  const handleFieldUpdate = (field: string, value: string) => {
    const updated = { ...entry, [field]: field === "confidence" ? Number(value) || 0 : value };
    onUpdate(index, updated);
  };

  return (
    <div
      ref={setNodeRef}
      style={style}
      className={cn(
        "flex items-start justify-between px-5 py-4 gap-4",
        isDragging && "opacity-50 bg-muted/30",
      )}
    >
      {/* Drag handle */}
      <div
        className="shrink-0 pt-1 cursor-grab active:cursor-grabbing text-muted-foreground hover:text-foreground"
        {...attributes}
        {...listeners}
      >
        <GripVertical size={14} />
      </div>

      {/* Left: pattern details */}
      <div className="space-y-2 min-w-0 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <InlineEdit
            value={entry.pattern}
            onSave={(v) => handleFieldUpdate("pattern", v)}
            className="font-semibold text-sm font-mono"
          />
          <Badge
            variant="outline"
            className={cn(
              "text-[10px] uppercase font-semibold",
              (entry.confidence ?? 0) >= 80
                ? "bg-success/20 text-success border-success/30"
                : (entry.confidence ?? 0) >= 50
                ? "bg-yellow-500/20 text-yellow-500 border-yellow-500/30"
                : "text-muted-foreground"
            )}
          >
            {entry.confidence ?? 80}%
          </Badge>
          {(entry.hits ?? 0) > 0 && (
            <Badge variant="secondary" className="text-[10px] font-semibold">
              {entry.hits} hit{entry.hits !== 1 ? "s" : ""}
            </Badge>
          )}
        </div>

        <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
          <span className="text-muted-foreground">Category:</span>
          <InlineEdit
            value={entry.device_type}
            onSave={(v) => handleFieldUpdate("device_type", v)}
          />
          <span className="text-muted-foreground">Vendor:</span>
          <InlineEdit
            value={entry.manufacturer || ""}
            onSave={(v) => handleFieldUpdate("manufacturer", v)}
          />
          {entry.created_at && (
            <>
              <span className="text-muted-foreground">Created:</span>
              <span className="text-muted-foreground">
                {new Date(entry.created_at).toLocaleDateString()}
              </span>
            </>
          )}
        </div>
      </div>

      {/* Right: actions */}
      <div className="flex items-center gap-1 shrink-0 pt-1">
        <Button
          variant="ghost"
          size="sm"
          className="text-xs h-7 w-7 p-0"
          title="Test pattern"
          onClick={() => onTest(entry, type)}
        >
          <FlaskConical size={14} />
        </Button>
        {(entry.hits ?? 0) > 0 && (
          <Button
            variant="ghost"
            size="sm"
            className="text-xs h-7 w-7 p-0"
            title="Reset hit counter"
            onClick={() => onResetHits(index)}
          >
            <RotateCcw size={14} />
          </Button>
        )}
        <Button
          variant="ghost"
          size="sm"
          className="text-xs h-7 w-7 p-0 text-destructive hover:text-destructive"
          title="Delete pattern"
          onClick={() => onDelete(index)}
        >
          <Trash2 size={14} />
        </Button>
      </div>
    </div>
  );
}

// --- Main Component ---

export default function Patterns() {
  const queryClient = useQueryClient();

  const { data: patterns = {} } = useQuery({
    queryKey: ["patterns"],
    queryFn: fetchPatterns,
  });

  // Dialog states
  const [addDialogOpen, setAddDialogOpen] = useState(false);
  const [importDialogOpen, setImportDialogOpen] = useState(false);
  const [testDialogOpen, setTestDialogOpen] = useState(false);

  // Add form state
  const [formType, setFormType] = useState<string>("hostname");
  const [formPattern, setFormPattern] = useState("");
  const [formDeviceType, setFormDeviceType] = useState("");
  const [formManufacturer, setFormManufacturer] = useState("");
  const [formConfidence, setFormConfidence] = useState("80");
  const [formError, setFormError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Import state
  const [importPreview, setImportPreview] = useState<any>(null);
  const [importData, setImportData] = useState("");
  const [importContentType, setImportContentType] = useState("");
  const [importing, setImporting] = useState(false);

  // Test state
  const [testMatches, setTestMatches] = useState<PatternTestMatch[]>([]);
  const [testLoading, setTestLoading] = useState(false);
  const [testEntry, setTestEntry] = useState<{ type: string; pattern: string; device_type: string; manufacturer: string } | null>(null);

  // Live test state
  const [liveTestActive, setLiveTestActive] = useState(false);
  const [liveMatches, setLiveMatches] = useState<any[]>([]);

  // DnD sensors
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 5 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates })
  );

  const totalPatterns = Object.values(patterns).reduce(
    (sum, arr) => sum + (Array.isArray(arr) ? arr.length : Object.keys(arr).length),
    0
  );

  // --- Handlers ---

  const handleAdd = async () => {
    if (!formPattern.trim() || !formDeviceType.trim()) {
      setFormError("Pattern and category are required.");
      return;
    }

    // Validate
    try {
      const result = await validatePattern({ type: formType, pattern: formPattern });
      if (!result.valid) {
        setFormError(result.error || "Invalid pattern");
        return;
      }
    } catch {
      // Proceed if validation endpoint fails
    }

    setSubmitting(true);
    setFormError("");
    try {
      const entry: PatternEntry = {
        pattern: formPattern.trim(),
        device_type: formDeviceType.trim(),
        manufacturer: formManufacturer.trim(),
        confidence: Number(formConfidence) || 80,
      };
      await addPattern(formType, entry);
      toast.success(`Added ${typeLabels[formType]?.split(" ")[0] ?? formType} pattern`);
      queryClient.invalidateQueries({ queryKey: ["patterns"] });
      setFormPattern("");
      setFormDeviceType("");
      setFormManufacturer("");
      setFormConfidence("80");
      setAddDialogOpen(false);
    } catch (err: any) {
      const msg = err?.message || String(err);
      setFormError(msg);
      toast.error(`Failed to add pattern: ${msg}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleAddAndTest = async () => {
    await handleAdd();
    if (formPattern && formDeviceType) {
      handleTest({ pattern: formPattern, device_type: formDeviceType, manufacturer: formManufacturer, confidence: Number(formConfidence) || 80 }, formType);
    }
  };

  const handleUpdate = async (type: string, index: number, updated: PatternEntry) => {
    try {
      await updatePattern(type, index, updated);
      queryClient.invalidateQueries({ queryKey: ["patterns"] });
    } catch (err) {
      toast.error(`Failed to update: ${err}`);
    }
  };

  const handleDelete = async (type: string, index: number) => {
    try {
      await deletePattern(type, index);
      toast.success("Pattern deleted");
      queryClient.invalidateQueries({ queryKey: ["patterns"] });
    } catch (err) {
      toast.error(`Failed to delete: ${err}`);
    }
  };

  const handleResetHits = async (type: string, index: number) => {
    try {
      await resetPatternHits(type, index);
      toast.success("Hit counter reset");
      queryClient.invalidateQueries({ queryKey: ["patterns"] });
    } catch (err) {
      toast.error(`Failed to reset: ${err}`);
    }
  };

  const handleDragEnd = async (type: string, event: DragEndEvent) => {
    const { active, over } = event;
    if (!over || active.id === over.id) return;

    const entries = patterns[type] ?? [];
    if (!Array.isArray(entries)) return;

    const oldIndex = entries.findIndex((_, i) => `${type}-${i}` === active.id);
    const newIndex = entries.findIndex((_, i) => `${type}-${i}` === over.id);
    if (oldIndex === -1 || newIndex === -1) return;

    const newOrder = arrayMove(
      entries.map((_, i) => i),
      oldIndex,
      newIndex
    );

    try {
      await reorderPatterns(type, newOrder);
      queryClient.invalidateQueries({ queryKey: ["patterns"] });
    } catch (err) {
      toast.error(`Failed to reorder: ${err}`);
    }
  };

  const handleTest = async (entry: PatternEntry, type: string) => {
    setTestEntry({ type, pattern: entry.pattern, device_type: entry.device_type, manufacturer: entry.manufacturer });
    setTestLoading(true);
    setTestDialogOpen(true);
    setTestMatches([]);
    setLiveMatches([]);
    setLiveTestActive(false);

    try {
      const result = await testPattern({ type, pattern: entry.pattern, device_type: entry.device_type, manufacturer: entry.manufacturer });
      setTestMatches(result.matches);
    } catch (err) {
      toast.error(`Test failed: ${err}`);
    } finally {
      setTestLoading(false);
    }
  };

  const handleLiveTest = async () => {
    if (!testEntry) return;
    setLiveTestActive(true);
    setLiveMatches([]);

    try {
      const token = localStorage.getItem("leetha_token");
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (token) headers["Authorization"] = `Bearer ${token}`;

      const resp = await fetch("/api/patterns/test/live", {
        method: "POST",
        headers,
        body: JSON.stringify({ ...testEntry, duration: 30 }),
      });

      const reader = resp.body?.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      if (!reader) return;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          const dataMatch = line.match(/^data:\s*(.+)$/m);
          if (!dataMatch) continue;
          try {
            const event = JSON.parse(dataMatch[1]);
            if (event.type === "done") {
              setLiveTestActive(false);
            } else {
              setLiveMatches((prev) => [...prev, event]);
            }
          } catch {}
        }
      }
    } catch (err) {
      toast.error(`Live test failed: ${err}`);
    } finally {
      setLiveTestActive(false);
    }
  };

  // --- Import handlers ---

  const handleImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const text = await file.text();
    const ct = file.name.endsWith(".csv") ? "text/csv" : "application/json";
    setImportData(text);
    setImportContentType(ct);

    try {
      const preview = await importPatterns(text, ct, true);
      setImportPreview(preview);
    } catch (err) {
      toast.error(`Failed to parse file: ${err}`);
      setImportPreview(null);
    }
  };

  const handleImportConfirm = async () => {
    setImporting(true);
    try {
      const result = await importPatterns(importData, importContentType, false);
      toast.success(`Imported ${(result as any).imported} pattern(s)`);
      queryClient.invalidateQueries({ queryKey: ["patterns"] });
      setImportDialogOpen(false);
      setImportPreview(null);
      setImportData("");
    } catch (err) {
      toast.error(`Import failed: ${err}`);
    } finally {
      setImporting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h2 className="text-lg font-semibold">Custom Fingerprint Patterns</h2>
          <Badge variant="outline" className="text-[10px] h-5">
            {totalPatterns} pattern{totalPatterns !== 1 ? "s" : ""}
          </Badge>
        </div>
        <div className="flex items-center gap-2">
          {/* Export */}
          <div className="flex gap-1">
            <Button
              variant="outline"
              size="sm"
              className="text-xs h-7 gap-1.5"
              onClick={() => window.open(exportPatternsUrl("json"), "_blank")}
              disabled={totalPatterns === 0}
            >
              <Download size={12} />
              JSON
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="text-xs h-7 gap-1.5"
              onClick={() => window.open(exportPatternsUrl("csv"), "_blank")}
              disabled={totalPatterns === 0}
            >
              <Download size={12} />
              CSV
            </Button>
          </div>

          {/* Import */}
          <Button
            variant="outline"
            size="sm"
            className="text-xs h-7 gap-1.5"
            onClick={() => {
              setImportPreview(null);
              setImportData("");
              setImportDialogOpen(true);
            }}
          >
            <Upload size={12} />
            Import
          </Button>

          {/* Add */}
          <Button
            size="sm"
            className="text-xs h-7 gap-1.5"
            onClick={() => {
              setFormError("");
              setAddDialogOpen(true);
            }}
          >
            <Plus size={12} />
            Add Pattern
          </Button>
        </div>
      </div>

      {/* Pattern type cards */}
      {PATTERN_TYPES.map((type) => {
        const entries = patterns[type];
        if (!entries || (Array.isArray(entries) ? entries.length === 0 : Object.keys(entries).length === 0)) return null;

        const entryList = Array.isArray(entries) ? entries : Object.entries(entries).map(([key, val]: [string, any]) => ({ pattern: key, ...val }));
        const TypeIcon = typeIcons[type] ?? Fingerprint;

        return (
          <div key={type} className="rounded-xl bg-card border border-border overflow-hidden">
            {/* Category header */}
            <div className="flex items-center gap-3 px-5 py-3 border-b border-border">
              <TypeIcon size={16} className="text-primary" />
              <div>
                <h3 className="text-sm font-semibold">{typeLabels[type]}</h3>
                <p className="text-[11px] text-muted-foreground">{typeDescriptions[type]}</p>
              </div>
              <span className="ml-auto text-xs text-muted-foreground">{entryList.length}</span>
            </div>

            {/* Pattern rows */}
            <DndContext
              sensors={sensors}
              collisionDetection={closestCenter}
              onDragEnd={(event) => handleDragEnd(type, event)}
            >
              <SortableContext
                items={entryList.map((_, i) => `${type}-${i}`)}
                strategy={verticalListSortingStrategy}
              >
                <div className="divide-y divide-border">
                  {entryList.map((entry, index) => (
                    <SortablePatternRow
                      key={`${type}-${index}`}
                      id={`${type}-${index}`}
                      entry={entry}
                      index={index}
                      type={type}
                      isCapturing={false}
                      onUpdate={(i, updated) => handleUpdate(type, i, updated)}
                      onDelete={(i) => handleDelete(type, i)}
                      onTest={(e, t) => handleTest(e, t)}
                      onResetHits={(i) => handleResetHits(type, i)}
                    />
                  ))}
                </div>
              </SortableContext>
            </DndContext>
          </div>
        );
      })}

      {/* Empty state */}
      {totalPatterns === 0 && (
        <div className="rounded-xl bg-card border border-border flex flex-col items-center justify-center py-16 text-muted-foreground">
          <Fingerprint size={32} className="mb-3" />
          <p className="font-medium text-foreground">No custom patterns defined</p>
          <p className="text-xs mt-1 max-w-md text-center">
            Custom patterns let you identify devices that aren't covered by the built-in fingerprint databases.
            Add hostname globs, DHCP vendor classes, or MAC prefixes to classify specific devices on your network.
          </p>
          <Button
            size="sm"
            className="mt-4 text-xs h-7 gap-1.5"
            onClick={() => {
              setFormError("");
              setAddDialogOpen(true);
            }}
          >
            <Plus size={12} />
            Add Your First Pattern
          </Button>
        </div>
      )}

      {/* Add Pattern Dialog */}
      <Dialog open={addDialogOpen} onOpenChange={setAddDialogOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Add Custom Pattern</DialogTitle>
            <DialogDescription>
              Create a new fingerprint pattern to identify devices on your network.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            <div>
              <Label className="text-xs">Pattern Type</Label>
              <Select value={formType} onValueChange={(v) => { setFormType(v); setFormError(""); }}>
                <SelectTrigger className="mt-1">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PATTERN_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {typeLabels[t]?.split(" ")[0] ?? t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label className="text-xs">Pattern</Label>
              <Input
                className="mt-1 font-mono"
                placeholder={typePlaceholders[formType] ?? ""}
                value={formPattern}
                onChange={(e) => { setFormPattern(e.target.value); setFormError(""); }}
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label className="text-xs">Host Category</Label>
                <Input
                  className="mt-1"
                  placeholder="e.g. Printer"
                  value={formDeviceType}
                  onChange={(e) => setFormDeviceType(e.target.value)}
                />
              </div>
              <div>
                <Label className="text-xs">Vendor</Label>
                <Input
                  className="mt-1"
                  placeholder="e.g. HP"
                  value={formManufacturer}
                  onChange={(e) => setFormManufacturer(e.target.value)}
                />
              </div>
            </div>

            <div>
              <Label className="text-xs">Certainty (0–100)</Label>
              <Input
                type="number"
                min={0}
                max={100}
                className="mt-1 w-24"
                value={formConfidence}
                onChange={(e) => setFormConfidence(e.target.value)}
              />
            </div>

            {formError && (
              <p className="text-xs text-destructive">{formError}</p>
            )}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setAddDialogOpen(false)}>Cancel</Button>
            <Button variant="outline" onClick={handleAddAndTest} disabled={submitting}>Add &amp; Test</Button>
            <Button onClick={handleAdd} disabled={submitting}>Add Pattern</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Import Dialog */}
      <Dialog open={importDialogOpen} onOpenChange={setImportDialogOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Import Patterns</DialogTitle>
            <DialogDescription>
              Upload a JSON or CSV file containing custom patterns.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            <Input
              type="file"
              accept=".json,.csv"
              onChange={handleImportFile}
            />

            {importPreview && (
              <div className="rounded-lg border border-border p-4">
                <p className="text-sm font-medium mb-2">
                  Preview: {importPreview.count} pattern(s) to import
                </p>
                <div className="text-xs text-muted-foreground space-y-1">
                  {Object.entries(importPreview.patterns || {}).map(([type, entries]: [string, any]) => (
                    <p key={type}>
                      {typeLabels[type] ?? type}: {Array.isArray(entries) ? entries.length : Object.keys(entries).length} pattern(s)
                    </p>
                  ))}
                </div>
              </div>
            )}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setImportDialogOpen(false)}>Cancel</Button>
            <Button
              onClick={handleImportConfirm}
              disabled={!importPreview || importing}
            >
              {importing ? "Importing..." : `Import ${importPreview?.count ?? 0} Pattern(s)`}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Test Results Dialog */}
      <Dialog open={testDialogOpen} onOpenChange={setTestDialogOpen}>
        <DialogContent className="sm:max-w-3xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Pattern Test Results</DialogTitle>
            <DialogDescription>
              {testEntry && (
                <>Testing <code className="bg-muted px-1 rounded">{testEntry.pattern}</code> ({testEntry.type})</>
              )}
            </DialogDescription>
          </DialogHeader>

          {testLoading ? (
            <p className="text-sm text-muted-foreground py-4">Testing pattern against inventory...</p>
          ) : (
            <div className="space-y-4">
              {/* Inventory matches */}
              <div>
                <h4 className="text-sm font-medium mb-2">
                  Inventory Matches ({testMatches.length})
                </h4>
                {testMatches.length === 0 ? (
                  <p className="text-xs text-muted-foreground">No devices in the inventory match this pattern.</p>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="text-xs">MAC</TableHead>
                        <TableHead className="text-xs">IP</TableHead>
                        <TableHead className="text-xs">Matched On</TableHead>
                        <TableHead className="text-xs">Current</TableHead>
                        <TableHead className="text-xs">New</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {testMatches.map((m, i) => (
                        <TableRow key={i}>
                          <TableCell className="font-mono text-xs">{m.hw_addr}</TableCell>
                          <TableCell className="text-xs">{m.ip_addr}</TableCell>
                          <TableCell className="text-xs">{m.matched_on}</TableCell>
                          <TableCell className="text-xs">{m.current_category} / {m.current_vendor}</TableCell>
                          <TableCell className="text-xs font-medium">{m.new_category} / {m.new_vendor}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </div>

              {/* Live test */}
              <div className="border-t border-border pt-4">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-sm font-medium">Live Test</h4>
                  <Button
                    size="sm"
                    variant="outline"
                    className="text-xs h-7 gap-1.5"
                    onClick={handleLiveTest}
                    disabled={liveTestActive}
                  >
                    <FlaskConical size={12} />
                    {liveTestActive ? "Testing (30s)..." : "Start Live Test"}
                  </Button>
                </div>
                {liveMatches.length > 0 && (
                  <div className="space-y-1">
                    {liveMatches.map((m, i) => (
                      <div key={i} className="flex items-center gap-3 text-xs bg-muted/30 rounded px-3 py-1.5">
                        <span className="font-mono">{m.hw_addr}</span>
                        <span>{m.ip_addr}</span>
                        <span className="text-muted-foreground">{m.protocol}</span>
                        <span className="ml-auto font-medium">{m.matched_on}</span>
                      </div>
                    ))}
                  </div>
                )}
                {liveTestActive && liveMatches.length === 0 && (
                  <p className="text-xs text-muted-foreground">Waiting for matching traffic...</p>
                )}
              </div>
            </div>
          )}

          <DialogFooter>
            <Button variant="outline" onClick={() => setTestDialogOpen(false)}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
