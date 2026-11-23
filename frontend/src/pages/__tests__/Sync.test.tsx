import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import Sync from "@/pages/Sync";

afterEach(() => vi.unstubAllGlobals());

it("shows the persisted fingerprint snapshot on load", async () => {
  const snapshot = "2026-11-21T10:44:08+00:00";
  const sources = {
    sources: [{
      name: "ieee_oui",
      display_name: "OUI Master Database",
      url: "https://example.test/feed.csv",
      description: "Assignment blocks",
      source_type: "csv",
      freshness: { last_synced_at: snapshot, entry_count: 59424, upstream_etag: '"revision-1"' },
    }],
  };
  vi.stubGlobal("fetch", vi.fn(async (url: string) => url.endsWith("/sync/sources")
    ? new Response(JSON.stringify(sources))
    : new Response(null, { status: 404 })));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><Sync /></QueryClientProvider>);

  const timestamp = await screen.findByText(new Date(snapshot).toLocaleString());
  expect(timestamp).toHaveAttribute("datetime", snapshot);
  expect(screen.getByText(`${(59424).toLocaleString()} entries`)).toBeInTheDocument();
  expect(screen.getByText('ETag "revision-1"')).toBeInTheDocument();
});
