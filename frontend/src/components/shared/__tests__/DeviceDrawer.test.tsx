import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { DeviceDrawer } from "@/components/shared/DeviceDrawer";

afterEach(() => vi.unstubAllGlobals());

it("shows OUI provenance from the device detail evidence chain", async () => {
  const mac = "00:35:a9:00:00:01";
  const detail = {
    device: { mac, manufacturer: "Example Networks", device_type: "access_point" },
    evidence: {
      chain: [{
        source: "oui",
        method: "exact",
        certainty: 0.95,
        vendor: "Example Networks",
        category: "access_point",
        raw: {
          registry: "MA-L",
          sources: "IEEE+Wireshark",
          registrant_history: "Old Networks | Example Networks",
        },
      }, {
        source: "oui",
        method: "exact",
        certainty: 0.95,
        raw: { registry_only: true, registrant_raw: "IEEE Registration Authority" },
      }],
    },
  };
  vi.stubGlobal("fetch", vi.fn(async (url: string) => url.endsWith("/detail")
    ? new Response(JSON.stringify(detail))
    : new Response(null, { status: 404 })));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <DeviceDrawer mac={mac} open onClose={vi.fn()} />
    </QueryClientProvider>,
  );

  await userEvent.click(await screen.findByRole("tab", { name: "Evidence" }));
  expect(screen.getByText("MA-L")).toBeInTheDocument();
  expect(screen.getByText("IEEE+Wireshark")).toBeInTheDocument();
  expect(screen.getByText("Old Networks | Example Networks")).toBeInTheDocument();
  expect(screen.getByText("95%")).toBeInTheDocument();
  expect(screen.getByText("Registry match only")).toBeInTheDocument();
  expect(screen.getByText("IEEE Registration Authority")).toBeInTheDocument();
});
