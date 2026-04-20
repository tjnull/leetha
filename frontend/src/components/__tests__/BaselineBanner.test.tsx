import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BaselineBanner } from "@/components/BaselineBanner";

vi.mock("@/lib/api", async () => ({
  authHeaders: (h: Record<string, string>) => h,
}));

function withQueryClient(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={qc}>{ui}</QueryClientProvider>;
}

function stubStatus(status: {
  approved: number; unapproved: number; rejected: number;
  last_baseline_at: string | null;
}) {
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    if (String(url).includes("/api/baseline/status")) {
      return { ok: true, status: 200, json: async () => status } as Response;
    }
    return { ok: true, status: 200, json: async () => ({ touched: 0 }) } as Response;
  }));
}

describe("BaselineBanner", () => {
  beforeEach(() => {
    vi.useRealTimers();
  });

  it("renders when approved < 5 and no prior baseline", async () => {
    stubStatus({ approved: 1, unapproved: 10, rejected: 0, last_baseline_at: null });
    render(withQueryClient(<BaselineBanner />));
    await waitFor(() => {
      expect(screen.getByText(/Authorization baseline not set/i)).toBeInTheDocument();
    });
  });

  it("hidden when a baseline has already been set", async () => {
    stubStatus({
      approved: 1, unapproved: 10, rejected: 0,
      last_baseline_at: "2026-04-10T00:00:00Z",
    });
    const { container } = render(withQueryClient(<BaselineBanner />));
    await new Promise((r) => setTimeout(r, 100));
    expect(container.querySelector("[class*='amber']")).toBeNull();
  });

  it("hidden when no unapproved devices exist", async () => {
    stubStatus({ approved: 0, unapproved: 0, rejected: 0, last_baseline_at: null });
    const { container } = render(withQueryClient(<BaselineBanner />));
    await new Promise((r) => setTimeout(r, 100));
    expect(container.querySelector("[class*='amber']")).toBeNull();
  });

  it("clicking 'Set baseline' calls POST /api/baseline/set", async () => {
    const spy = vi.fn(async (url: string) => {
      if (String(url).includes("/api/baseline/status")) {
        return {
          ok: true, status: 200,
          json: async () => ({ approved: 1, unapproved: 5, rejected: 0, last_baseline_at: null }),
        } as Response;
      }
      return { ok: true, status: 200, json: async () => ({ touched: 5 }) } as Response;
    });
    vi.stubGlobal("fetch", spy);

    render(withQueryClient(<BaselineBanner />));
    const button = await screen.findByRole("button", { name: /set baseline/i });
    await userEvent.click(button);
    await waitFor(() => {
      expect(spy.mock.calls.some(c => String(c[0]).includes("/api/baseline/set"))).toBe(true);
    });
  });
});
