import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PresencePanel } from "@/components/shared/PresencePanel";

vi.mock("@/lib/api", async () => ({
  authHeaders: (h: Record<string, string>) => h,
}));

describe("PresencePanel", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: true, status: 200, json: async () => ({}),
    } as Response)));
  });

  it("formats threshold helpfully", () => {
    render(<PresencePanel
      mac="aa:bb:cc:dd:ee:01"
      isOnline={true}
      offlineSince={null}
      thresholdSeconds={300}
    />);
    // The label text contains "5m" inside the font-mono span
    expect(screen.getByText(/Offline threshold/i)).toBeInTheDocument();
    const label = screen.getByText(/Offline threshold/i);
    expect(label.textContent).toMatch(/5m/);
  });

  it("shows Online label when isOnline=true", () => {
    render(<PresencePanel
      mac="aa:bb:cc:dd:ee:01"
      isOnline={true}
      offlineSince={null}
      thresholdSeconds={300}
    />);
    expect(screen.getByText("Online")).toBeInTheDocument();
  });

  it("preset button PATCHes presence_threshold_seconds", async () => {
    const fetchSpy = vi.fn(async () => ({
      ok: true, status: 200, json: async () => ({}),
    } as Response));
    vi.stubGlobal("fetch", fetchSpy);

    render(<PresencePanel
      mac="aa:bb:cc:dd:ee:01"
      isOnline={true}
      offlineSince={null}
      thresholdSeconds={300}
    />);

    await userEvent.click(screen.getByRole("button", { name: "1h" }));
    await waitFor(() => expect(fetchSpy).toHaveBeenCalled());
    const body = JSON.parse((fetchSpy.mock.calls[0][1] as RequestInit).body as string);
    expect(body).toEqual({ presence_threshold_seconds: 3600 });
  });

  it("does not PATCH when same preset is chosen twice (no-op)", async () => {
    const fetchSpy = vi.fn(async () => ({
      ok: true, status: 200, json: async () => ({}),
    } as Response));
    vi.stubGlobal("fetch", fetchSpy);

    render(<PresencePanel
      mac="aa:bb:cc:dd:ee:01"
      isOnline={true}
      offlineSince={null}
      thresholdSeconds={300}
    />);

    await userEvent.click(screen.getByRole("button", { name: "5m" }));
    // 5m === current threshold — should NOT fire a request
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
