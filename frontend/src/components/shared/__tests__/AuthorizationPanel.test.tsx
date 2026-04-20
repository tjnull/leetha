import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AuthorizationPanel } from "@/components/shared/AuthorizationPanel";

vi.mock("@/lib/api", async () => ({
  authHeaders: (h: Record<string, string>) => h,
}));

describe("AuthorizationPanel", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: true, status: 200, json: async () => ({ authorization: "approved" }),
    } as Response)));
  });

  it("renders the current badge", () => {
    render(<AuthorizationPanel
      mac="aa:bb:cc:dd:ee:01"
      current="unapproved"
      authorizedBy={null}
      authorizedAt={null}
    />);
    expect(screen.getByText("Unapproved")).toBeInTheDocument();
  });

  it("shows authorized_by and authorized_at when present", () => {
    render(<AuthorizationPanel
      mac="aa:bb:cc:dd:ee:01"
      current="approved"
      authorizedBy="alice"
      authorizedAt="2026-04-19T12:00:00Z"
    />);
    expect(screen.getByText(/by alice/i)).toBeInTheDocument();
  });

  it("Approve button is disabled when already approved", () => {
    render(<AuthorizationPanel
      mac="aa:bb:cc:dd:ee:01"
      current="approved"
      authorizedBy={null}
      authorizedAt={null}
    />);
    expect(screen.getByRole("button", { name: /approve/i })).toBeDisabled();
  });

  it("Approve button fires POST /approve with optional reason", async () => {
    const fetchSpy = vi.fn(async () => ({
      ok: true, status: 200, json: async () => ({ authorization: "approved" }),
    } as Response));
    vi.stubGlobal("fetch", fetchSpy);

    render(<AuthorizationPanel
      mac="aa:bb:cc:dd:ee:01"
      current="unapproved"
      authorizedBy={null}
      authorizedAt={null}
    />);

    await userEvent.type(screen.getByPlaceholderText(/reason/i), "onboard");
    await userEvent.click(screen.getByRole("button", { name: /approve/i }));

    await waitFor(() => expect(fetchSpy).toHaveBeenCalled());
    const [url, opts] = fetchSpy.mock.calls[0];
    expect(String(url)).toMatch(/\/api\/devices\/.*\/approve$/);
    expect(JSON.parse((opts as RequestInit).body as string)).toEqual({ reason: "onboard" });
  });

  it("Reject button fires /reject", async () => {
    const fetchSpy = vi.fn(async () => ({
      ok: true, status: 200, json: async () => ({}),
    } as Response));
    vi.stubGlobal("fetch", fetchSpy);

    render(<AuthorizationPanel
      mac="aa:bb:cc:dd:ee:01"
      current="unapproved"
      authorizedBy={null}
      authorizedAt={null}
    />);

    await userEvent.click(screen.getByRole("button", { name: /reject/i }));
    await waitFor(() => expect(fetchSpy).toHaveBeenCalled());
    expect(String(fetchSpy.mock.calls[0][0])).toMatch(/\/reject$/);
  });

  it("Revoke button is disabled when already unapproved", () => {
    render(<AuthorizationPanel
      mac="aa:bb:cc:dd:ee:01"
      current="unapproved"
      authorizedBy={null}
      authorizedAt={null}
    />);
    expect(screen.getByRole("button", { name: /revoke/i })).toBeDisabled();
  });
});
