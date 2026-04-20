import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { InventorySources } from "@/components/InventorySources";

vi.mock("@/lib/api", async () => ({
  authHeaders: (h: Record<string, string>) => h,
}));

describe("InventorySources", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: true, status: 200,
      json: async () => ({ imported: 3, flavor: "isc" }),
    } as Response)));
  });

  it("renders the DHCP importer card", () => {
    render(<InventorySources />);
    expect(screen.getByText(/Inventory Sources/i)).toBeInTheDocument();
    expect(screen.getByText(/DHCP lease file/i)).toBeInTheDocument();
  });

  it("uploads a lease file via multipart POST", async () => {
    const spy = vi.fn(async () => ({
      ok: true, status: 200,
      json: async () => ({ imported: 3, flavor: "isc" }),
    } as Response));
    vi.stubGlobal("fetch", spy);

    const { container } = render(<InventorySources />);
    const fileInput = container.querySelector("input[type='file']") as HTMLInputElement;
    const file = new File(["lease 1.1.1.1 {}\n"], "test.leases", { type: "text/plain" });
    await userEvent.upload(fileInput, file);
    await waitFor(() => expect(spy).toHaveBeenCalled());

    const [url, opts] = spy.mock.calls[0];
    expect(String(url)).toBe("/api/inventory/dhcp-leases/upload");
    expect((opts as RequestInit).method).toBe("POST");
    expect((opts as RequestInit).body).toBeInstanceOf(FormData);
  });

  it("shows success state after upload", async () => {
    const { container } = render(<InventorySources />);
    const fileInput = container.querySelector("input[type='file']") as HTMLInputElement;
    const file = new File(["x"], "test.leases");
    await userEvent.upload(fileInput, file);
    await waitFor(() => {
      expect(screen.getByText(/Imported 3 device/i)).toBeInTheDocument();
    });
  });

  it("shows error state on upload failure", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: false, status: 500, statusText: "Internal Server Error",
      json: async () => ({}),
    } as Response)));

    const { container } = render(<InventorySources />);
    const fileInput = container.querySelector("input[type='file']") as HTMLInputElement;
    const file = new File(["x"], "test.leases");
    await userEvent.upload(fileInput, file);
    await waitFor(() => {
      expect(screen.getByText(/500 Internal Server Error/i)).toBeInTheDocument();
    });
  });
});
