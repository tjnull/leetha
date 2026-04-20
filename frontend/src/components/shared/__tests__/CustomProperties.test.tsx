import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CustomProperties } from "@/components/shared/CustomProperties";

// Stub authHeaders
vi.mock("@/lib/api", async () => ({
  authHeaders: (h: Record<string, string>) => h,
}));

function mockFetchOk(bodyFactory: () => unknown) {
  return vi.fn(async (_url: string, opts?: RequestInit) => {
    const requestBody = opts?.body ? JSON.parse(opts.body as string) : {};
    return {
      ok: true,
      status: 200,
      json: async () => bodyFactory(),
      __requestBody: requestBody,
    } as unknown as Response;
  });
}

describe("CustomProperties", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", mockFetchOk(() => ({
      mac: "aa:bb:cc:dd:ee:01",
      owner: null, location: null, criticality: null,
      tags: [], notes: null,
    })));
  });

  it("renders initial owner + criticality values", () => {
    render(<CustomProperties
      mac="aa:bb:cc:dd:ee:01"
      initial={{
        owner: "alice", location: null,
        criticality: "high", tags: ["prod"], notes: null,
      }}
    />);
    expect((screen.getByLabelText(/owner/i) as HTMLInputElement).value).toBe("alice");
    expect(screen.getByText("prod")).toBeInTheDocument();
  });

  it("PATCH sends owner on blur when changed", async () => {
    const spyFetch = vi.fn(async () => ({
      ok: true, status: 200,
      json: async () => ({ owner: "bob" }),
    } as Response));
    vi.stubGlobal("fetch", spyFetch);

    render(<CustomProperties
      mac="aa:bb:cc:dd:ee:01"
      initial={{ owner: "alice", location: null, criticality: null, tags: [], notes: null }}
    />);
    const owner = screen.getByLabelText(/owner/i) as HTMLInputElement;
    await userEvent.clear(owner);
    await userEvent.type(owner, "bob");
    fireEvent.blur(owner);
    await waitFor(() => expect(spyFetch).toHaveBeenCalled());
    const call = spyFetch.mock.calls[0];
    const body = JSON.parse((call[1] as RequestInit).body as string);
    expect(body).toEqual({ owner: "bob" });
  });

  it("adds a new tag via Enter key", async () => {
    const spyFetch = vi.fn(async () => ({
      ok: true, status: 200,
      json: async () => ({ tags: ["prod", "core"] }),
    } as Response));
    vi.stubGlobal("fetch", spyFetch);

    render(<CustomProperties
      mac="aa:bb:cc:dd:ee:01"
      initial={{ owner: null, location: null, criticality: null, tags: ["prod"], notes: null }}
    />);
    const input = screen.getByPlaceholderText(/add tag/i);
    await userEvent.type(input, "core");
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() => expect(spyFetch).toHaveBeenCalled());
    const body = JSON.parse((spyFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(body).toEqual({ tags: ["prod", "core"] });
  });

  it("duplicate tag add is a no-op", async () => {
    const spyFetch = vi.fn(async () => ({
      ok: true, status: 200, json: async () => ({}),
    } as Response));
    vi.stubGlobal("fetch", spyFetch);

    render(<CustomProperties
      mac="aa:bb:cc:dd:ee:01"
      initial={{ owner: null, location: null, criticality: null, tags: ["prod"], notes: null }}
    />);
    const input = screen.getByPlaceholderText(/add tag/i);
    await userEvent.type(input, "prod");
    fireEvent.keyDown(input, { key: "Enter" });
    expect(spyFetch).not.toHaveBeenCalled();
  });

  it("removes a tag via the X button", async () => {
    const spyFetch = vi.fn(async () => ({
      ok: true, status: 200, json: async () => ({ tags: [] }),
    } as Response));
    vi.stubGlobal("fetch", spyFetch);

    render(<CustomProperties
      mac="aa:bb:cc:dd:ee:01"
      initial={{ owner: null, location: null, criticality: null, tags: ["prod"], notes: null }}
    />);
    const removeBtn = screen.getByLabelText("Remove tag prod");
    await userEvent.click(removeBtn);
    await waitFor(() => expect(spyFetch).toHaveBeenCalled());
    const body = JSON.parse((spyFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(body).toEqual({ tags: [] });
  });
});
