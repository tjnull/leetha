import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { PresenceDot } from "@/components/PresenceDot";

describe("PresenceDot", () => {
  it("tooltip says 'Online' when online", () => {
    render(<PresenceDot isOnline={true} />);
    const dot = screen.getByLabelText("Online");
    expect(dot).toBeInTheDocument();
    expect(dot).toHaveAttribute("title", "Online");
  });

  it("tooltip says 'Offline' when offline without timestamp", () => {
    render(<PresenceDot isOnline={false} />);
    expect(screen.getByLabelText("Offline")).toBeInTheDocument();
  });

  it("tooltip shows duration when offlineSince present", () => {
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    render(<PresenceDot isOnline={false} offlineSince={fiveMinAgo} />);
    const dot = screen.getByLabelText(/offline for/i);
    const title = dot.getAttribute("title") ?? "";
    expect(title).toMatch(/Offline for (4|5|6)m/);
  });

  it("tooltip shows '<1m' when just offline", () => {
    const justNow = new Date(Date.now() - 10 * 1000).toISOString();
    render(<PresenceDot isOnline={false} offlineSince={justNow} />);
    expect(screen.getByLabelText("Offline for <1m")).toBeInTheDocument();
  });

  it("tooltip shows hours when offline more than 1h", () => {
    const twoHrAgo = new Date(Date.now() - 2 * 3600 * 1000).toISOString();
    render(<PresenceDot isOnline={false} offlineSince={twoHrAgo} />);
    expect(screen.getByLabelText(/Offline for 2h/)).toBeInTheDocument();
  });

  it("applies online styling", () => {
    const { container } = render(<PresenceDot isOnline={true} />);
    expect((container.firstChild as HTMLElement).className).toMatch(/emerald/);
  });

  it("applies offline styling", () => {
    const { container } = render(<PresenceDot isOnline={false} />);
    expect((container.firstChild as HTMLElement).className).toMatch(/slate/);
  });
});
