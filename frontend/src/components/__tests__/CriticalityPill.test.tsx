import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { CriticalityPill } from "@/components/CriticalityPill";

describe("CriticalityPill", () => {
  it("renders the label for each level", () => {
    for (const level of ["low", "medium", "high", "critical"] as const) {
      const { unmount } = render(<CriticalityPill value={level} />);
      expect(screen.getByText(level)).toBeInTheDocument();
      unmount();
    }
  });

  it("renders nothing when value is null", () => {
    const { container } = render(<CriticalityPill value={null} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing when value is undefined", () => {
    const { container } = render(<CriticalityPill value={undefined} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("applies distinct styles per level", () => {
    const { rerender, container } = render(<CriticalityPill value="low" />);
    const lowClass = container.firstChild?.textContent ? (container.firstChild as HTMLElement).className : "";
    rerender(<CriticalityPill value="critical" />);
    const criticalClass = container.firstChild ? (container.firstChild as HTMLElement).className : "";
    expect(lowClass).not.toBe(criticalClass);
  });
});
