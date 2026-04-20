import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { AuthorizationBadge } from "@/components/AuthorizationBadge";

describe("AuthorizationBadge", () => {
  it("renders 'Approved' for approved state", () => {
    render(<AuthorizationBadge value="approved" />);
    expect(screen.getByText("Approved")).toBeInTheDocument();
  });

  it("renders 'Unapproved' for unapproved state", () => {
    render(<AuthorizationBadge value="unapproved" />);
    expect(screen.getByText("Unapproved")).toBeInTheDocument();
  });

  it("renders 'Rejected' for rejected state", () => {
    render(<AuthorizationBadge value="rejected" />);
    expect(screen.getByText("Rejected")).toBeInTheDocument();
  });

  it("defaults to 'Unapproved' when value is null", () => {
    render(<AuthorizationBadge value={null} />);
    expect(screen.getByText("Unapproved")).toBeInTheDocument();
  });

  it("defaults to 'Unapproved' when value is undefined", () => {
    render(<AuthorizationBadge value={undefined} />);
    expect(screen.getByText("Unapproved")).toBeInTheDocument();
  });
});
