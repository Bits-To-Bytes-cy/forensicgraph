import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import App from "./App";

describe("ForensicGraph shell", () => {
  it("renders the Phase 0 platform status", () => {
    render(
      <MemoryRouter>
        <App />
      </MemoryRouter>,
    );
    expect(screen.getByText("Platform shell ready")).toBeInTheDocument();
  });
});
