import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import React from "react";

import { FloatingNotice } from "../FloatingNotice";

test("announces the message in a live region pinned to the viewport", () => {
  render(<FloatingNotice message="Changes are disabled in the demo." />);

  const notice = screen.getByRole("status");
  expect(notice).toHaveTextContent("Changes are disabled in the demo.");
  expect(notice).toHaveAttribute("aria-live", "polite");
  // Pinned to the viewport so it is visible wherever the user clicked.
  expect(notice.className).toMatch(/\bfixed\b/);
});

test("renders nothing without a message", () => {
  const { container } = render(<FloatingNotice message={null} />);
  expect(container).toBeEmptyDOMElement();
});
