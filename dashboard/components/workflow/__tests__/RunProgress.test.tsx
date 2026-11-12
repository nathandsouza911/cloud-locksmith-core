/**
 * Sprint 4 — RunProgress.
 *
 * Resource-driven progress display: "N resources · N reviewed · N remaining
 * · N% complete", plus a bar. Never phrased as "Step X of Y" — progress is
 * derived from the count of resources actually reviewed, not workflow stage
 * position.
 */

import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import React from "react";

import { RunProgress } from "../RunProgress";

test("shows total, reviewed, remaining and percent complete", () => {
  render(<RunProgress total={14} reviewed={10} />);

  expect(screen.getByText(/14 resources/i)).toBeInTheDocument();
  expect(screen.getByText(/10 reviewed/i)).toBeInTheDocument();
  expect(screen.getByText(/4 remaining/i)).toBeInTheDocument();
  expect(screen.getByText(/71% complete/i)).toBeInTheDocument();
});

test("handles the zero-resource case as 100% complete without dividing by zero", () => {
  render(<RunProgress total={0} reviewed={0} />);

  expect(screen.getByText(/0 resources/i)).toBeInTheDocument();
  expect(screen.getByText(/100% complete/i)).toBeInTheDocument();
  expect(screen.queryByText(/NaN/i)).not.toBeInTheDocument();
  expect(screen.queryByText(/Infinity/i)).not.toBeInTheDocument();
});

test("never phrases progress as a step count", () => {
  render(<RunProgress total={14} reviewed={10} />);
  expect(screen.queryByText(/step \d+ of \d+/i)).not.toBeInTheDocument();
});

test("renders a progress bar reflecting the percent complete", () => {
  render(<RunProgress total={20} reviewed={5} />);
  const bar = screen.getByTestId("run-progress-bar");
  expect(bar).toHaveStyle({ width: "25%" });
});
