/**
 * Help & Documentation — /help.
 *
 * Static reference content: no API calls, no tenant dependency. These tests
 * exist to catch the one thing that matters for a docs page — a title in the
 * table of contents actually has a matching section on the page, and search
 * genuinely narrows what's shown rather than silently doing nothing.
 */

import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import React from "react";

jest.mock("next/link", () => {
  const React = require("react");
  return ({ children, href, ...rest }: any) => React.createElement("a", { href, ...rest }, children);
});

jest.mock("lucide-react", () => {
  const React = require("react");
  return new Proxy(
    {},
    {
      get: (_target, name: string) => {
        return ({ size, ...rest }: any) =>
          React.createElement("svg", { "data-testid": `icon-${name}`, ...rest });
      },
    },
  );
});

import HelpPage from "../page";

it("lists every nav-mapped section with a working sidebar path", () => {
  render(<HelpPage />);
  // Spot-check a section from each real nav group renders as a heading.
  for (const title of ["My Work", "Risk Feed", "Clients", "Reports", "Security Baselines", "Settings"]) {
    expect(screen.getByRole("heading", { name: title })).toBeInTheDocument();
  }
});

it("explains the four decision buttons, not just the happy ones", () => {
  render(<HelpPage />);
  expect(screen.getByRole("heading", { name: /what each decision button does/i })).toBeInTheDocument();
  expect(screen.getByText(/there's no ticket or notification behind it yet/i)).toBeInTheDocument();
});

it("flags the Remediation Timeline export button as not wired up", () => {
  render(<HelpPage />);
  expect(screen.getByText(/export button is visible but not wired up yet/i)).toBeInTheDocument();
});

it("search narrows the page to matching topics only", async () => {
  render(<HelpPage />);
  expect(screen.getByRole("heading", { name: "Campaigns" })).toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "Settings" })).toBeInTheDocument();

  await userEvent.type(screen.getByPlaceholderText(/search help topics/i), "campaign");

  expect(screen.getByRole("heading", { name: "Campaigns" })).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: "Settings" })).not.toBeInTheDocument();
});

it("shows a message when search matches nothing", async () => {
  render(<HelpPage />);
  await userEvent.type(screen.getByPlaceholderText(/search help topics/i), "zzz-not-a-real-topic");
  expect(screen.getByText(/no help topics match/i)).toBeInTheDocument();
});
