/**
 * Sprint 3 — Workflow Library.
 *
 * Informational, read-only catalogue of workflow types the platform can run.
 * Tenant-neutral: does not depend on the currently selected tenant.
 */

import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import React from "react";

const mockUseWorkflowLibrary = jest.fn();

jest.mock("next/navigation", () => ({
  useRouter: () => ({ push: jest.fn(), replace: jest.fn() }),
}));

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

jest.mock("@/lib/api/hooks", () => ({
  useWorkflowLibrary: () => mockUseWorkflowLibrary(),
}));

import WorkflowsPage from "../page";

const OAUTH_WORKFLOW = {
  id: "OAUTH_REVIEW",
  key: "oauth-review",
  name: "OAuth Review",
  description: "Review and revoke unapproved application consent grants.",
  category: "IDENTITY",
  icon: "KeyRound",
  supported_controls: ["IDENTITY_ILLICIT_CONSENT_GRANTS", "IDENTITY_RISKY_APPS"],
  resource_types: ["TENANT"],
  review_modes: ["PER_RESOURCE"],
  default_priority: "HIGH",
  display_order: 1,
  enabled: true,
  estimated_effort: { base_minutes: 5, minutes_per_item: 2, cap_minutes: 60 },
  supports_delta: true,
  supports_reports: true,
  supports_remediation: true,
  supports_verification: true,
  supported_reports: ["OAUTH_SUMMARY"],
  review_philosophy: "Trust nothing that was granted without review.",
  typical_cadence: "MONTHLY",
  evidence_strategy: "MATERIAL_KEYS",
  recommended_role: "Security Analyst",
};

const GUEST_WORKFLOW = {
  ...OAUTH_WORKFLOW,
  id: "GUEST_REVIEW",
  key: "guest-review",
  name: "Guest Access Review",
  description: "Review external guests and remove stale access.",
  category: "ACCESS_CONTROL",
  icon: "UserPlus",
  supported_controls: ["ACCESS_STALE_GUESTS"],
  supports_delta: false,
  supports_reports: false,
  supports_remediation: false,
  supports_verification: false,
  typical_cadence: "QUARTERLY",
  recommended_role: "IT Admin",
};

function libraryResult(overrides: Record<string, unknown> = {}) {
  return {
    data: { workflows: [OAUTH_WORKFLOW, GUEST_WORKFLOW] },
    loading: false,
    error: null,
    refetch: jest.fn(),
    ...overrides,
  };
}

beforeEach(() => {
  mockUseWorkflowLibrary.mockReturnValue(libraryResult());
});

test("renders one card per workflow", () => {
  render(<WorkflowsPage />);
  expect(screen.getAllByTestId("workflow-card")).toHaveLength(2);
});

test("a workflow card shows name, description, category and cadence", () => {
  render(<WorkflowsPage />);
  const card = screen.getAllByTestId("workflow-card")[0];

  expect(card).toHaveTextContent("OAuth Review");
  expect(card).toHaveTextContent(/revoke unapproved application consent/i);
  expect(card).toHaveTextContent(/identity/i);
  expect(card).toHaveTextContent(/monthly/i);
});

test("a workflow card shows the recommended role and review philosophy", () => {
  render(<WorkflowsPage />);
  const card = screen.getAllByTestId("workflow-card")[0];

  expect(card).toHaveTextContent(/security analyst/i);
  expect(card).toHaveTextContent(/trust nothing that was granted without review/i);
});

test("a workflow card shows the supported control count and control ids", () => {
  render(<WorkflowsPage />);
  const card = screen.getAllByTestId("workflow-card")[0];

  expect(card).toHaveTextContent("2");
  expect(card).toHaveTextContent(/IDENTITY_ILLICIT_CONSENT_GRANTS/);
  expect(card).toHaveTextContent(/IDENTITY_RISKY_APPS/);
});

test("a workflow card shows estimated effort", () => {
  render(<WorkflowsPage />);
  const card = screen.getAllByTestId("workflow-card")[0];

  // base 5 min + 2 min/item is surfaced somewhere in the effort summary
  expect(card).toHaveTextContent(/5/);
  expect(card).toHaveTextContent(/2/);
});

test("capability badges are shown as active when true", () => {
  render(<WorkflowsPage />);
  const card = screen.getAllByTestId("workflow-card")[0]; // OAuth: all four true

  expect(card.querySelector('[data-testid="badge-delta-on"]')).toBeInTheDocument();
  expect(card.querySelector('[data-testid="badge-verification-on"]')).toBeInTheDocument();
  expect(card.querySelector('[data-testid="badge-reports-on"]')).toBeInTheDocument();
  expect(card.querySelector('[data-testid="badge-remediation-on"]')).toBeInTheDocument();
});

test("capability badges are greyed / off when false", () => {
  render(<WorkflowsPage />);
  const card = screen.getAllByTestId("workflow-card")[1]; // Guest: all four false

  expect(card.querySelector('[data-testid="badge-delta-off"]')).toBeInTheDocument();
  expect(card.querySelector('[data-testid="badge-verification-off"]')).toBeInTheDocument();
  expect(card.querySelector('[data-testid="badge-reports-off"]')).toBeInTheDocument();
  expect(card.querySelector('[data-testid="badge-remediation-off"]')).toBeInTheDocument();
});

test("resolves a known icon name to a lucide icon", () => {
  render(<WorkflowsPage />);
  const card = screen.getAllByTestId("workflow-card")[0];
  expect(card.querySelector('[data-testid="icon-KeyRound"]')).toBeInTheDocument();
});

test("falls back to a default icon for an unknown icon name", () => {
  mockUseWorkflowLibrary.mockReturnValue(
    libraryResult({
      data: {
        workflows: [{ ...OAUTH_WORKFLOW, icon: "TotallyMadeUpIconName" }],
      },
    }),
  );
  render(<WorkflowsPage />);
  const card = screen.getAllByTestId("workflow-card")[0];
  // Should not throw and should render *some* icon svg instead of crashing.
  expect(card.querySelector("svg")).toBeInTheDocument();
});

test("shows a loading state while the library is being fetched", () => {
  mockUseWorkflowLibrary.mockReturnValue({
    data: null,
    loading: true,
    error: null,
    refetch: jest.fn(),
  });

  render(<WorkflowsPage />);
  expect(screen.getByTestId("workflows-loading")).toBeInTheDocument();
});

test("surfaces an error instead of an empty library", () => {
  mockUseWorkflowLibrary.mockReturnValue({
    data: null,
    loading: false,
    error: "Request failed",
    refetch: jest.fn(),
  });

  render(<WorkflowsPage />);
  expect(screen.getByText(/request failed/i)).toBeInTheDocument();
});

test("shows an empty state when there are no workflows", () => {
  mockUseWorkflowLibrary.mockReturnValue(libraryResult({ data: { workflows: [] } }));

  render(<WorkflowsPage />);
  expect(screen.getByTestId("workflows-empty")).toBeInTheDocument();
  expect(screen.queryAllByTestId("workflow-card")).toHaveLength(0);
});
