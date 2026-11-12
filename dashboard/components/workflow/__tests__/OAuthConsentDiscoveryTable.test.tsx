/**
 * Gate 2 validation slice — the minimal, read-only OAuth consent discovery
 * table. Deliberately separate from ResourceList/WorkflowReviewPage: those
 * render KEEP/REVOKE/ESCALATE/IGNORE action buttons and a risk badge for
 * every resource in a workflow, which would put a non-functional "Revoke"
 * button next to a control that is explicitly not executable
 * (IDENTITY_OAUTH_APP_CONSENT_DISCOVERY, is_executable=False). This
 * component only ever shows Application / Consented by / Permissions / Date
 * -- no risk, no score, no action, no recommendation.
 */

import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import React from "react";

import { OAuthConsentDiscoveryTable } from "../OAuthConsentDiscoveryTable";

const mockUseWorkflowReview = jest.fn();

jest.mock("@/lib/api/hooks", () => ({
  useWorkflowReview: (...args: any[]) => mockUseWorkflowReview(...args),
}));

jest.mock("@/components/ui", () => {
  const React = require("react");
  return {
    Card: ({ children, className }: any) =>
      React.createElement("div", { "data-testid": "card", className }, children),
    ErrorState: ({ message }: any) => React.createElement("div", { "data-testid": "error-state" }, message),
    TableSkeleton: () => React.createElement("div", { "data-testid": "table-skeleton" }),
  };
});

function discoveryResource(overrides: Record<string, unknown> = {}) {
  return {
    control_id: "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY",
    resource_id: "grant-1",
    resource_type: "SERVICE_PRINCIPAL",
    title: "Contoso App",
    subtitle: "Principal",
    risk_level: "DISCOVERY",
    risk_explanation: "Discovered via the delegated OAuth consent inventory.",
    risk_drivers: [],
    recommended_action: "REVIEW",
    facts: [
      { label: "Application", value: "Contoso App" },
      { label: "Consented by", value: "Jane Doe" },
      { label: "Permissions", value: "Mail.Read, User.Read" },
      { label: "Date", value: "Unknown" },
    ],
    evidence: {},
    evidence_hash: "hash-1",
    compliance_result_id: 1,
    delta_state: null,
    previous_decision: null,
    previous_reviewed_by: null,
    previous_reviewed_at: null,
    ...overrides,
  };
}

function illicitGrantResource() {
  return {
    control_id: "IDENTITY_ILLICIT_CONSENT_GRANTS",
    resource_id: "grant-9",
    resource_type: "SERVICE_PRINCIPAL",
    title: "Risky App",
    subtitle: null,
    risk_level: "CRITICAL",
    risk_explanation: "",
    risk_drivers: [],
    recommended_action: "REVOKE",
    facts: [],
    evidence: {},
    evidence_hash: "hash-9",
    compliance_result_id: 2,
    delta_state: null,
    previous_decision: null,
    previous_reviewed_by: null,
    previous_reviewed_at: null,
  };
}

beforeEach(() => {
  mockUseWorkflowReview.mockReset();
});

test("shows a loading skeleton while fetching", () => {
  mockUseWorkflowReview.mockReturnValue({ data: null, loading: true, error: null });
  render(<OAuthConsentDiscoveryTable />);
  expect(screen.getByTestId("table-skeleton")).toBeInTheDocument();
});

test("shows an error state on failure", () => {
  mockUseWorkflowReview.mockReturnValue({ data: null, loading: false, error: "Request failed" });
  render(<OAuthConsentDiscoveryTable />);
  expect(screen.getByTestId("error-state")).toHaveTextContent("Request failed");
});

test("renders exactly the four-column contract: Application, Consented by, Permissions, Date", () => {
  mockUseWorkflowReview.mockReturnValue({
    data: { resources: [discoveryResource()] },
    loading: false,
    error: null,
  });
  render(<OAuthConsentDiscoveryTable />);

  expect(screen.getByText("Application")).toBeInTheDocument();
  expect(screen.getByText("Consented by")).toBeInTheDocument();
  expect(screen.getByText("Permissions")).toBeInTheDocument();
  expect(screen.getByText("Date")).toBeInTheDocument();

  expect(screen.getByText("Contoso App")).toBeInTheDocument();
  expect(screen.getByText("Jane Doe")).toBeInTheDocument();
  expect(screen.getByText("Mail.Read, User.Read")).toBeInTheDocument();
});

test("shows Unknown for a row with no confirmed date, not a blank cell", () => {
  mockUseWorkflowReview.mockReturnValue({
    data: { resources: [discoveryResource()] },
    loading: false,
    error: null,
  });
  render(<OAuthConsentDiscoveryTable />);

  const row = screen.getByText("Contoso App").closest("tr");
  expect(row).toHaveTextContent("Unknown");
});

test("filters out resources belonging to other controls, e.g. illicit-consent-grants", () => {
  mockUseWorkflowReview.mockReturnValue({
    data: { resources: [discoveryResource(), illicitGrantResource()] },
    loading: false,
    error: null,
  });
  render(<OAuthConsentDiscoveryTable />);

  expect(screen.getByText("Contoso App")).toBeInTheDocument();
  expect(screen.queryByText("Risky App")).not.toBeInTheDocument();
});

test("shows a legitimate empty state, not a generic 'no data' message, when there are no grants", () => {
  mockUseWorkflowReview.mockReturnValue({
    data: { resources: [] },
    loading: false,
    error: null,
  });
  render(<OAuthConsentDiscoveryTable />);

  expect(screen.getByTestId("discovery-empty-state")).toHaveTextContent(
    /no delegated oauth application grants were found/i,
  );
});

test("never renders a risk badge, score, or action button", () => {
  mockUseWorkflowReview.mockReturnValue({
    data: { resources: [discoveryResource()] },
    loading: false,
    error: null,
  });
  render(<OAuthConsentDiscoveryTable />);

  expect(screen.queryByRole("button")).not.toBeInTheDocument();
  expect(screen.queryByText(/critical|high|medium|low/i)).not.toBeInTheDocument();
  expect(screen.queryByText(/revoke/i)).not.toBeInTheDocument();
});

test("does not claim a 90-day window in its copy", () => {
  mockUseWorkflowReview.mockReturnValue({
    data: { resources: [discoveryResource()] },
    loading: false,
    error: null,
  });
  render(<OAuthConsentDiscoveryTable />);

  expect(screen.queryByText(/90 days/i)).not.toBeInTheDocument();
});
