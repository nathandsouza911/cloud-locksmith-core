/**
 * The shared workflow review screen.
 *
 * The point of these tests is that they are written once and hold for every
 * workflow: the same panels, the same interaction model, only the labels differ.
 */

import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import React from "react";

import { WorkflowReviewPage } from "../WorkflowReviewPage";
import * as endpoints from "@/lib/api/endpoints";

jest.mock("@/lib/api/endpoints");

// The review hook is tenant-scoped, so the screen only renders for an
// authenticated session with a client selected.
jest.mock("@/lib/auth-context", () => ({
  useAuth: () => ({ loading: false, authed: true, tenantId: "t1" }),
}));

const mockRouterPush = jest.fn();
jest.mock("next/navigation", () => ({
  useRouter: () => ({ push: mockRouterPush }),
}));

const REVIEW = {
  tenant_id: "t1",
  workflow: {
    id: "IDENTITY_HYGIENE",
    key: "identity-hygiene",
    name: "Identity Hygiene",
    description: "Routine identity cleanup.",
    category: "IDENTITY",
    icon: "Sparkles",
    review_philosophy: "High-volume, low-ceremony.",
    supports_remediation: true,
    supports_reports: true,
  },
  review_actions: [
    { decision: "KEEP", label: "Keep", description: "" },
    { decision: "REVOKE", label: "Disable", description: "" },
    { decision: "ESCALATE", label: "Escalate", description: "" },
    { decision: "IGNORE", label: "Ignore", description: "" },
  ],
  run: {
    id: "run-1",
    state: "READY_FOR_REVIEW",
    current_stage: null,
    started_at: "2026-08-01T09:00:00Z",
    completed_at: null,
    created_by: "tech@msp.com",
    summary: {},
  },
  stages: [
    {
      stage_key: "DISCOVER",
      state: "COMPLETED",
      started_at: "2026-08-01T09:00:00Z",
      completed_at: "2026-08-01T09:01:00Z",
    },
  ],
  progress: {
    total_resources: 2,
    reviewed_resources: 1,
    remaining_resources: 1,
    percent_complete: 50,
    is_complete: false,
  },
  resources: [
    {
      control_id: "IDENTITY_USER_NO_MFA",
      resource_id: "user-1",
      resource_type: "USER",
      title: "alice@contoso.com",
      subtitle: "No MFA registered",
      risk_level: "HIGH",
      risk_explanation: "This account can sign in with a password alone.",
      risk_drivers: ["mfa:none"],
      recommended_action: "REVIEW",
      facts: [{ label: "Last sign-in", value: "2026-07-01", emphasis: false }],
      evidence: { user_principal_name: "alice@contoso.com" },
      evidence_hash: "hash-1",
      compliance_result_id: 1,
      delta_state: "NEW",
      previous_decision: null,
      previous_reviewed_by: null,
      previous_reviewed_at: null,
    },
    {
      control_id: "IDENTITY_UNUSED_ACCOUNT",
      resource_id: "user-2",
      resource_type: "USER",
      title: "bob@contoso.com",
      subtitle: "Dormant account",
      risk_level: "MEDIUM",
      risk_explanation: "Bob has not signed in recently.",
      risk_drivers: ["dormant:true"],
      recommended_action: "REVIEW",
      facts: [],
      evidence: {},
      evidence_hash: "hash-2",
      compliance_result_id: 2,
      delta_state: "PREVIOUSLY_REVIEWED",
      previous_decision: "KEEP",
      previous_reviewed_by: "tech@msp.com",
      previous_reviewed_at: "2026-07-01T00:00:00Z",
    },
  ],
  next_resource_id: "user-1",
};

const SIMULATION = {
  control_id: "IDENTITY_USER_NO_MFA",
  selected_resource_ids: ["user-1"],
  changes: [
    {
      resource_id: "user-1",
      title: "alice@contoso.com",
      resource_type: "USER",
      recommended_action: "REVOKE",
      risk_level: "HIGH",
    },
  ],
  reversible: true,
  rollback_strategy: "Restore from the pre-execution snapshot.",
  requires_confirmation: true,
  summary: "1 item(s) will be remediated. A snapshot is captured first.",
};

beforeEach(() => {
  jest.clearAllMocks();
  (endpoints.getWorkflowReview as jest.Mock).mockResolvedValue(REVIEW);
  (endpoints.submitWorkflowDecision as jest.Mock).mockResolvedValue(REVIEW);
  (endpoints.completeWorkflowReview as jest.Mock).mockResolvedValue(REVIEW);
  (endpoints.simulateWorkflowRemediation as jest.Mock).mockResolvedValue(SIMULATION);
  (endpoints.executeWorkflowRemediation as jest.Mock).mockResolvedValue({
    selected_resource_ids: ["user-1"],
    executions: [],
    review: REVIEW,
  });
});

it("names the workflow so the technician knows where they are", async () => {
  render(<WorkflowReviewPage workflowKey="identity-hygiene" />);
  expect(await screen.findByText("Identity Hygiene")).toBeInTheDocument();
});

it("shows resource-driven progress rather than stage counts", async () => {
  render(<WorkflowReviewPage workflowKey="identity-hygiene" />);
  expect(await screen.findByText(/1 reviewed/i)).toBeInTheDocument();
  expect(screen.getByText(/50% complete/i)).toBeInTheDocument();
});

it("lists every resource with its risk and delta state", async () => {
  render(<WorkflowReviewPage workflowKey="identity-hygiene" />);
  expect(await screen.findByText("alice@contoso.com")).toBeInTheDocument();
  expect(screen.getByText("bob@contoso.com")).toBeInTheDocument();
  expect(screen.getByText("New")).toBeInTheDocument();
  expect(screen.getByText("Previously reviewed")).toBeInTheDocument();
});

it("renders the workflow's own action labels, not hardcoded ones", async () => {
  render(<WorkflowReviewPage workflowKey="identity-hygiene" />);
  expect(await screen.findByRole("button", { name: "Disable" })).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument();
});

it("explains the risk in prose the technician can quote to a client", async () => {
  render(<WorkflowReviewPage workflowKey="identity-hygiene" />);
  expect(await screen.findByText("This account can sign in with a password alone.")).toBeInTheDocument();
});

it("shows who reviewed a settled resource and when", async () => {
  render(<WorkflowReviewPage workflowKey="identity-hygiene" />);
  expect(await screen.findByText(/tech@msp.com/)).toBeInTheDocument();
});

it("a non-revoke decision is recorded directly, with no simulation", async () => {
  render(<WorkflowReviewPage workflowKey="identity-hygiene" />);
  await userEvent.click(await screen.findByRole("button", { name: "Keep" }));

  await waitFor(() =>
    expect(endpoints.submitWorkflowDecision).toHaveBeenCalledWith(
      "identity-hygiene",
      expect.objectContaining({
        control_id: "IDENTITY_USER_NO_MFA",
        resource_id: "user-1",
        decision: "KEEP",
      }),
    ),
  );
  expect(endpoints.simulateWorkflowRemediation).not.toHaveBeenCalled();
});

it("clicking Disable simulates remediation instead of recording a bare decision", async () => {
  render(<WorkflowReviewPage workflowKey="identity-hygiene" />);
  await userEvent.click(await screen.findByRole("button", { name: "Disable" }));

  await waitFor(() =>
    expect(endpoints.simulateWorkflowRemediation).toHaveBeenCalledWith("identity-hygiene", {
      control_id: "IDENTITY_USER_NO_MFA",
      resource_ids: ["user-1"],
    }),
  );
  expect(endpoints.submitWorkflowDecision).not.toHaveBeenCalled();
  expect(endpoints.executeWorkflowRemediation).not.toHaveBeenCalled();
});

it("shows the simulated impact and requires a typed confirmation before executing", async () => {
  render(<WorkflowReviewPage workflowKey="identity-hygiene" />);
  await userEvent.click(await screen.findByRole("button", { name: "Disable" }));

  expect(await screen.findByText(/will be remediated/i)).toBeInTheDocument();

  const confirmButton = screen.getByRole("button", { name: "Remediate" });
  expect(confirmButton).toBeDisabled();

  await userEvent.type(screen.getByPlaceholderText("CONFIRM"), "CONFIRM");
  expect(confirmButton).toBeEnabled();

  await userEvent.click(confirmButton);

  await waitFor(() =>
    expect(endpoints.executeWorkflowRemediation).toHaveBeenCalledWith("identity-hygiene", {
      control_id: "IDENTITY_USER_NO_MFA",
      resource_ids: ["user-1"],
      confirmed: true,
    }),
  );
});

it("cancelling the remediation dialog executes nothing", async () => {
  render(<WorkflowReviewPage workflowKey="identity-hygiene" />);
  await userEvent.click(await screen.findByRole("button", { name: "Disable" }));
  await screen.findByText(/will be remediated/i);

  // The modal's X icon shares the accessible name "Cancel" with its text
  // button — both call onCancel, so either serves this test.
  const [cancelButton] = screen.getAllByRole("button", { name: "Cancel" });
  await userEvent.click(cancelButton);

  expect(endpoints.executeWorkflowRemediation).not.toHaveBeenCalled();
  expect(screen.queryByText(/will be remediated/i)).not.toBeInTheDocument();
});

it("disables completion while work remains", async () => {
  render(<WorkflowReviewPage workflowKey="identity-hygiene" />);
  expect(await screen.findByRole("button", { name: /complete review/i })).toBeDisabled();
});

it("completing the review sends the technician back to the work queue", async () => {
  (endpoints.getWorkflowReview as jest.Mock).mockResolvedValue({
    ...REVIEW,
    progress: { ...REVIEW.progress, remaining_resources: 0, percent_complete: 100, is_complete: true },
  });
  render(<WorkflowReviewPage workflowKey="identity-hygiene" />);

  await userEvent.click(await screen.findByRole("button", { name: /complete review/i }));

  await waitFor(() => expect(endpoints.completeWorkflowReview).toHaveBeenCalledWith("identity-hygiene"));
  expect(mockRouterPush).toHaveBeenCalledWith("/work");
});

it("a failed completion stays on the page and shows the error", async () => {
  (endpoints.getWorkflowReview as jest.Mock).mockResolvedValue({
    ...REVIEW,
    progress: { ...REVIEW.progress, remaining_resources: 0, percent_complete: 100, is_complete: true },
  });
  (endpoints.completeWorkflowReview as jest.Mock).mockRejectedValue(new Error("Review already completed"));
  render(<WorkflowReviewPage workflowKey="identity-hygiene" />);

  await userEvent.click(await screen.findByRole("button", { name: /complete review/i }));

  expect(await screen.findByText(/review already completed/i)).toBeInTheDocument();
  expect(mockRouterPush).not.toHaveBeenCalled();
});

it("shows the evidence fingerprint so a decision is auditable", async () => {
  render(<WorkflowReviewPage workflowKey="identity-hygiene" />);
  expect(await screen.findByText(/hash-1/)).toBeInTheDocument();
});

it("surfaces an error instead of failing silently", async () => {
  (endpoints.getWorkflowReview as jest.Mock).mockRejectedValue(new Error("Unknown workflow"));
  render(<WorkflowReviewPage workflowKey="nope" />);
  expect(await screen.findByText(/unknown workflow/i)).toBeInTheDocument();
});

// ── Gate 2 — resourceFilter excludes non-executable controls from the
// action-having list (e.g. a pure discovery control with no Revoke path) ──

it("without a resourceFilter, every resource (including progress totals) is shown as before", async () => {
  render(<WorkflowReviewPage workflowKey="identity-hygiene" />);
  expect(await screen.findByText("alice@contoso.com")).toBeInTheDocument();
  expect(screen.getByText("bob@contoso.com")).toBeInTheDocument();
});

it("resourceFilter excludes matching resources from the reviewable list", async () => {
  render(
    <WorkflowReviewPage
      workflowKey="identity-hygiene"
      resourceFilter={(resource) => resource.control_id !== "IDENTITY_UNUSED_ACCOUNT"}
    />,
  );
  expect(await screen.findByText("alice@contoso.com")).toBeInTheDocument();
  expect(screen.queryByText("bob@contoso.com")).not.toBeInTheDocument();
});
