/**
 * Live run 2026-11-13, defect L17: after a verified report-only fix the Legacy
 * Authentication card still read "Not configured", because a report-only policy
 * leaves the finding failing. The card now shows "Report only" when the engine
 * manages an active audit-mode policy, and does not offer to apply it again.
 */
import "@testing-library/jest-dom";
import { render, screen, within } from "@testing-library/react";

import ControlsPage from "../page";
import * as ep from "@/lib/api/endpoints";

jest.mock("lucide-react", () => {
  const React = require("react");
  return new Proxy(
    {},
    {
      get:
        () =>
        ({ size, ...rest }: any) =>
          React.createElement("svg", rest),
    },
  );
});

jest.mock("@/lib/auth-context", () => ({
  useAuth: () => ({ tenantId: "tenant-1" }),
}));

const legacyFinding = {
  id: 410,
  tenant_id: "tenant-1",
  control_id: "CA_LEGACY_AUTH_BLOCK",
  passed: false,
  severity: "HIGH",
  evaluated_at: "2026-11-13T11:26:28Z",
  remediation_status: "PENDING",
  resource_type: "TENANT",
  resource_id: "tenant-1",
  evidence: {},
};

jest.mock("@/lib/api/hooks", () => ({
  useComplianceResults: () => ({ data: [legacyFinding], refetch: jest.fn(), isLoading: false, error: null }),
  useControlCapabilities: () => ({
    data: {
      CA_LEGACY_AUTH_BLOCK: {
        allowed: true,
        mode: "manual",
        reason: "",
        notes: "Microsoft supports creating and modifying Conditional Access policies.",
      },
    },
    isLoading: false,
    error: null,
  }),
}));

jest.mock("@/lib/api/endpoints", () => ({
  getControlState: jest.fn(),
  approveByResult: jest.fn(),
  executeRemediation: jest.fn(),
  applyControl: jest.fn(),
}));

const mocked = ep as unknown as Record<string, jest.Mock>;

beforeEach(() => {
  jest.clearAllMocks();
  mocked.getControlState.mockImplementation(async (controlId: string) =>
    controlId === "CA_LEGACY_AUTH_BLOCK"
      ? {
          control_id: controlId,
          tenant_id: "tenant-1",
          state: {
            mode: "audit",
            rollout_phase: "full",
            rollout_percentage: 100,
            target_group_id: null,
            policy_version: 1,
            status: "active",
            managed_policy_ids: ["policy-1"],
            last_applied_at: null,
            created_at: null,
            updated_at: null,
          },
          latest_snapshot: null,
        }
      : { control_id: controlId, tenant_id: "tenant-1", state: null, latest_snapshot: null },
  );
  mocked.approveByResult.mockResolvedValue({});
  mocked.executeRemediation.mockResolvedValue({ status: "success", verified: true });
});

function legacyCard(): HTMLElement {
  let node: HTMLElement | null = screen.getByText("Block Legacy Authentication");
  while (node && !node.querySelector("button")) node = node.parentElement;
  return node as HTMLElement;
}

it("shows a report-only policy as Report only and does not offer to apply it again", async () => {
  render(<ControlsPage />);
  await screen.findAllByText("REPORT ONLY");
  const card = legacyCard();
  expect(within(card).getByText("REPORT ONLY")).toBeInTheDocument();
  expect(within(card).queryByText("NOT CONFIGURED")).not.toBeInTheDocument();
  const button = within(card).getByRole("button", { name: /report-only applied/i });
  expect(button).toBeDisabled();
});
