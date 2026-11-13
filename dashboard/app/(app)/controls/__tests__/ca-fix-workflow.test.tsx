/**
 * Live run 2026-11-13, defect L11: "Review & Fix" on a Conditional Access card called
 * POST /api/v1/control/apply with mode "enforced", which bypassed approval, approval
 * expiry and the preflight checks and created an ENFORCED policy. A CA fix from this
 * page must go through the same approve -> execute workflow as the Risk Feed.
 */
import "@testing-library/jest-dom";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";

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
  mocked.getControlState.mockResolvedValue({ control_id: "x", status: "not_configured" });
  mocked.approveByResult.mockResolvedValue({});
  mocked.executeRemediation.mockResolvedValue({ status: "success", verified: true });
});

async function reviewAndFixLegacyAuth() {
  render(<ControlsPage />);
  const card = (await screen.findByText("Block Legacy Authentication")).closest("div[class]")!;
  let cardRoot: HTMLElement | null = card as HTMLElement;
  while (cardRoot && !cardRoot.querySelector("button")) cardRoot = cardRoot.parentElement;
  fireEvent.click(cardRoot!.querySelector("button")!);
  const dialog = await screen.findByRole("dialog");
  fireEvent.click(within(dialog).getByRole("button", { name: /review & fix/i }));
}

it("approves and executes the CA finding through the remediation workflow", async () => {
  await reviewAndFixLegacyAuth();

  await waitFor(() => expect(mocked.executeRemediation).toHaveBeenCalledWith(410));
  expect(mocked.approveByResult).toHaveBeenCalledWith(410, "tenant-1");
  expect(mocked.approveByResult.mock.invocationCallOrder[0]).toBeLessThan(
    mocked.executeRemediation.mock.invocationCallOrder[0],
  );
});

it("never calls the direct control-apply endpoint", async () => {
  await reviewAndFixLegacyAuth();

  await waitFor(() => expect(mocked.executeRemediation).toHaveBeenCalled());
  expect(mocked.applyControl).not.toHaveBeenCalled();
});
