import "@testing-library/jest-dom";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import TenantDetailPage from "../page";
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
jest.mock("recharts", () => {
  const React = require("react");
  const Stub = ({ children }: any) => React.createElement("div", null, children);
  return new Proxy({}, { get: () => Stub });
});
jest.mock("next/navigation", () => ({ useRouter: () => ({ push: jest.fn() }) }));
jest.mock("@/lib/auth-context", () => ({
  useAuth: () => ({
    tenants: [{ tenant_id: "tenant-1" }],
    tenantId: "tenant-1",
    setActiveTenantId: jest.fn(),
  }),
}));

const mockRefetch = jest.fn();
const mockFinding = {
  id: 7,
  tenant_id: "tenant-1",
  control_id: "IDENTITY_USER_NO_MFA",
  passed: false,
  severity: "HIGH",
  decision_status: "APPROVED",
  evaluated_at: "2026-11-13T11:26:28Z",
  evidence: {},
};

jest.mock("@/lib/api/hooks", () => ({
  useExecutiveSummary: () => ({ data: null, isLoading: false, error: null, refetch: jest.fn() }),
  usePostureTrend: () => ({ data: [], isLoading: false, error: null }),
  useComplianceResults: () => ({ data: [mockFinding], isLoading: false, error: null, refetch: mockRefetch }),
}));
jest.mock("@/lib/api/endpoints", () => ({
  executeRemediation: jest.fn(),
  approveByResult: jest.fn(),
}));

const mocked = ep as unknown as Record<string, jest.Mock>;

beforeEach(() => jest.clearAllMocks());

async function clickExecute() {
  render(<TenantDetailPage params={{ id: "tenant-1" }} />);
  fireEvent.click(await screen.findByRole("button", { name: /execute/i }));
}

it("shows the failure when execute resolves with a non-success status", async () => {
  mocked.executeRemediation.mockResolvedValue({ status: "failed", reason: "GRAPH_ERROR" });
  await clickExecute();
  expect(await screen.findByText(/Execution failed: GRAPH_ERROR/)).toBeInTheDocument();
  expect(mockRefetch).not.toHaveBeenCalled();
});

it("shows the error when execute throws", async () => {
  mocked.executeRemediation.mockRejectedValue(new Error("Forbidden"));
  await clickExecute();
  expect(await screen.findByText(/Forbidden/)).toBeInTheDocument();
});

it("refetches without an error on success", async () => {
  mocked.executeRemediation.mockResolvedValue({ status: "success" });
  await clickExecute();
  await waitFor(() => expect(mockRefetch).toHaveBeenCalled());
  expect(screen.queryByText(/Execution failed/)).not.toBeInTheDocument();
});

it.each(["already_compliant", "already_resolved"])("treats %s as no error and refetches", async (status) => {
  mocked.executeRemediation.mockResolvedValue({ status });
  await clickExecute();
  await waitFor(() => expect(mockRefetch).toHaveBeenCalled());
  expect(screen.queryByText(/Execution failed/)).not.toBeInTheDocument();
});
