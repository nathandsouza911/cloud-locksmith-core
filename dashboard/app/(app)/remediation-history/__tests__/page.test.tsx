import "@testing-library/jest-dom";
import { fireEvent, render, screen } from "@testing-library/react";
import RemediationHistoryPage from "../page";

const mockDownload = jest.fn();
jest.mock("@/components/remediation/ChangeRecordPanel", () => ({
  __esModule: true,
  default: ({ complianceResultId }: { complianceResultId: number }) =>
    require("react").createElement("div", { "data-testid": "change-panel" }, `record ${complianceResultId}`),
  downloadChangeRecords: () => mockDownload(),
}));

jest.mock("@/lib/api/endpoints", () => ({ rollbackRemediation: jest.fn() }));
jest.mock("@/lib/api/hooks", () => ({
  useRemediationHistory: () => ({
    data: [
      {
        compliance_result_id: 9,
        control_id: "CA_LEGACY_AUTH_BLOCK",
        resource_id: "t",
        resource_label: "Tenant",
        status: "SUCCESS",
        executed_at: "2026-11-13T12:00:00Z",
        can_rollback: true,
        snapshot_available: true,
      },
    ],
    loading: false,
    error: null,
    refetch: jest.fn(),
  }),
}));

test("View change opens the change record for that row", () => {
  render(<RemediationHistoryPage />);
  expect(screen.queryByTestId("change-panel")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: /view change/i }));
  expect(screen.getByTestId("change-panel")).toHaveTextContent("record 9");
});

test("Export change records downloads the tenant's records", () => {
  mockDownload.mockResolvedValue(undefined);
  render(<RemediationHistoryPage />);
  fireEvent.click(screen.getByRole("button", { name: /export change records/i }));
  expect(mockDownload).toHaveBeenCalled();
});
