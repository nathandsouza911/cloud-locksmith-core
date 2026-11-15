import "@testing-library/jest-dom";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import ChangeRecordPanel, { downloadChangeRecords } from "../ChangeRecordPanel";

const mockGet = jest.fn();
jest.mock("@/lib/api/endpoints", () => ({
  getChangeRecords: (params: unknown) => mockGet(params),
}));

const RECORD = {
  id: "r1",
  compliance_result_id: 5,
  control_id: "IDENTITY_UNUSED_ACCOUNT",
  resource: { type: "USER", id: "u1" },
  executed_by: "admin@contoso.example",
  executed_at: "2026-11-13T12:03:00+00:00",
  approval: {
    approved_by: "owner@contoso.example",
    approved_at: "2026-11-13T12:01:00+00:00",
    approval_mode: "MANUAL",
  },
  before: { accountEnabled: true },
  after: { accountEnabled: false },
  changes: [{ setting: "accountEnabled", before: true, after: false }],
  verification: { verified: true, scope: null },
  rollback: null,
};

beforeEach(() => jest.resetAllMocks());

test("shows each changed setting with its before and after value", async () => {
  mockGet.mockResolvedValue({ tenant_id: "t", generated_at: "x", records: [RECORD] });
  render(<ChangeRecordPanel complianceResultId={5} onClose={() => {}} />);

  const table = await screen.findByRole("table", { name: /changed settings/i });
  const row = within(table).getByText("accountEnabled").closest("tr")!;
  expect(within(row).getByText("true")).toBeInTheDocument();
  expect(within(row).getByText("false")).toBeInTheDocument();
  expect(mockGet).toHaveBeenCalledWith({ compliance_result_id: 5 });
});

test("shows who approved and executed, verification and rollback", async () => {
  mockGet.mockResolvedValue({
    tenant_id: "t",
    generated_at: "x",
    records: [
      {
        ...RECORD,
        rollback: {
          rolled_back_at: "2026-11-13T13:00:00+00:00",
          requested_by: "owner@contoso.example",
          reason: "test",
        },
      },
    ],
  });
  render(<ChangeRecordPanel complianceResultId={5} onClose={() => {}} />);

  expect(await screen.findByText("admin@contoso.example")).toBeInTheDocument();
  expect(screen.getAllByText("owner@contoso.example").length).toBeGreaterThan(0);
  expect(screen.getByText(/verified/i)).toBeInTheDocument();
  expect(screen.getByText(/rolled back/i)).toBeInTheDocument();
});

test("says when the executor was not recorded instead of guessing", async () => {
  mockGet.mockResolvedValue({
    tenant_id: "t",
    generated_at: "x",
    records: [{ ...RECORD, executed_by: null, changes: [] }],
  });
  render(<ChangeRecordPanel complianceResultId={5} onClose={() => {}} />);
  expect(await screen.findByText(/not recorded/i)).toBeInTheDocument();
  expect(screen.getByText(/no setting-level changes recorded/i)).toBeInTheDocument();
});

test("download saves the export as a JSON file", async () => {
  mockGet.mockResolvedValue({ tenant_id: "t", generated_at: "x", records: [RECORD] });
  const createObjectURL = jest.fn(() => "blob:x");
  const revokeObjectURL = jest.fn();
  Object.assign(URL, { createObjectURL, revokeObjectURL });
  const click = jest.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

  await downloadChangeRecords();

  expect(mockGet).toHaveBeenCalledWith({});
  expect(createObjectURL).toHaveBeenCalled();
  expect(click).toHaveBeenCalled();
  await waitFor(() => expect(revokeObjectURL).toHaveBeenCalledWith("blob:x"));
});

test("close button calls onClose", async () => {
  mockGet.mockResolvedValue({ tenant_id: "t", generated_at: "x", records: [RECORD] });
  const onClose = jest.fn();
  render(<ChangeRecordPanel complianceResultId={5} onClose={onClose} />);
  fireEvent.click(await screen.findByRole("button", { name: /close/i }));
  expect(onClose).toHaveBeenCalled();
});
