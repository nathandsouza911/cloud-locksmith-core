import "@testing-library/jest-dom";
import { fireEvent, render, screen } from "@testing-library/react";
import CaCoveragePage from "../page";

const mockCsv = jest.fn();
jest.mock("@/lib/api/endpoints", () => ({ getCaCoverageCsv: () => mockCsv() }));

const covered = { status: "covered", policies: ["MFA admins"], reasons: [] };
const na = { status: "not_applicable", policies: [], reasons: [] };
jest.mock("@/lib/api/hooks", () => ({
  useCaCoverage: () => ({
    data: {
      generated_at: "2026-11-16T00:00:00Z",
      security_defaults_enabled: false,
      disclaimer: "Models policy assignment; it is not Microsoft's evaluation engine.",
      limits: ["PIM-eligible assignments are not modelled."],
      summary: {
        users: 2,
        mfa: { covered: 1, report_only: 0, gap: 1 },
        legacy_auth: { covered: 0, report_only: 0, gap: 2 },
        admin_mfa: { covered: 1, report_only: 0, gap: 0, not_applicable: 1 },
      },
      users: [
        {
          id: "a",
          display_name: "Ada Admin",
          user_principal_name: "ada@x",
          enabled: true,
          is_guest: false,
          is_admin: true,
          mfa: covered,
          legacy_auth: covered,
          admin_mfa: covered,
        },
        {
          id: "g",
          display_name: "Gwen Gap",
          user_principal_name: "gwen@x",
          enabled: true,
          is_guest: false,
          is_admin: false,
          mfa: { status: "gap", policies: [], reasons: ["Excluded from 'MFA all' by group 'CA exclusions'"] },
          legacy_auth: { status: "gap", policies: [], reasons: ["No policy blocks legacy authentication"] },
          admin_mfa: na,
        },
      ],
    },
    loading: false,
    error: null,
    refetch: jest.fn(),
  }),
}));

test("shows gap users by default and the reason when a row is opened", () => {
  render(<CaCoveragePage />);
  expect(screen.queryByText("Ada Admin")).not.toBeInTheDocument();
  fireEvent.click(screen.getByText("Gwen Gap"));
  expect(screen.getByText("Excluded from 'MFA all' by group 'CA exclusions'")).toBeInTheDocument();
});

test("unchecking the filter shows every user", () => {
  render(<CaCoveragePage />);
  fireEvent.click(screen.getByLabelText(/only users with a gap/i));
  expect(screen.getByText("Ada Admin")).toBeInTheDocument();
});

test("the page states what it does not evaluate", () => {
  render(<CaCoveragePage />);
  expect(screen.getByText(/not Microsoft's evaluation engine/)).toBeInTheDocument();
  expect(screen.getByText(/PIM-eligible/)).toBeInTheDocument();
});

test("Export CSV fetches the server CSV", () => {
  mockCsv.mockResolvedValue("id\n");
  global.URL.createObjectURL = jest.fn(() => "blob:x");
  render(<CaCoveragePage />);
  fireEvent.click(screen.getByRole("button", { name: /export csv/i }));
  expect(mockCsv).toHaveBeenCalled();
});
