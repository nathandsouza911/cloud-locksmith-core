import "@testing-library/jest-dom";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import BreakGlassAccountsCard from "../BreakGlassAccountsCard";

const mockGet = jest.fn();
const mockRegister = jest.fn();
const mockRemove = jest.fn();

jest.mock("@/lib/api/endpoints", () => ({
  getBreakGlassAccounts: () => mockGet(),
  registerBreakGlassAccount: (user: string) => mockRegister(user),
  removeBreakGlassAccount: (id: number) => mockRemove(id),
}));

const ACCOUNT = {
  id: 7,
  user_external_id: "11111111-1111-1111-1111-111111111111",
  created_at: "2026-11-15T10:00:00",
};

function list(accounts: unknown[], canManage: boolean) {
  mockGet.mockResolvedValue({ accounts, can_manage: canManage });
}

beforeEach(() => {
  jest.resetAllMocks();
});

test("lists registered accounts", async () => {
  list([ACCOUNT], true);
  render(<BreakGlassAccountsCard />);
  expect(await screen.findByText(ACCOUNT.user_external_id)).toBeInTheDocument();
});

test("empty state explains that Conditional Access fixes are blocked", async () => {
  list([], true);
  render(<BreakGlassAccountsCard />);
  expect(await screen.findByText(/conditional access fixes are blocked/i)).toBeInTheDocument();
});

test("owner registers an account and sees the synced-account warning", async () => {
  list([], true);
  mockRegister.mockResolvedValue({ ...ACCOUNT, warnings: ["synced_from_on_premises"] });
  render(<BreakGlassAccountsCard />);

  const input = await screen.findByLabelText(/object id or upn/i);
  fireEvent.change(input, { target: { value: " bg1@contoso.example " } });
  list([ACCOUNT], true);
  fireEvent.click(screen.getByRole("button", { name: /register/i }));

  await waitFor(() => expect(mockRegister).toHaveBeenCalledWith("bg1@contoso.example"));
  expect(await screen.findByText(/synced from on-premises/i)).toBeInTheDocument();
  expect(await screen.findByText(ACCOUNT.user_external_id)).toBeInTheDocument();
});

test("shows the server's message when registration is refused", async () => {
  list([], true);
  mockRegister.mockRejectedValue(new Error("This account is not an active Global Administrator."));
  render(<BreakGlassAccountsCard />);

  fireEvent.change(await screen.findByLabelText(/object id or upn/i), {
    target: { value: "x@contoso.example" },
  });
  fireEvent.click(screen.getByRole("button", { name: /register/i }));

  expect(await screen.findByRole("alert")).toHaveTextContent("not an active Global Administrator");
});

test("owner removes an account only after confirming", async () => {
  list([ACCOUNT], true);
  mockRemove.mockResolvedValue(undefined);
  render(<BreakGlassAccountsCard />);

  fireEvent.click(await screen.findByRole("button", { name: /^remove/i }));
  expect(mockRemove).not.toHaveBeenCalled();
  list([], true);
  fireEvent.click(screen.getByRole("button", { name: /confirm remove/i }));

  await waitFor(() => expect(mockRemove).toHaveBeenCalledWith(7));
  expect(await screen.findByText(/conditional access fixes are blocked/i)).toBeInTheDocument();
});

test("non-owner sees the list without add or remove controls", async () => {
  list([ACCOUNT], false);
  render(<BreakGlassAccountsCard />);

  expect(await screen.findByText(ACCOUNT.user_external_id)).toBeInTheDocument();
  expect(screen.queryByLabelText(/object id or upn/i)).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /register/i })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /remove/i })).not.toBeInTheDocument();
  expect(screen.getByText(/only the tenant owner/i)).toBeInTheDocument();
});
