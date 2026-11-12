/**
 * Gate 1 — post-attach frontend state synchronization.
 *
 * Regression: AuthProvider (lib/auth-context.tsx) fetches the tenant list
 * exactly once, in a mount-time useEffect. It is not remounted by
 * router.replace() (client-side SPA navigation), so its `tenants`/`tenantId`
 * state stays whatever it was BEFORE this tenant was attached -- empty, for
 * a first-time MSP user. confirmAttach() navigated straight to /work without
 * calling the already-existing `refreshTenants()` from useAuth(), so /work
 * rendered against a stale, empty tenant list until a full browser refresh
 * remounted AuthProvider and re-fetched /api/v1/tenants/my from scratch.
 *
 * The fix must call refreshTenants() (already exposed by AuthProvider) so
 * the newly attached tenant is resolved before navigating away.
 */

import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import React from "react";

const mockReplace = jest.fn();
const mockSearchParams = new Map<string, string>([["session_id", "session-123"]]);
const mockRefreshTenants = jest
  .fn()
  .mockResolvedValue([{ tenant_id: "tenant-abc", tenant_name: "Contoso", role: "OWNER" }]);

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: mockReplace }),
  useSearchParams: () => ({
    get: (key: string) => mockSearchParams.get(key) ?? null,
  }),
}));

jest.mock("@/lib/auth", () => ({
  getApiBaseUrl: () => "http://localhost:8000",
  POST_LOGIN_LANDING: "/work",
}));

jest.mock("@/lib/auth-context", () => ({
  useAuth: () => ({ refreshTenants: mockRefreshTenants }),
}));

const PENDING_RESPONSE = {
  session_id: "session-123",
  tenant_id: "tenant-abc",
  tenant_name: "Contoso",
  domain: "contoso.example.com",
  existing_organization_id: null,
  msp_organization_id: "org-1",
};

import ConfirmTenantPage from "../page";

beforeEach(() => {
  mockReplace.mockClear();
  mockRefreshTenants.mockClear();
  global.fetch = jest.fn((url: string, init?: RequestInit) => {
    if (String(url).includes("/msp-connect/pending/")) {
      return Promise.resolve({
        ok: true,
        json: async () => PENDING_RESPONSE,
      } as Response);
    }
    if (String(url).includes("/msp-connect/confirm")) {
      return Promise.resolve({
        ok: true,
        json: async () => ({ status: "tenant_attached", tenant_id: "tenant-abc" }),
      } as Response);
    }
    throw new Error(`Unexpected fetch: ${url}`);
  }) as unknown as typeof fetch;
});

test("refreshes the tenant list before navigating to /work, so the newly attached tenant is resolved without a page refresh", async () => {
  const user = userEvent.setup();
  render(<ConfirmTenantPage />);

  const attachButton = await screen.findByRole("button", { name: /attach tenant/i });
  await user.click(attachButton);

  await waitFor(() => {
    expect(mockReplace).toHaveBeenCalledWith("/work");
  });

  expect(mockRefreshTenants).toHaveBeenCalledTimes(1);

  // Order matters: the tenant list must be refreshed BEFORE navigating away,
  // otherwise /work renders against the same stale, empty tenant list that
  // caused the bug.
  const refreshOrder = mockRefreshTenants.mock.invocationCallOrder[0];
  const replaceOrder = mockReplace.mock.invocationCallOrder[0];
  expect(refreshOrder).toBeLessThan(replaceOrder);
});
