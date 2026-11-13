/**
 * A signed-out visitor is sent to /login. If they arrived with a sign-in failure
 * (?connect_error=<code>, e.g. from a refused Microsoft callback), the code must
 * survive the redirect so the login page can explain it.
 */

import "@testing-library/jest-dom";
import { render } from "@testing-library/react";
import React from "react";

const mockReplace = jest.fn();

jest.mock("next/navigation", () => ({
  usePathname: () => "/tenants",
  useRouter: () => ({ replace: mockReplace }),
}));

jest.mock("next/link", () => {
  const React = require("react");
  return ({ children, href, ...rest }: any) => React.createElement("a", { href, ...rest }, children);
});

jest.mock("lucide-react", () => {
  const React = require("react");
  return new Proxy({}, { get: () => (props: any) => React.createElement("svg", props) });
});

jest.mock("@/lib/auth-context", () => ({
  useAuth: () => ({
    loading: false,
    authed: false,
    user: null,
    tenantId: null,
    tenants: [],
    selectedTenant: null,
    requiresTenantSelection: false,
    isSmb: false,
    isPreviewMode: false,
    setActiveTenantId: jest.fn(),
    logout: jest.fn(),
  }),
}));

jest.mock("@/lib/auth", () => ({ startMicrosoftOAuth: jest.fn() }));
jest.mock("@/lib/api/hooks", () => ({ useBreakGlassEvents: () => ({ data: null }) }));
jest.mock("@/components/ui", () => {
  const React = require("react");
  return { Button: ({ children, onClick }: any) => React.createElement("button", { onClick }, children) };
});
jest.mock("@/components/ui/PreviewModeBanner", () => ({ PreviewModeBanner: () => null }));

function renderLayout() {
  const DashboardLayout = require("../DashboardLayout").default;
  return render(React.createElement(DashboardLayout, null, React.createElement("div", null, "content")));
}

afterEach(() => {
  mockReplace.mockClear();
  window.history.replaceState(null, "", "/");
});

test("keeps the connect_error code when redirecting to /login", () => {
  window.history.replaceState(
    null,
    "",
    "/tenants?connect_error=tenant_already_owned&connect_error_message=whatever",
  );
  renderLayout();
  expect(mockReplace).toHaveBeenCalledWith("/login?connect_error=tenant_already_owned");
});

test("plain /login when there is no sign-in error", () => {
  window.history.replaceState(null, "", "/tenants");
  renderLayout();
  expect(mockReplace).toHaveBeenCalledWith("/login");
});
