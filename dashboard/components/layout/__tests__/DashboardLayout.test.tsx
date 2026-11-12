/**
 * Top-bar audit: notification bell removal — N-1.
 *
 * The notification bell has no backend, no state, no onClick handler, and a
 * hardcoded red dot that misleads users into thinking they have unread items.
 * These tests assert the bell and its indicator are absent.
 *
 * RED: fails while bell exists in DashboardLayout.
 * GREEN: passes after bell is removed.
 */

import "@testing-library/jest-dom";
import { render } from "@testing-library/react";
import React from "react";

// ── Mocks ─────────────────────────────────────────────────────────────────────

jest.mock("next/navigation", () => ({
  usePathname: () => "/dashboard",
  useRouter: () => ({ replace: jest.fn() }),
}));

jest.mock("next/link", () => {
  const React = require("react");
  return ({ children, href, ...rest }: any) => React.createElement("a", { href, ...rest }, children);
});

jest.mock("lucide-react", () => {
  const React = require("react");
  return new Proxy(
    {},
    {
      get: (_target, name: string) => {
        return ({ size, ...rest }: any) =>
          React.createElement("svg", { "data-testid": `icon-${name}`, ...rest });
      },
    },
  );
});

jest.mock("@/lib/auth-context", () => ({
  useAuth: () => ({
    loading: false,
    authed: true,
    user: { email: "admin@example.com" },
    tenantId: "tenant-1",
    tenants: [{ tenant_id: "tenant-1", tenant_name: "Acme Corp", role: "admin" }],
    selectedTenant: { tenant_id: "tenant-1", tenant_name: "Acme Corp" },
    requiresTenantSelection: false,
    isSmb: false,
    isPreviewMode: false,
    setActiveTenantId: jest.fn(),
    logout: jest.fn(),
  }),
}));

jest.mock("@/lib/auth", () => ({
  startMicrosoftOAuth: jest.fn(),
}));

jest.mock("@/lib/api/hooks", () => ({
  useBreakGlassEvents: () => ({ data: null }),
}));

jest.mock("@/components/ui", () => {
  const React = require("react");
  return {
    Button: ({ children, onClick }: any) => React.createElement("button", { onClick }, children),
  };
});

jest.mock("@/components/ui/PreviewModeBanner", () => ({
  PreviewModeBanner: () => null,
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

function renderLayout() {
  const DashboardLayout = require("../DashboardLayout").default;
  return render(React.createElement(DashboardLayout, null, React.createElement("div", null, "content")));
}

// ── N-1: Notification bell removal ────────────────────────────────────────────

describe("notification bell — N-1", () => {
  test("notification bell icon is not rendered in the top bar", () => {
    const { container } = renderLayout();
    // The Bell lucide icon gets rendered as <svg data-testid="icon-Bell">
    const bellIcon = container.querySelector('[data-testid="icon-Bell"]');
    expect(bellIcon).not.toBeInTheDocument();
  });

  test("hardcoded notification red dot is not rendered", () => {
    const { container } = renderLayout();
    // The dot was a <span class="... bg-red-500 ..."> inside the bell button.
    // bg-red-500 is used only for the notification indicator in DashboardLayout.
    const redDot = container.querySelector("span.bg-red-500");
    expect(redDot).not.toBeInTheDocument();
  });
});
