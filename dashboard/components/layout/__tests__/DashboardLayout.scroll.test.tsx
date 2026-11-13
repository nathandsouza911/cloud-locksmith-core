/**
 * The sidebar and the page content scroll independently.
 *
 * The shell was min-h-screen, so it grew with the page and the window scrolled the
 * sidebar together with the content. The shell is now the height of the window and
 * clips; the sidebar's nav and <main> each scroll on their own. jsdom has no layout,
 * so this asserts the classes that produce that behaviour.
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

function classesOf(element: Element | null): string[] {
  return (element?.getAttribute("class") ?? "").split(/\s+/).filter(Boolean);
}

describe("independent scrolling", () => {
  test("the shell is the height of the window and does not scroll itself", () => {
    const { container } = renderLayout();
    const shell = classesOf(container.firstElementChild);
    expect(shell).toEqual(expect.arrayContaining(["h-screen", "overflow-hidden"]));
    expect(shell).not.toContain("min-h-screen");
  });

  test("the sidebar fills the window height and its nav scrolls on its own", () => {
    const { container } = renderLayout();
    expect(classesOf(container.querySelector("aside"))).toEqual(expect.arrayContaining(["lg:h-full"]));
    expect(classesOf(container.querySelector("aside nav"))).toEqual(
      expect.arrayContaining(["flex-1", "min-h-0", "overflow-y-auto"]),
    );
  });

  test("the page content scrolls on its own", () => {
    const { container } = renderLayout();
    const column = container.querySelector("main")?.parentElement ?? null;
    expect(classesOf(column)).toEqual(expect.arrayContaining(["min-h-0", "overflow-hidden"]));
    expect(classesOf(container.querySelector("main"))).toEqual(
      expect.arrayContaining(["flex-1", "min-h-0", "overflow-y-auto"]),
    );
  });
});
