/**
 * Sprint 1 — navigation becomes work-first.
 *
 * Product Bible §13/§14: users navigate by work, not by data. "My Work" is the
 * primary destination; the posture Dashboard is demoted under Fleet rather than
 * removed.
 */

import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import React from "react";

jest.mock("next/navigation", () => ({
  usePathname: () => "/work",
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
    user: { email: "tech@msp.example" },
    tenantId: "tenant-1",
    tenants: [{ tenant_id: "tenant-1", tenant_name: "Contoso", role: "admin" }],
    selectedTenant: { tenant_id: "tenant-1", tenant_name: "Contoso" },
    requiresTenantSelection: false,
    isSmb: false,
    isPreviewMode: false,
    setActiveTenantId: jest.fn(),
    logout: jest.fn(),
  }),
}));

jest.mock("@/lib/auth", () => ({ startMicrosoftOAuth: jest.fn() }));

jest.mock("@/lib/api/hooks", () => ({
  useBreakGlassEvents: () => ({ data: [] }),
}));

import DashboardLayout from "../DashboardLayout";

function renderNav() {
  return render(
    <DashboardLayout>
      <div>content</div>
    </DashboardLayout>,
  );
}

function navHrefs(container: HTMLElement): string[] {
  return Array.from(container.querySelectorAll("nav a")).map((anchor) => anchor.getAttribute("href") ?? "");
}

test("nav exposes My Work", () => {
  const { container } = renderNav();
  expect(navHrefs(container)).toContain("/work");
});

test("My Work is the first navigation destination", () => {
  const { container } = renderNav();
  expect(navHrefs(container)[0]).toBe("/work");
});

test("the posture dashboard is not removed", () => {
  const { container } = renderNav();
  expect(navHrefs(container)).toContain("/dashboard");
});

test("nav is organised by work, with a Work group before a Fleet group", () => {
  renderNav();
  const labels = screen.getAllByTestId("nav-group-label").map((node) => node.textContent);

  expect(labels).toContain("Work");
  expect(labels).toContain("Fleet");
  expect(labels.indexOf("Work")).toBeLessThan(labels.indexOf("Fleet"));
});

test("Dashboard is grouped under Fleet, not under the work group", () => {
  const { container } = renderNav();
  const fleetGroup = Array.from(container.querySelectorAll("[data-nav-group]")).find(
    (node) => node.getAttribute("data-nav-group") === "Fleet",
  );

  expect(fleetGroup).toBeTruthy();
  const fleetHrefs = Array.from(fleetGroup!.querySelectorAll("a")).map((a) => a.getAttribute("href"));
  expect(fleetHrefs).toContain("/dashboard");
});

// ── Sprint 3 — Workflow Library nav entry ────────────────────────────────────

test("nav exposes the Workflow Library inside the Work group, after My Work", () => {
  const { container } = renderNav();
  const workGroup = Array.from(container.querySelectorAll("[data-nav-group]")).find(
    (node) => node.getAttribute("data-nav-group") === "Work",
  );

  expect(workGroup).toBeTruthy();
  const workHrefs = Array.from(workGroup!.querySelectorAll("a")).map((a) => a.getAttribute("href"));
  expect(workHrefs).toContain("/workflows");
  expect(workHrefs.indexOf("/work")).toBeLessThan(workHrefs.indexOf("/workflows"));
});
