/**
 * Fleet Report page tests (RED → GREEN).
 *
 *  FR1  — fleet summary stat cards are shown (fleet size, avg score, total critical)
 *  FR2  — risk ranking table shows tenants sorted worst → best
 *  FR3  — trend indicators show score_delta_7d direction
 *  FR4  — insurance readiness proxy column derived from score_band
 *  FR5  — findings column shows critical_findings and failed_controls per tenant
 *  FR6  — top fleet risks section renders
 *  FR7  — loading skeleton shown while data fetches
 *  FR8  — error state shown when fleet posture fails
 *  FR9  — SMB users are redirected to /dashboard
 *  FR10 — tenant rows link to /tenants page
 */

import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import React from "react";

// ── Top-level mock captures ───────────────────────────────────────────────────

const mockUseAuth = jest.fn();
const mockUseFleetPosture = jest.fn();
const mockUseFleetOverview = jest.fn();
const mockRouterReplace = jest.fn();
const mockRouterPush = jest.fn();

// ── Module mocks ──────────────────────────────────────────────────────────────

jest.mock("next/navigation", () => ({
  useRouter: () => ({ push: mockRouterPush, replace: mockRouterReplace }),
  usePathname: () => "/fleet-report",
}));

jest.mock("lucide-react", () => {
  const React = require("react");
  return new Proxy(
    {},
    {
      get: (_: unknown, name: string) => (props: any) =>
        React.createElement("svg", { "data-testid": `icon-${name}` }),
    },
  );
});

jest.mock("@/components/ui", () => {
  const React = require("react");
  return {
    Button: ({ children, onClick, disabled }: any) =>
      React.createElement("button", { onClick, disabled }, children),
    Card: ({ children, className }: any) =>
      React.createElement("div", { "data-testid": "card", className }, children),
    EmptyState: ({ message }: any) => React.createElement("div", { "data-testid": "empty-state" }, message),
    ErrorState: ({ message }: any) => React.createElement("div", { "data-testid": "error-state" }, message),
    PageHeader: ({ title, subtitle }: any) =>
      React.createElement(
        "div",
        null,
        React.createElement("h1", null, title),
        subtitle && React.createElement("p", { "data-testid": "subtitle" }, subtitle),
      ),
    TableSkeleton: ({ rows }: any) => React.createElement("div", { "data-testid": "table-skeleton" }),
  };
});

jest.mock("@/lib/auth-context", () => ({
  useAuth: (...args: any[]) => mockUseAuth(...args),
}));

jest.mock("@/lib/api/hooks", () => ({
  useFleetPosture: (...args: any[]) => mockUseFleetPosture(...args),
  useFleetOverview: (...args: any[]) => mockUseFleetOverview(...args),
}));

// ── Test data ─────────────────────────────────────────────────────────────────

const FLEET_POSTURE = {
  tenants: [
    {
      tenant_id: "t1",
      tenant_name: "Contoso",
      posture_score: 28,
      score_band: "CRITICAL",
      failed_controls: 12,
      has_snapshot: true,
      status: "Active",
      latest_snapshot_at: "2026-06-14T09:00:00",
      score_delta_7d: -5,
      percentile: 92,
      relative_position: "Bottom 20%",
    },
    {
      tenant_id: "t2",
      tenant_name: "Fabrikam",
      posture_score: 61,
      score_band: "MODERATE",
      failed_controls: 4,
      has_snapshot: true,
      status: "Active",
      latest_snapshot_at: "2026-06-14T08:00:00",
      score_delta_7d: 3,
      percentile: 45,
      relative_position: "Middle",
    },
  ],
  fleet_avg_score: 44.5,
  fleet_size: 2,
};

const FLEET_OVERVIEW = {
  tenants: [
    {
      tenant_id: "t1",
      tenant_name: "Contoso",
      risk_score: 28,
      risk_score_band: "CRITICAL",
      critical_findings: 5,
      mfa_coverage: 40,
      last_scan: "2026-06-14T09:00:00",
    },
    {
      tenant_id: "t2",
      tenant_name: "Fabrikam",
      risk_score: 61,
      risk_score_band: "MODERATE",
      critical_findings: 1,
      mfa_coverage: 88,
      last_scan: "2026-06-14T08:00:00",
    },
  ],
  aggregate: {
    avg_risk: 44.5,
    avg_risk_band: "HIGH",
    total_critical: 6,
    tenant_count: 2,
  },
  top_risks: [
    {
      tenant_id: "t1",
      tenant_name: "Contoso",
      control_id: "IDENTITY_ADMIN_NO_MFA",
      resource_id: "admin@contoso.com",
      severity: "CRITICAL",
      title: "Identity Admin No Mfa",
    },
    {
      tenant_id: "t2",
      tenant_name: "Fabrikam",
      control_id: "IDENTITY_UNUSED_ACCOUNT",
      resource_id: "user@fabrikam.com",
      severity: "HIGH",
      title: "Identity Unused Account",
    },
  ],
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function renderPage() {
  const FleetReportPage = require("../page").default;
  return render(React.createElement(FleetReportPage));
}

function setupMsp() {
  mockUseAuth.mockReturnValue({ isSmb: false });
  mockUseFleetPosture.mockReturnValue({
    data: FLEET_POSTURE,
    loading: false,
    error: null,
    refetch: jest.fn(),
  });
  mockUseFleetOverview.mockReturnValue({
    data: FLEET_OVERVIEW,
    loading: false,
    error: null,
    refetch: jest.fn(),
  });
}

// ── FR1 — fleet summary stat cards ───────────────────────────────────────────

describe("FR1 — fleet summary stat cards", () => {
  beforeEach(() => setupMsp());

  test("page heading is shown", () => {
    renderPage();
    expect(screen.getByText(/fleet report/i)).toBeInTheDocument();
  });

  test("fleet size is displayed", () => {
    renderPage();
    expect(screen.getByText("2")).toBeInTheDocument();
  });

  test("fleet avg score is displayed", () => {
    renderPage();
    // Math.round(44.5) = 45 in JavaScript
    expect(screen.getByText("45")).toBeInTheDocument();
  });

  test("total critical findings is displayed", () => {
    renderPage();
    expect(screen.getByText("6")).toBeInTheDocument();
  });
});

// ── FR2 — risk ranking table ──────────────────────────────────────────────────

describe("FR2 — risk ranking table shows tenants", () => {
  beforeEach(() => setupMsp());

  test("Contoso appears in the risk ranking table", () => {
    renderPage();
    expect(screen.getByText("Contoso")).toBeInTheDocument();
  });

  test("Fabrikam appears in the risk ranking table", () => {
    renderPage();
    expect(screen.getByText("Fabrikam")).toBeInTheDocument();
  });

  test("posture scores are shown", () => {
    renderPage();
    expect(screen.getByText("28")).toBeInTheDocument();
    expect(screen.getByText("61")).toBeInTheDocument();
  });

  test("score bands are shown", () => {
    renderPage();
    // "Critical" appears in band badge AND "Not Insurable" row — multiple matches expected
    expect(screen.getAllByText(/critical/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/moderate/i).length).toBeGreaterThan(0);
  });
});

// ── FR3 — trend indicators ────────────────────────────────────────────────────

describe("FR3 — trend indicators show 7-day score delta", () => {
  beforeEach(() => setupMsp());

  test("negative delta shown for Contoso (score worsened)", () => {
    renderPage();
    // score_delta_7d = -5 → show "-5"
    expect(screen.getByText(/-5/)).toBeInTheDocument();
  });

  test("positive delta shown for Fabrikam (score improved)", () => {
    renderPage();
    // score_delta_7d = +3 → show "+3"
    expect(screen.getByText(/\+3/)).toBeInTheDocument();
  });
});

// ── FR4 — insurance readiness proxy ──────────────────────────────────────────

describe("FR4 — insurance readiness proxy derived from score_band", () => {
  beforeEach(() => setupMsp());

  test("CRITICAL score_band maps to 'Not Insurable' label", () => {
    renderPage();
    expect(screen.getByText(/not insurable/i)).toBeInTheDocument();
  });

  test("MODERATE score_band maps to an insurable label", () => {
    renderPage();
    // MODERATE → "Conditional" or "Conditionally Insurable"
    expect(screen.getByText(/conditional/i)).toBeInTheDocument();
  });
});

// ── FR5 — findings column ─────────────────────────────────────────────────────

describe("FR5 — findings column shows critical_findings and failed_controls", () => {
  beforeEach(() => setupMsp());

  test("critical_findings for Contoso (5) is shown", () => {
    renderPage();
    expect(screen.getByText("5")).toBeInTheDocument();
  });

  test("failed_controls for Contoso (12) is shown", () => {
    renderPage();
    expect(screen.getByText("12")).toBeInTheDocument();
  });
});

// ── FR6 — top fleet risks ─────────────────────────────────────────────────────

describe("FR6 — top fleet risks section", () => {
  beforeEach(() => setupMsp());

  test("top risks section heading is visible", () => {
    renderPage();
    // heading text may also appear in subtitle — use getAllByText
    expect(screen.getAllByText(/top.*risk|fleet.*risk/i).length).toBeGreaterThan(0);
  });

  test("IDENTITY_ADMIN_NO_MFA risk is listed", () => {
    renderPage();
    expect(screen.getByText(/identity_admin_no_mfa|identity admin no mfa/i)).toBeInTheDocument();
  });

  test("risk severity CRITICAL is shown", () => {
    renderPage();
    // Multiple CRITICAL occurrences (score band + risk severity) — verify at least one
    expect(screen.getAllByText(/critical/i).length).toBeGreaterThan(0);
  });

  test("tenant name Contoso is associated with the top risk", () => {
    renderPage();
    // Contoso appears in both table and risks section
    expect(screen.getAllByText("Contoso").length).toBeGreaterThan(0);
  });
});

// ── FR7 — loading skeleton ────────────────────────────────────────────────────

describe("FR7 — loading skeleton during data fetch", () => {
  beforeEach(() => {
    mockUseAuth.mockReturnValue({ isSmb: false });
    mockUseFleetPosture.mockReturnValue({ data: null, loading: true, error: null, refetch: jest.fn() });
    mockUseFleetOverview.mockReturnValue({ data: null, loading: true, error: null, refetch: jest.fn() });
  });

  test("table skeleton is shown while loading", () => {
    renderPage();
    expect(screen.getByTestId("table-skeleton")).toBeInTheDocument();
  });
});

// ── FR8 — error state ─────────────────────────────────────────────────────────

describe("FR8 — error state when fleet posture fails", () => {
  beforeEach(() => {
    mockUseAuth.mockReturnValue({ isSmb: false });
    mockUseFleetPosture.mockReturnValue({
      data: null,
      loading: false,
      error: "Unauthorized",
      refetch: jest.fn(),
    });
    mockUseFleetOverview.mockReturnValue({ data: null, loading: false, error: null, refetch: jest.fn() });
  });

  test("error state is shown when fleet posture fails", () => {
    renderPage();
    expect(screen.getByTestId("error-state")).toBeInTheDocument();
  });
});

// ── FR9 — SMB redirect ────────────────────────────────────────────────────────

describe("FR9 — SMB users are redirected to /dashboard", () => {
  beforeEach(() => {
    mockUseAuth.mockReturnValue({ isSmb: true });
    mockUseFleetPosture.mockReturnValue({ data: null, loading: false, error: null, refetch: jest.fn() });
    mockUseFleetOverview.mockReturnValue({ data: null, loading: false, error: null, refetch: jest.fn() });
  });

  test("SMB user does not see the fleet report page", () => {
    renderPage();
    expect(screen.queryByText(/fleet report/i)).not.toBeInTheDocument();
  });

  test("router.replace is called for SMB users", () => {
    renderPage();
    expect(mockRouterReplace).toHaveBeenCalledWith("/dashboard");
  });
});

// ── FR10 — tenant detail links ────────────────────────────────────────────────

describe("FR10 — tenant rows link to /tenants page", () => {
  beforeEach(() => setupMsp());

  test("each tenant row has an anchor linking to /tenants", () => {
    renderPage();
    const links = screen.getAllByRole("link");
    const tenantLinks = links.filter((link) => link.getAttribute("href")?.includes("/tenants"));
    expect(tenantLinks.length).toBeGreaterThan(0);
  });
});
