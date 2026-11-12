/**
 * HIGH-3: Fleet view must not gate fleet-wide posture data behind selectedTenantId.
 *
 * Gates under test (currently RED — gated on selectedTenantId):
 *  G1 — StatCard values: `selectedTenantId ? good : "-"`  → must always show counts
 *  G2 — Loading skeleton: `selectedTenantId && fleetQuery.loading` → must show without selection
 *  G3 — Error state: `selectedTenantId && fleetQuery.error`      → must show without selection
 *  G4 — Refresh button: `selectedTenantId ? <Button> : null`    → must show without selection
 *
 * After fix (GREEN): all four gates are removed.
 */

import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import React from "react";

// ── Top-level mock captures ───────────────────────────────────────────────────
// Variables prefixed "mock" are permitted in jest.mock() factories.

const mockUseAuth = jest.fn();
const mockUseFleetPosture = jest.fn();
const mockRouterReplace = jest.fn();
const mockSearchParams = new Map<string, string>();

// ── Module mocks ──────────────────────────────────────────────────────────────

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: mockRouterReplace, push: jest.fn() }),
  useSearchParams: () => ({
    get: (key: string) => mockSearchParams.get(key) ?? null,
  }),
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
      get: (_: unknown, name: string) => (props: Record<string, unknown>) =>
        React.createElement("svg", { "data-testid": `icon-${name}` }),
    },
  );
});

jest.mock("@/components/ui", () => {
  const React = require("react");
  return {
    Button: ({ children, onClick, disabled, variant, loading }: any) =>
      React.createElement(
        "button",
        { onClick, disabled: disabled || loading, "data-variant": variant },
        children,
      ),
    Card: ({ children, "data-testid": testId }: any) =>
      React.createElement("div", { "data-testid": testId ?? "card" }, children),
    EmptyState: ({ message }: any) => React.createElement("div", { "data-testid": "empty-state" }, message),
    ErrorState: ({ message }: any) => React.createElement("div", { "data-testid": "error-state" }, message),
    FilterSelect: ({ value, onChange, options }: any) =>
      React.createElement(
        "select",
        { value, onChange: (e: any) => onChange(e.target.value) },
        options.map((o: any) => React.createElement("option", { key: o.value, value: o.value }, o.label)),
      ),
    PageHeader: ({ title, actions }: any) =>
      React.createElement(
        "div",
        null,
        React.createElement("h1", null, title),
        React.createElement("div", { "data-testid": "header-actions" }, actions),
      ),
    StatCard: ({ label, value }: any) =>
      React.createElement(
        "div",
        { "data-testid": `stat-${label.toLowerCase()}` },
        React.createElement("span", { "data-testid": `stat-value-${label.toLowerCase()}` }, String(value)),
      ),
    TableSkeleton: ({ rows }: any) =>
      React.createElement("div", { "data-testid": "table-skeleton", "data-rows": rows }),
  };
});

jest.mock("@/lib/auth-context", () => ({
  useAuth: (...args: any[]) => mockUseAuth(...args),
}));

jest.mock("@/lib/api/hooks", () => ({
  useFleetPosture: (...args: any[]) => mockUseFleetPosture(...args),
}));

jest.mock("@/lib/auth", () => ({
  startMicrosoftOAuth: jest.fn(),
  getToken: () => null,
  getSelectedTenantId: () => null,
}));

jest.mock("@/lib/api/endpoints", () => ({
  startTenantScan: jest.fn(),
  startAllTenantScans: jest.fn(),
  deleteTenant: jest.fn(),
}));

jest.mock("@/utils/posture", () => ({
  scoreBandAccent: () => "text-green-400",
  scoreBandLabel: (band: string | null) => band ?? "Unknown",
}));

// ── Shared defaults ───────────────────────────────────────────────────────────

const TWO_TENANTS = [
  { tenant_id: "t1", tenant_name: "Alpha Corp", role: "ADMIN" },
  { tenant_id: "t2", tenant_name: "Beta LLC", role: "ADMIN" },
];

const FLEET_DATA_TWO = {
  tenants: [
    {
      tenant_id: "t1",
      posture_score: 85,
      score_band: "GOOD",
      failed_controls: 2,
      has_snapshot: true,
      status: "Active",
      latest_snapshot_at: null,
    },
    {
      tenant_id: "t2",
      posture_score: 30,
      score_band: "CRITICAL",
      failed_controls: 12,
      has_snapshot: true,
      status: "Active",
      latest_snapshot_at: null,
    },
  ],
};

// ── Render helper ─────────────────────────────────────────────────────────────

function renderTenantsPage() {
  const TenantsPage = require("../page").default;
  return render(React.createElement(TenantsPage));
}

// ─────────────────────────────────────────────────────────────────────────────
// G1 — Stat cards must show real counts without a selected tenant
// ─────────────────────────────────────────────────────────────────────────────

describe("G1 — stat cards show fleet counts without tenant selection", () => {
  beforeEach(() => {
    mockUseAuth.mockReturnValue({
      tenants: TWO_TENANTS,
      tenantId: null, // ← no tenant selected
      setActiveTenantId: jest.fn(),
      refreshTenants: jest.fn().mockResolvedValue([]),
      isSmb: false,
    });
    mockUseFleetPosture.mockReturnValue({
      data: FLEET_DATA_TWO,
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
  });

  test("Good count renders as '1' when one tenant has GOOD band, not '-'", () => {
    renderTenantsPage();
    const goodValue = screen.getByTestId("stat-value-good");
    expect(goodValue).toHaveTextContent("1");
    expect(goodValue).not.toHaveTextContent("-");
  });

  test("Critical count renders as '1' when one tenant has CRITICAL band, not '-'", () => {
    renderTenantsPage();
    const critValue = screen.getByTestId("stat-value-critical");
    expect(critValue).toHaveTextContent("1");
    expect(critValue).not.toHaveTextContent("-");
  });

  test("Moderate count renders as '0' when no tenant has MODERATE band, not '-'", () => {
    renderTenantsPage();
    const modValue = screen.getByTestId("stat-value-moderate");
    expect(modValue).toHaveTextContent("0");
    expect(modValue).not.toHaveTextContent("-");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// G2 — Loading skeleton must show during fleet load without tenant selection
// ─────────────────────────────────────────────────────────────────────────────

describe("G2 — fleet loading skeleton shows without tenant selection", () => {
  beforeEach(() => {
    mockUseAuth.mockReturnValue({
      tenants: [{ tenant_id: "t1", tenant_name: "Alpha Corp", role: "ADMIN" }],
      tenantId: null, // ← no tenant selected
      setActiveTenantId: jest.fn(),
      refreshTenants: jest.fn().mockResolvedValue([]),
      isSmb: false,
    });
    mockUseFleetPosture.mockReturnValue({
      data: null,
      loading: true, // ← fleet is loading
      error: null,
      refetch: jest.fn(),
    });
  });

  test("TableSkeleton renders while fleet query is loading, even without a selected tenant", () => {
    renderTenantsPage();
    expect(screen.getByTestId("table-skeleton")).toBeInTheDocument();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// G3 — Error state must show on fleet error without tenant selection
// ─────────────────────────────────────────────────────────────────────────────

describe("G3 — fleet error state shows without tenant selection", () => {
  beforeEach(() => {
    mockUseAuth.mockReturnValue({
      tenants: [{ tenant_id: "t1", tenant_name: "Alpha Corp", role: "ADMIN" }],
      tenantId: null, // ← no tenant selected
      setActiveTenantId: jest.fn(),
      refreshTenants: jest.fn().mockResolvedValue([]),
      isSmb: false,
    });
    mockUseFleetPosture.mockReturnValue({
      data: null,
      loading: false,
      error: "Fleet data unavailable", // ← fleet errored
      refetch: jest.fn(),
    });
  });

  test("ErrorState renders when fleet query errors, even without a selected tenant", () => {
    renderTenantsPage();
    expect(screen.getByTestId("error-state")).toBeInTheDocument();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// G4 — Refresh button must show without tenant selection
// ─────────────────────────────────────────────────────────────────────────────

describe("G4 — Refresh button shows without tenant selection", () => {
  beforeEach(() => {
    mockUseAuth.mockReturnValue({
      tenants: [{ tenant_id: "t1", tenant_name: "Alpha Corp", role: "ADMIN" }],
      tenantId: null, // ← no tenant selected
      setActiveTenantId: jest.fn(),
      refreshTenants: jest.fn().mockResolvedValue([]),
      isSmb: false,
    });
    mockUseFleetPosture.mockReturnValue({
      data: {
        tenants: [
          {
            tenant_id: "t1",
            posture_score: 85,
            score_band: "GOOD",
            failed_controls: 2,
            has_snapshot: true,
            status: "Active",
            latest_snapshot_at: null,
          },
        ],
      },
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
  });

  test("Refresh button is present in header even when no tenant is selected", () => {
    renderTenantsPage();
    const actions = screen.getByTestId("header-actions");
    const refreshButton = Array.from(actions.querySelectorAll("button")).find((btn) =>
      btn.textContent?.includes("Refresh"),
    );
    expect(refreshButton).toBeDefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Regressions — with tenant selected, existing behavior must be preserved
// ─────────────────────────────────────────────────────────────────────────────

describe("regressions — fleet data still works with a selected tenant", () => {
  beforeEach(() => {
    mockUseAuth.mockReturnValue({
      tenants: TWO_TENANTS,
      tenantId: "t1", // ← tenant IS selected
      setActiveTenantId: jest.fn(),
      refreshTenants: jest.fn().mockResolvedValue([]),
      isSmb: false,
    });
    mockUseFleetPosture.mockReturnValue({
      data: FLEET_DATA_TWO,
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
  });

  test("Good stat card shows '1' when a tenant is selected", () => {
    renderTenantsPage();
    expect(screen.getByTestId("stat-value-good")).toHaveTextContent("1");
  });

  test("tenant rows still render in the table when tenant is selected", () => {
    renderTenantsPage();
    expect(screen.getByText("Alpha Corp")).toBeInTheDocument();
    expect(screen.getByText("Beta LLC")).toBeInTheDocument();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SMB regression — SMB users must not see the Tenants page content
// ─────────────────────────────────────────────────────────────────────────────

describe("SMB regression — page renders null for SMB users", () => {
  beforeEach(() => {
    mockUseAuth.mockReturnValue({
      tenants: [],
      tenantId: null,
      setActiveTenantId: jest.fn(),
      refreshTenants: jest.fn(),
      isSmb: true, // ← SMB user
    });
    mockUseFleetPosture.mockReturnValue({ data: null, loading: false, error: null, refetch: jest.fn() });
  });

  test("Tenants page heading is absent when isSmb is true", () => {
    renderTenantsPage();
    expect(screen.queryByText("Tenants")).not.toBeInTheDocument();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Gate 1 — onboarding-failure query params must be shown, not silently dropped
// ─────────────────────────────────────────────────────────────────────────────

describe("Gate 1 — connect-error query params are displayed", () => {
  beforeEach(() => {
    mockSearchParams.clear();
    mockUseAuth.mockReturnValue({
      tenants: [],
      tenantId: null,
      setActiveTenantId: jest.fn(),
      refreshTenants: jest.fn().mockResolvedValue([]),
      isSmb: false,
    });
    mockUseFleetPosture.mockReturnValue({
      data: { tenants: [] },
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
  });

  test("shows a message when the OAuth callback redirected here with connect_error", () => {
    mockSearchParams.set("connect_error", "cancelled");
    renderTenantsPage();
    expect(screen.getByText(/cancel/i)).toBeInTheDocument();
  });

  test("shows a message when a non-admin's connection attempt is denied", () => {
    mockSearchParams.set("error", "tenant_admin_required");
    renderTenantsPage();
    expect(screen.getByTestId("connect-error-banner")).toHaveTextContent(/global administrator/i);
  });

  test("renders nothing extra when there is no error param", () => {
    renderTenantsPage();
    expect(screen.queryByTestId("connect-error-banner")).not.toBeInTheDocument();
  });

  test("the empty state tells a first-time user they need admin access to connect", () => {
    renderTenantsPage();
    expect(screen.getByText(/global administrator/i)).toBeInTheDocument();
  });
});
