/**
 * New campaign page — pre-creation finding preview tests (RED → GREEN).
 *
 *  P1 — preview panel renders when controls and tenants are selected
 *  P2 — shows finding count per tenant from useCampaignPreview
 *  P3 — shows "0 findings" for tenants with no matches
 *  P4 — preview panel is hidden when no controls are selected
 *  P5 — preview panel is hidden when no tenants are selected
 */

import "@testing-library/jest-dom";
import { render, screen, fireEvent } from "@testing-library/react";
import React from "react";

// ── Top-level mock captures ───────────────────────────────────────────────────

const mockUseAuth = jest.fn();
const mockUseCampaignPreview = jest.fn();
const mockCreateCampaign = jest.fn();
const mockRouterPush = jest.fn();
const mockRouterReplace = jest.fn();

// ── Module mocks ──────────────────────────────────────────────────────────────

jest.mock("next/navigation", () => ({
  useRouter: () => ({ push: mockRouterPush, replace: mockRouterReplace }),
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
    Button: ({ children, onClick, disabled, loading, type, variant }: any) =>
      React.createElement(
        "button",
        { onClick, disabled: disabled || loading, type, "data-variant": variant },
        children,
      ),
    Card: ({ children, className, "data-testid": dataTestId }: any) =>
      React.createElement("div", { "data-testid": dataTestId ?? "card", className }, children),
    PageHeader: ({ title, actions }: any) =>
      React.createElement(
        "div",
        null,
        React.createElement("h1", null, title),
        React.createElement("div", { "data-testid": "header-actions" }, actions),
      ),
  };
});

jest.mock("@/lib/auth-context", () => ({
  useAuth: (...args: any[]) => mockUseAuth(...args),
}));

jest.mock("@/lib/api/hooks", () => ({
  useCampaignPreview: (...args: any[]) => mockUseCampaignPreview(...args),
}));

jest.mock("@/lib/api/campaigns", () => ({
  createCampaign: (...args: any[]) => mockCreateCampaign(...args),
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

function mspAuth() {
  mockUseAuth.mockReturnValue({
    isSmb: false,
    tenants: [
      { tenant_id: "t1", tenant_name: "Contoso" },
      { tenant_id: "t2", tenant_name: "Fabrikam" },
    ],
  });
}

function previewData(items: Array<{ tenant_id: string; tenant_name: string | null; finding_count: number }>) {
  mockUseCampaignPreview.mockReturnValue({
    data: { items },
    loading: false,
    error: null,
  });
}

function renderNew() {
  const NewCampaignPage = require("../page").default;
  return render(React.createElement(NewCampaignPage));
}

function selectControl() {
  fireEvent.click(screen.getByLabelText("IDENTITY_UNUSED_ACCOUNT"));
}

function selectTenant(name: string) {
  fireEvent.click(screen.getByLabelText(name));
}

// ── P1 — preview panel appears ────────────────────────────────────────────────

describe("P1 — preview panel renders when controls and tenants are selected", () => {
  beforeEach(() => {
    mspAuth();
    previewData([
      { tenant_id: "t1", tenant_name: "Contoso", finding_count: 4 },
      { tenant_id: "t2", tenant_name: "Fabrikam", finding_count: 0 },
    ]);
  });

  test("preview panel is visible after selecting a control and a tenant", () => {
    renderNew();
    selectControl();
    selectTenant("Contoso");
    expect(screen.getByTestId("campaign-preview-panel")).toBeInTheDocument();
  });
});

// ── P2 — shows finding counts ─────────────────────────────────────────────────

describe("P2 — shows finding count per tenant from useCampaignPreview", () => {
  beforeEach(() => {
    mspAuth();
    previewData([
      { tenant_id: "t1", tenant_name: "Contoso", finding_count: 4 },
      { tenant_id: "t2", tenant_name: "Fabrikam", finding_count: 2 },
    ]);
  });

  test("shows Contoso with 4 findings", () => {
    renderNew();
    selectControl();
    selectTenant("Contoso");
    selectTenant("Fabrikam");
    const panel = screen.getByTestId("campaign-preview-panel");
    expect(panel).toHaveTextContent("Contoso");
    expect(panel).toHaveTextContent("4");
  });

  test("shows Fabrikam with 2 findings", () => {
    renderNew();
    selectControl();
    selectTenant("Contoso");
    selectTenant("Fabrikam");
    const panel = screen.getByTestId("campaign-preview-panel");
    expect(panel).toHaveTextContent("Fabrikam");
    expect(panel).toHaveTextContent("2");
  });
});

// ── P3 — shows 0 findings tenant ─────────────────────────────────────────────

describe("P3 — shows '0 findings' for tenants with no matches", () => {
  beforeEach(() => {
    mspAuth();
    previewData([
      { tenant_id: "t1", tenant_name: "Contoso", finding_count: 3 },
      { tenant_id: "t2", tenant_name: "Fabrikam", finding_count: 0 },
    ]);
  });

  test("Fabrikam appears in preview with 0 findings", () => {
    renderNew();
    selectControl();
    selectTenant("Contoso");
    selectTenant("Fabrikam");
    const panel = screen.getByTestId("campaign-preview-panel");
    expect(panel).toHaveTextContent("Fabrikam");
    expect(panel).toHaveTextContent("0");
  });
});

// ── P4 — panel hidden when no controls selected ───────────────────────────────

describe("P4 — preview panel is hidden when no controls selected", () => {
  beforeEach(() => {
    mspAuth();
    previewData([]);
  });

  test("preview panel absent when no controls checked", () => {
    renderNew();
    selectTenant("Contoso");
    expect(screen.queryByTestId("campaign-preview-panel")).not.toBeInTheDocument();
  });
});

// ── P5 — panel hidden when no tenants selected ────────────────────────────────

describe("P5 — preview panel is hidden when no tenants selected", () => {
  beforeEach(() => {
    mspAuth();
    previewData([]);
  });

  test("preview panel absent when no tenants checked", () => {
    renderNew();
    selectControl();
    expect(screen.queryByTestId("campaign-preview-panel")).not.toBeInTheDocument();
  });
});
