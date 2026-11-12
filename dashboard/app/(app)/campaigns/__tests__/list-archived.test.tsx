/**
 * Campaign list — active/archived filtering tests (BLOCKER-2).
 *
 *  B2-L1  active campaigns (AWAITING_APPROVAL, EXECUTING, FAILED, PLAN) are visible by default
 *  B2-L2  terminal campaigns (ROLLED_BACK, CANCELLED, COMPLETED) are hidden by default
 *  B2-L3  "Show Archived" toggle reveals terminal campaigns
 *  B2-L4  toggling back hides terminal campaigns again
 *  B2-L5  "Show Archived" toggle is not shown when there are no terminal campaigns
 */

import "@testing-library/jest-dom";
import { render, screen, fireEvent } from "@testing-library/react";
import React from "react";

// ── Top-level mock captures ───────────────────────────────────────────────────

const mockUseAuth = jest.fn();
const mockUseCampaigns = jest.fn();
const mockRouterReplace = jest.fn();

// ── Module mocks ──────────────────────────────────────────────────────────────

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: mockRouterReplace, push: jest.fn() }),
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
      get: (_: unknown, name: string) => (props: any) =>
        React.createElement("svg", { "data-testid": `icon-${name}` }),
    },
  );
});

jest.mock("@/components/ui", () => {
  const React = require("react");
  return {
    Button: ({ children, onClick, disabled, variant, size }: any) =>
      React.createElement("button", { onClick, disabled, "data-variant": variant }, children),
    Card: ({ children, className }: any) =>
      React.createElement("div", { "data-testid": "card", className }, children),
    EmptyState: ({ message }: any) => React.createElement("div", { "data-testid": "empty-state" }, message),
    ErrorState: ({ message }: any) => React.createElement("div", { "data-testid": "error-state" }, message),
    PageHeader: ({ title, actions }: any) =>
      React.createElement(
        "div",
        null,
        React.createElement("h1", null, title),
        React.createElement("div", { "data-testid": "header-actions" }, actions),
      ),
    TableSkeleton: ({ rows }: any) => React.createElement("div", { "data-testid": "table-skeleton" }),
  };
});

jest.mock("@/lib/auth-context", () => ({
  useAuth: (...args: any[]) => mockUseAuth(...args),
}));

jest.mock("@/lib/api/hooks", () => ({
  useCampaigns: (...args: any[]) => mockUseCampaigns(...args),
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

function campaign(id: string, status: string) {
  return {
    campaign_id: id,
    status,
    control_ids: ["IDENTITY_UNUSED_ACCOUNT"],
    dry_run: false,
    created_by: `op-${id}@example.com`,
    created_at: "2026-06-14T10:00:00",
    plan_hash: "abc123",
    approved_plan_hash: null,
    approved_by: null,
    approved_at: null,
    total_tasks: 2,
    tasks_by_status: {},
    tasks: [],
  };
}

const ACTIVE = [campaign("a1", "AWAITING_APPROVAL"), campaign("a2", "EXECUTING"), campaign("a3", "FAILED")];

const TERMINAL = [campaign("t1", "COMPLETED"), campaign("t2", "CANCELLED"), campaign("t3", "ROLLED_BACK")];

function renderList() {
  const CampaignsPage = require("../page").default;
  return render(React.createElement(CampaignsPage));
}

function setupMixed() {
  mockUseAuth.mockReturnValue({ isSmb: false });
  mockUseCampaigns.mockReturnValue({
    data: [...ACTIVE, ...TERMINAL],
    loading: false,
    error: null,
    refetch: jest.fn(),
  });
}

// ── B2-L1 — active campaigns visible by default ───────────────────────────────

describe("B2-L1 — active campaigns are visible by default", () => {
  beforeEach(() => setupMixed());

  test("AWAITING_APPROVAL campaign created_by is visible", () => {
    renderList();
    expect(screen.getByText("op-a1@example.com")).toBeInTheDocument();
  });

  test("EXECUTING campaign created_by is visible", () => {
    renderList();
    expect(screen.getByText("op-a2@example.com")).toBeInTheDocument();
  });

  test("FAILED campaign created_by is visible", () => {
    renderList();
    expect(screen.getByText("op-a3@example.com")).toBeInTheDocument();
  });
});

// ── B2-L2 — terminal campaigns hidden by default ──────────────────────────────

describe("B2-L2 — terminal campaigns are hidden by default", () => {
  beforeEach(() => setupMixed());

  test("COMPLETED campaign is not shown in default view", () => {
    renderList();
    expect(screen.queryByText("op-t1@example.com")).not.toBeInTheDocument();
  });

  test("CANCELLED campaign is not shown in default view", () => {
    renderList();
    expect(screen.queryByText("op-t2@example.com")).not.toBeInTheDocument();
  });

  test("ROLLED_BACK campaign is not shown in default view", () => {
    renderList();
    expect(screen.queryByText("op-t3@example.com")).not.toBeInTheDocument();
  });
});

// ── B2-L3 — Show Archived toggle reveals terminal campaigns ───────────────────

describe("B2-L3 — Show Archived toggle reveals terminal campaigns", () => {
  beforeEach(() => setupMixed());

  test("Show Archived button is present when there are terminal campaigns", () => {
    renderList();
    expect(screen.getByRole("button", { name: /show archived/i })).toBeInTheDocument();
  });

  test("clicking Show Archived reveals COMPLETED campaign", () => {
    renderList();
    fireEvent.click(screen.getByRole("button", { name: /show archived/i }));
    expect(screen.getByText("op-t1@example.com")).toBeInTheDocument();
  });

  test("clicking Show Archived reveals CANCELLED campaign", () => {
    renderList();
    fireEvent.click(screen.getByRole("button", { name: /show archived/i }));
    expect(screen.getByText("op-t2@example.com")).toBeInTheDocument();
  });

  test("clicking Show Archived reveals ROLLED_BACK campaign", () => {
    renderList();
    fireEvent.click(screen.getByRole("button", { name: /show archived/i }));
    expect(screen.getByText("op-t3@example.com")).toBeInTheDocument();
  });
});

// ── B2-L4 — toggling Hide Archived removes terminal campaigns ─────────────────

describe("B2-L4 — Hide Archived hides terminal campaigns again", () => {
  beforeEach(() => setupMixed());

  test("after Show then Hide, terminal campaigns disappear", () => {
    renderList();
    // Show
    fireEvent.click(screen.getByRole("button", { name: /show archived/i }));
    expect(screen.getByText("op-t1@example.com")).toBeInTheDocument();
    // Hide
    fireEvent.click(screen.getByRole("button", { name: /hide archived/i }));
    expect(screen.queryByText("op-t1@example.com")).not.toBeInTheDocument();
  });
});

// ── B2-L5 — toggle not shown when no terminal campaigns ───────────────────────

describe("B2-L5 — Show Archived toggle absent when no terminal campaigns", () => {
  beforeEach(() => {
    mockUseAuth.mockReturnValue({ isSmb: false });
    mockUseCampaigns.mockReturnValue({
      data: ACTIVE,
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
  });

  test("Show Archived button is absent when all campaigns are active", () => {
    renderList();
    expect(screen.queryByRole("button", { name: /show archived/i })).not.toBeInTheDocument();
  });
});
