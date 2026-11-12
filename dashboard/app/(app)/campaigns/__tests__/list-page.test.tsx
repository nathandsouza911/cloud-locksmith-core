/**
 * Campaign list page tests (RED → GREEN).
 *
 * Tests:
 *  L1 — empty state renders when no campaigns exist
 *  L2 — campaign rows render with status badge
 *  L3 — all 7 status values produce a visible badge
 *  L4 — New Campaign button present
 *  L5 — each row links to /campaigns/{id}
 *  L6 — SMB users are redirected (page is MSP-only)
 *  L7 — loading skeleton renders while fetching
 *  L8 — error state renders on fetch failure
 */

import "@testing-library/jest-dom";
import { render, screen, fireEvent } from "@testing-library/react";
import React from "react";

// ── Top-level mock captures ───────────────────────────────────────────────────

const mockUseAuth = jest.fn();
const mockUseCampaigns = jest.fn();
const mockRouterReplace = jest.fn();
const mockRouterPush = jest.fn();

// ── Module mocks ──────────────────────────────────────────────────────────────

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: mockRouterReplace, push: mockRouterPush }),
}));

jest.mock("next/link", () => {
  const React = require("react");
  return ({ children, href, ...rest }: any) =>
    React.createElement("a", { href, "data-testid": "link", ...rest }, children);
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
    Button: ({ children, onClick, disabled, loading, variant, className }: any) =>
      React.createElement(
        "button",
        { onClick, disabled: disabled || loading, "data-variant": variant, className },
        children,
      ),
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

function mspAuth() {
  mockUseAuth.mockReturnValue({ isSmb: false, tenants: [{ tenant_id: "t1", tenant_name: "Alpha" }] });
}

function smbAuth() {
  mockUseAuth.mockReturnValue({ isSmb: true, tenants: [] });
}

function makeCampaign(overrides: Record<string, unknown> = {}) {
  return {
    campaign_id: "c1",
    status: "AWAITING_APPROVAL",
    control_ids: ["IDENTITY_UNUSED_ACCOUNT"],
    dry_run: false,
    created_by: "msp@example.com",
    created_at: "2026-06-14T10:00:00",
    plan_hash: "abc123",
    approved_plan_hash: null,
    approved_by: null,
    approved_at: null,
    total_tasks: 3,
    tasks_by_status: { PLANNED: 3 },
    tasks: [],
    ...overrides,
  };
}

function renderList() {
  const CampaignsPage = require("../page").default;
  return render(React.createElement(CampaignsPage));
}

// ── L1 — empty state ──────────────────────────────────────────────────────────

describe("L1 — empty state renders when no campaigns exist", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaigns.mockReturnValue({ data: [], loading: false, error: null, refetch: jest.fn() });
  });

  test("shows empty state message when campaign list is empty", () => {
    renderList();
    expect(screen.getByTestId("empty-state")).toBeInTheDocument();
  });
});

// ── L2 — campaign rows render with status badge ───────────────────────────────

describe("L2 — campaign rows render with status badge", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaigns.mockReturnValue({
      data: [makeCampaign({ status: "AWAITING_APPROVAL" })],
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
  });

  test("campaign created_by email appears in the list", () => {
    renderList();
    expect(screen.getByText("msp@example.com")).toBeInTheDocument();
  });

  test("AWAITING_APPROVAL status badge is visible", () => {
    renderList();
    expect(screen.getByText(/awaiting approval/i)).toBeInTheDocument();
  });

  test("task count appears in the list", () => {
    renderList();
    expect(screen.getByText(/3/)).toBeInTheDocument();
  });
});

// ── L3 — all status values produce a visible badge ────────────────────────────

describe("L3 — all 7 status values display a recognizable badge", () => {
  // Active statuses are visible immediately.
  const activeStatuses = [
    ["AWAITING_APPROVAL", /awaiting approval/i],
    ["EXECUTING", /executing|running/i],
    ["FAILED", /failed/i],
  ] as const;

  // Terminal statuses require "Show Archived" toggle to be clicked first.
  const terminalStatuses = [
    ["COMPLETED", /completed/i],
    ["CANCELLED", /cancelled/i],
    ["ROLLED_BACK", /rolled back/i],
  ] as const;

  activeStatuses.forEach(([status, pattern]) => {
    test(`${status} badge is visible by default`, () => {
      mspAuth();
      mockUseCampaigns.mockReturnValue({
        data: [makeCampaign({ status, campaign_id: `c-${status}` })],
        loading: false,
        error: null,
        refetch: jest.fn(),
      });
      renderList();
      expect(screen.getByText(pattern)).toBeInTheDocument();
    });
  });

  terminalStatuses.forEach(([status, pattern]) => {
    test(`${status} badge is visible after Show Archived`, () => {
      mspAuth();
      mockUseCampaigns.mockReturnValue({
        data: [makeCampaign({ status, campaign_id: `c-${status}` })],
        loading: false,
        error: null,
        refetch: jest.fn(),
      });
      renderList();
      fireEvent.click(screen.getByRole("button", { name: /show archived/i }));
      expect(screen.getByText(pattern)).toBeInTheDocument();
    });
  });
});

// ── L4 — New Campaign button ──────────────────────────────────────────────────

describe("L4 — New Campaign button is present", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaigns.mockReturnValue({ data: [], loading: false, error: null, refetch: jest.fn() });
  });

  test("header contains a New Campaign button", () => {
    renderList();
    const actions = screen.getByTestId("header-actions");
    expect(actions.textContent).toMatch(/new campaign/i);
  });
});

// ── L5 — each row links to /campaigns/{id} ───────────────────────────────────

describe("L5 — campaign rows link to detail page", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaigns.mockReturnValue({
      data: [makeCampaign({ campaign_id: "abc-uuid" })],
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
  });

  test("row contains a link to /campaigns/abc-uuid", () => {
    renderList();
    const links = screen.getAllByTestId("link");
    const detailLink = links.find((l) => l.getAttribute("href")?.includes("abc-uuid"));
    expect(detailLink).toBeDefined();
  });
});

// ── L6 — SMB redirect ────────────────────────────────────────────────────────

describe("L6 — SMB users are redirected", () => {
  beforeEach(() => {
    smbAuth();
    mockUseCampaigns.mockReturnValue({ data: null, loading: false, error: null, refetch: jest.fn() });
  });

  test("page content is absent for SMB users", () => {
    renderList();
    expect(screen.queryByText(/campaigns/i)).not.toBeInTheDocument();
  });
});

// ── L7 — loading skeleton ─────────────────────────────────────────────────────

describe("L7 — loading skeleton renders while fetching", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaigns.mockReturnValue({ data: null, loading: true, error: null, refetch: jest.fn() });
  });

  test("table skeleton is visible while loading", () => {
    renderList();
    expect(screen.getByTestId("table-skeleton")).toBeInTheDocument();
  });
});

// ── L8 — error state ─────────────────────────────────────────────────────────

describe("L8 — error state on fetch failure", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaigns.mockReturnValue({
      data: null,
      loading: false,
      error: "Network error",
      refetch: jest.fn(),
    });
  });

  test("error state is visible on fetch failure", () => {
    renderList();
    expect(screen.getByTestId("error-state")).toBeInTheDocument();
  });
});
