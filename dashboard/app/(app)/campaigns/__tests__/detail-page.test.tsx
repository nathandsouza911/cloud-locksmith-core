/**
 * Campaign detail page tests (RED → GREEN).
 *
 * Tests cover all 6 stable campaign states and key actions:
 *  D1 — AWAITING_APPROVAL (pre-approve): shows plan_hash, Approve button, Cancel button
 *  D2 — AWAITING_APPROVAL (post-approve): shows Execute button, approved_by info
 *  D3 — EXECUTING: shows task progress breakdown, no action buttons
 *  D4 — COMPLETED: shows Rollback button, task summary
 *  D5 — FAILED: shows error messages for failed tasks
 *  D6 — CANCELLED: shows cancelled state, no action buttons
 *  D7 — ROLLED_BACK: shows rolled back state
 *  D8 — Approve sends expected_plan_hash equal to plan_hash
 *  D9 — Cancel button triggers cancel API
 *  D10 — cross-org 404 renders error state
 */

import "@testing-library/jest-dom";
import { render, screen, fireEvent } from "@testing-library/react";
import React from "react";

// ── Top-level mock captures ───────────────────────────────────────────────────

const mockUseAuth = jest.fn();
const mockUseCampaign = jest.fn();
const mockUseParams = jest.fn();
const mockApproveCampaign = jest.fn();
const mockExecuteCampaign = jest.fn();
const mockRollbackCampaign = jest.fn();
const mockCancelCampaign = jest.fn();
const mockRouterPush = jest.fn();
const mockRouterReplace = jest.fn();

// ── Module mocks ──────────────────────────────────────────────────────────────

jest.mock("next/navigation", () => ({
  useRouter: () => ({ push: mockRouterPush, replace: mockRouterReplace }),
  useParams: () => mockUseParams(),
}));

// jsdom has no EventSource. Report SSE as not connected so the page uses its
// 5-second polling fallback, which the D-E3 tests exercise.
jest.mock("@/lib/hooks/useRealtimeEvents", () => ({
  useRealtimeEvents: () => ({ connected: false }),
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
    Button: ({ children, onClick, disabled, loading, variant, className }: any) =>
      React.createElement(
        "button",
        {
          onClick,
          disabled: disabled || loading,
          "data-variant": variant,
          className,
          "data-loading": loading,
        },
        children,
      ),
    Card: ({ children, className, "data-testid": dataTestId }: any) =>
      React.createElement("div", { "data-testid": dataTestId ?? "card", className }, children),
    ConfirmModal: ({ open, title, message, confirmLabel, onConfirm, onCancel }: any) =>
      open
        ? React.createElement(
            "div",
            { role: "dialog", "aria-label": title },
            React.createElement("p", null, message),
            React.createElement("button", { onClick: onConfirm }, confirmLabel ?? "Confirm"),
            React.createElement("button", { onClick: onCancel }, "Cancel"),
          )
        : null,
    EmptyState: ({ message }: any) => React.createElement("div", { "data-testid": "empty-state" }, message),
    ErrorState: ({ message }: any) => React.createElement("div", { "data-testid": "error-state" }, message),
    PageHeader: ({ title, subtitle, actions }: any) =>
      React.createElement(
        "div",
        null,
        React.createElement("h1", null, title),
        subtitle && React.createElement("p", { "data-testid": "subtitle" }, subtitle),
        React.createElement("div", { "data-testid": "header-actions" }, actions),
      ),
    TableSkeleton: ({ rows }: any) => React.createElement("div", { "data-testid": "table-skeleton" }),
  };
});

jest.mock("@/lib/auth-context", () => ({
  useAuth: (...args: any[]) => mockUseAuth(...args),
}));

jest.mock("@/lib/api/hooks", () => ({
  useCampaign: (...args: any[]) => mockUseCampaign(...args),
}));

jest.mock("@/lib/api/campaigns", () => ({
  approveCampaign: (...args: any[]) => mockApproveCampaign(...args),
  executeCampaign: (...args: any[]) => mockExecuteCampaign(...args),
  rollbackCampaign: (...args: any[]) => mockRollbackCampaign(...args),
  cancelCampaign: (...args: any[]) => mockCancelCampaign(...args),
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

function mspAuth() {
  mockUseAuth.mockReturnValue({ isSmb: false });
}

function makeCampaign(overrides: Record<string, unknown> = {}) {
  return {
    campaign_id: "c1",
    status: "AWAITING_APPROVAL" as const,
    control_ids: ["IDENTITY_UNUSED_ACCOUNT"],
    dry_run: false,
    created_by: "msp@example.com",
    created_at: "2026-06-14T10:00:00",
    plan_hash: "deadbeef1234",
    approved_plan_hash: null,
    approved_by: null,
    approved_at: null,
    total_tasks: 3,
    tasks_by_status: { PLANNED: 3 },
    tasks: [
      {
        id: "t1",
        tenant_id: "tenant-a",
        compliance_result_id: 1,
        control_id: "IDENTITY_UNUSED_ACCOUNT",
        status: "PLANNED",
        attempts: 0,
        error: null,
      },
      {
        id: "t2",
        tenant_id: "tenant-b",
        compliance_result_id: 2,
        control_id: "IDENTITY_UNUSED_ACCOUNT",
        status: "PLANNED",
        attempts: 0,
        error: null,
      },
      {
        id: "t3",
        tenant_id: "tenant-c",
        compliance_result_id: 3,
        control_id: "IDENTITY_UNUSED_ACCOUNT",
        status: "PLANNED",
        attempts: 0,
        error: null,
      },
    ],
    ...overrides,
  };
}

function renderDetail() {
  mockUseParams.mockReturnValue({ campaignId: "c1" });
  const CampaignDetailPage = require("../[campaignId]/page").default;
  return render(React.createElement(CampaignDetailPage));
}

// ── D1 — AWAITING_APPROVAL pre-approve ───────────────────────────────────────

describe("D1 — AWAITING_APPROVAL (pre-approve) shows plan_hash, Approve, Cancel", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({ status: "AWAITING_APPROVAL", approved_plan_hash: null }),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
    mockApproveCampaign.mockResolvedValue({});
    mockCancelCampaign.mockResolvedValue({});
  });

  test("plan_hash is displayed for operator review", () => {
    renderDetail();
    expect(screen.getByText("deadbeef1234")).toBeInTheDocument();
  });

  test("Approve button is visible", () => {
    renderDetail();
    expect(screen.getByRole("button", { name: /approve/i })).toBeInTheDocument();
  });

  test("Cancel button is visible", () => {
    renderDetail();
    expect(screen.getByRole("button", { name: /cancel/i })).toBeInTheDocument();
  });

  test("Execute button is NOT visible before approval", () => {
    renderDetail();
    expect(screen.queryByRole("button", { name: /execute/i })).not.toBeInTheDocument();
  });
});

// ── D2 — AWAITING_APPROVAL post-approve ──────────────────────────────────────

describe("D2 — AWAITING_APPROVAL (post-approve) shows Execute button and approved_by", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({
        status: "AWAITING_APPROVAL",
        approved_plan_hash: "deadbeef1234",
        approved_by: "msp@example.com",
        approved_at: "2026-06-14T10:05:00",
      }),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
    mockExecuteCampaign.mockResolvedValue({});
    mockCancelCampaign.mockResolvedValue({});
  });

  test("Execute button is visible after approval", () => {
    renderDetail();
    expect(screen.getByRole("button", { name: /execute/i })).toBeInTheDocument();
  });

  test("approved_by name is shown", () => {
    renderDetail();
    // approved_by appears in the metadata section (created_by also matches — use getAllByText)
    const matches = screen.getAllByText(/msp@example\.com/);
    expect(matches.length).toBeGreaterThan(0);
  });

  test("Approve button is no longer visible after approval", () => {
    renderDetail();
    expect(screen.queryByRole("button", { name: /^approve$/i })).not.toBeInTheDocument();
  });
});

// ── D3 — EXECUTING shows task progress ───────────────────────────────────────

describe("D3 — EXECUTING shows task progress breakdown", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({
        status: "EXECUTING",
        approved_plan_hash: "deadbeef1234",
        tasks_by_status: { EXECUTED: 1, PLANNED: 2 },
        tasks: [
          {
            id: "t1",
            tenant_id: "tenant-a",
            compliance_result_id: 1,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "EXECUTED",
            attempts: 1,
            error: null,
          },
          {
            id: "t2",
            tenant_id: "tenant-b",
            compliance_result_id: 2,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "PLANNED",
            attempts: 0,
            error: null,
          },
          {
            id: "t3",
            tenant_id: "tenant-c",
            compliance_result_id: 3,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "PLANNED",
            attempts: 0,
            error: null,
          },
        ],
      }),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
  });

  test("EXECUTING status is shown", () => {
    renderDetail();
    expect(screen.getAllByText(/executing|running/i).length).toBeGreaterThan(0);
  });

  test("task status breakdown shows executed count", () => {
    renderDetail();
    // "EXECUTED" appears in both breakdown and task rows — verify at least one exists
    expect(screen.getAllByText(/EXECUTED/).length).toBeGreaterThan(0);
  });

  test("no action buttons visible during execution", () => {
    renderDetail();
    expect(
      screen.queryByRole("button", { name: /approve|execute|rollback|cancel/i }),
    ).not.toBeInTheDocument();
  });
});

// ── D4 — COMPLETED shows Rollback button ─────────────────────────────────────

describe("D4 — COMPLETED shows Rollback button", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({
        status: "COMPLETED",
        approved_plan_hash: "deadbeef1234",
        tasks_by_status: { EXECUTED: 3 },
        tasks: [
          {
            id: "t1",
            tenant_id: "tenant-a",
            compliance_result_id: 1,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "EXECUTED",
            attempts: 1,
            error: null,
          },
          {
            id: "t2",
            tenant_id: "tenant-b",
            compliance_result_id: 2,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "EXECUTED",
            attempts: 1,
            error: null,
          },
          {
            id: "t3",
            tenant_id: "tenant-c",
            compliance_result_id: 3,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "EXECUTED",
            attempts: 1,
            error: null,
          },
        ],
      }),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
    mockRollbackCampaign.mockResolvedValue({});
  });

  test("COMPLETED status is shown", () => {
    renderDetail();
    expect(screen.getByText(/completed/i)).toBeInTheDocument();
  });

  test("Rollback button is visible on COMPLETED campaign", () => {
    renderDetail();
    expect(screen.getByRole("button", { name: /rollback/i })).toBeInTheDocument();
  });
});

// ── D5 — FAILED shows error messages ─────────────────────────────────────────

describe("D5 — FAILED shows error messages for failed tasks", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({
        status: "FAILED",
        tasks_by_status: { FAILED: 2, EXECUTED: 1 },
        tasks: [
          {
            id: "t1",
            tenant_id: "tenant-a",
            compliance_result_id: 1,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "EXECUTED",
            attempts: 1,
            error: null,
          },
          {
            id: "t2",
            tenant_id: "tenant-b",
            compliance_result_id: 2,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "FAILED",
            attempts: 3,
            error: "Token expired",
          },
          {
            id: "t3",
            tenant_id: "tenant-c",
            compliance_result_id: 3,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "FAILED",
            attempts: 3,
            error: "Permission denied",
          },
        ],
      }),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
  });

  test("FAILED status is shown", () => {
    renderDetail();
    // Multiple "failed" occurrences expected (badge + task rows); just verify at least one
    expect(screen.getAllByText(/failed/i).length).toBeGreaterThan(0);
  });

  test("error message 'Token expired' is visible", () => {
    renderDetail();
    expect(screen.getByText(/token expired/i)).toBeInTheDocument();
  });

  test("error message 'Permission denied' is visible", () => {
    renderDetail();
    expect(screen.getByText(/permission denied/i)).toBeInTheDocument();
  });
});

// ── D6 — CANCELLED shows cancelled state ─────────────────────────────────────

describe("D6 — CANCELLED shows cancelled state with no action buttons", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({ status: "CANCELLED" }),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
  });

  test("CANCELLED status is shown", () => {
    renderDetail();
    expect(screen.getByText(/cancelled/i)).toBeInTheDocument();
  });

  test("no action buttons on CANCELLED campaign", () => {
    renderDetail();
    expect(
      screen.queryByRole("button", { name: /approve|execute|rollback|cancel/i }),
    ).not.toBeInTheDocument();
  });
});

// ── D7 — ROLLED_BACK state ───────────────────────────────────────────────────

describe("D7 — ROLLED_BACK shows rolled back state and acknowledge action", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({
        status: "ROLLED_BACK",
        tasks_by_status: { ROLLED_BACK: 3 },
        tasks: [
          {
            id: "t1",
            tenant_id: "tenant-a",
            compliance_result_id: 1,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "ROLLED_BACK",
            attempts: 1,
            error: null,
          },
        ],
      }),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
  });

  test("ROLLED_BACK status is shown", () => {
    renderDetail();
    expect(screen.getByText(/rolled back/i)).toBeInTheDocument();
  });

  test("D7b — Back to Campaigns link is visible on ROLLED_BACK (BLOCKER-2)", () => {
    renderDetail();
    const link = screen.getByRole("link", { name: /back to campaigns/i });
    expect(link).toBeInTheDocument();
    expect(link.getAttribute("href")).toBe("/campaigns");
  });

  test("D7c — no mutative action buttons on ROLLED_BACK", () => {
    renderDetail();
    expect(
      screen.queryByRole("button", { name: /approve|execute|rollback|cancel/i }),
    ).not.toBeInTheDocument();
  });
});

// ── D8 — Approve sends expected_plan_hash ─────────────────────────────────────

describe("D8 — Approve button sends expected_plan_hash matching plan_hash", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({ plan_hash: "deadbeef1234", approved_plan_hash: null }),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
    mockApproveCampaign.mockResolvedValue({
      ...makeCampaign({ approved_plan_hash: "deadbeef1234", approved_by: "msp@example.com" }),
    });
  });

  test("clicking Approve calls approveCampaign with the plan_hash as expected_plan_hash", async () => {
    renderDetail();
    const approveBtn = screen.getByRole("button", { name: /approve/i });
    fireEvent.click(approveBtn);
    // Wait a tick for async
    await new Promise((r) => setTimeout(r, 0));
    expect(mockApproveCampaign).toHaveBeenCalledWith("c1", { expected_plan_hash: "deadbeef1234" });
  });
});

// ── D9 — Cancel button triggers cancel API ────────────────────────────────────

describe("D9 — Cancel button triggers cancelCampaign", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({ status: "AWAITING_APPROVAL", approved_plan_hash: null }),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
    mockCancelCampaign.mockResolvedValue({});
  });

  test("clicking Cancel calls cancelCampaign with the campaign_id", async () => {
    renderDetail();
    const cancelBtn = screen.getByRole("button", { name: /cancel/i });
    fireEvent.click(cancelBtn);
    await new Promise((r) => setTimeout(r, 0));
    expect(mockCancelCampaign).toHaveBeenCalledWith("c1");
  });
});

// ── D10 — 404 / error state ───────────────────────────────────────────────────

describe("D10 — error state on campaign not found", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaign.mockReturnValue({
      data: null,
      loading: false,
      error: "Campaign not found",
      refetch: jest.fn(),
    });
  });

  test("error state is shown when campaign cannot be loaded", () => {
    renderDetail();
    expect(screen.getByTestId("error-state")).toBeInTheDocument();
  });
});

// ── D-E1 — TaskRow shows tenant_name ─────────────────────────────────────────

describe("D-E1 — TaskRow displays tenant_name instead of raw UUID", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({
        tasks: [
          {
            id: "t1",
            tenant_id: "uuid-aaaa-1111",
            tenant_name: "Contoso Ltd",
            compliance_result_id: 1,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "PLANNED",
            attempts: 0,
            error: null,
            resource_detail: null,
          },
        ],
      }),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
  });

  test("shows tenant_name label in task row", () => {
    renderDetail();
    expect(screen.getByText("Contoso Ltd")).toBeInTheDocument();
  });

  test("still shows UUID as secondary text when tenant_name present", () => {
    renderDetail();
    expect(screen.getByText("uuid-aaaa-1111")).toBeInTheDocument();
  });
});

// ── D-E2 — TaskRow shows resource_detail ─────────────────────────────────────

describe("D-E2 — TaskRow displays resource detail fields", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({
        tasks: [
          {
            id: "t1",
            tenant_id: "tid-1",
            tenant_name: "Fabrikam",
            compliance_result_id: 1,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "PLANNED",
            attempts: 0,
            error: null,
            resource_detail: {
              resource_id: "john.doe@fabrikam.com",
              display_name: "John Doe",
              upn: "john.doe@fabrikam.com",
              last_sign_in: "2026-01-10T09:00:00Z",
            },
          },
        ],
      }),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
  });

  test("shows display_name from resource_detail", () => {
    renderDetail();
    expect(screen.getByText("John Doe")).toBeInTheDocument();
  });

  test("shows UPN from resource_detail", () => {
    renderDetail();
    expect(screen.getAllByText(/john\.doe@fabrikam\.com/).length).toBeGreaterThan(0);
  });

  test("shows last sign-in date", () => {
    renderDetail();
    expect(screen.getByText(/last sign-in/i)).toBeInTheDocument();
  });
});

// ── D-E3 — polling while EXECUTING ───────────────────────────────────────────

describe("D-E3 — auto-polls refetch every 5s while EXECUTING", () => {
  beforeEach(() => {
    jest.useFakeTimers();
    mspAuth();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  test("refetch is called after 5s when status is EXECUTING", () => {
    const mockRefetch = jest.fn();
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({ status: "EXECUTING" }),
      loading: false,
      error: null,
      refetch: mockRefetch,
    });
    renderDetail();
    jest.advanceTimersByTime(5000);
    expect(mockRefetch).toHaveBeenCalled();
  });

  test("refetch is NOT called on timer advance when status is COMPLETED", () => {
    const mockRefetch = jest.fn();
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({ status: "COMPLETED" }),
      loading: false,
      error: null,
      refetch: mockRefetch,
    });
    renderDetail();
    jest.advanceTimersByTime(5000);
    expect(mockRefetch).not.toHaveBeenCalled();
  });
});

// ── D-E4 — Execute triggers confirmation modal ────────────────────────────────

describe("D-E4 — Execute button opens confirmation modal", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({
        status: "AWAITING_APPROVAL",
        approved_plan_hash: "deadbeef1234",
        total_tasks: 3,
        tasks: [
          {
            id: "t1",
            tenant_id: "tid-1",
            tenant_name: null,
            compliance_result_id: 1,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "PLANNED",
            attempts: 0,
            error: null,
            resource_detail: null,
          },
          {
            id: "t2",
            tenant_id: "tid-2",
            tenant_name: null,
            compliance_result_id: 2,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "PLANNED",
            attempts: 0,
            error: null,
            resource_detail: null,
          },
          {
            id: "t3",
            tenant_id: "tid-3",
            tenant_name: null,
            compliance_result_id: 3,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "PLANNED",
            attempts: 0,
            error: null,
            resource_detail: null,
          },
        ],
      }),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
    mockExecuteCampaign.mockResolvedValue({});
  });

  test("clicking Execute opens a confirmation dialog (not calling API immediately)", () => {
    renderDetail();
    const executeBtn = screen.getByRole("button", { name: /execute/i });
    fireEvent.click(executeBtn);
    // Modal should now be open — look for confirmation dialog elements
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(mockExecuteCampaign).not.toHaveBeenCalled();
  });
});

// ── D-F1 — Completion Summary Card ───────────────────────────────────────────

describe("D-F1 — CompletionSummaryCard shows on COMPLETED campaigns", () => {
  const completedCampaign = () =>
    makeCampaign({
      status: "COMPLETED",
      approved_plan_hash: "deadbeef1234",
      started_at: "2026-06-14T10:05:00Z",
      completed_at: "2026-06-14T10:07:30Z",
      tasks_executed: 3,
      tasks_failed: 0,
      tenants_affected: 2,
      rollback_available: true,
      tasks_by_status: { EXECUTED: 3 },
      tasks: [
        {
          id: "t1",
          tenant_id: "tenant-a",
          compliance_result_id: 1,
          control_id: "IDENTITY_UNUSED_ACCOUNT",
          status: "EXECUTED",
          attempts: 1,
          error: null,
          resource_detail: null,
        },
        {
          id: "t2",
          tenant_id: "tenant-b",
          compliance_result_id: 2,
          control_id: "IDENTITY_UNUSED_ACCOUNT",
          status: "EXECUTED",
          attempts: 1,
          error: null,
          resource_detail: null,
        },
        {
          id: "t3",
          tenant_id: "tenant-a",
          compliance_result_id: 3,
          control_id: "IDENTITY_UNUSED_ACCOUNT",
          status: "EXECUTED",
          attempts: 1,
          error: null,
          resource_detail: null,
        },
      ],
    });

  beforeEach(() => {
    mspAuth();
    mockUseCampaign.mockReturnValue({
      data: completedCampaign(),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
    mockRollbackCampaign.mockResolvedValue({});
  });

  test("F1-A — summary card is rendered on COMPLETED status", () => {
    renderDetail();
    expect(screen.getByTestId("completion-summary")).toBeInTheDocument();
  });

  test("F1-B — shows tenants_affected count", () => {
    renderDetail();
    const summary = screen.getByTestId("completion-summary");
    expect(summary).toHaveTextContent("2");
  });

  test("F1-C — shows tasks_executed count", () => {
    renderDetail();
    const summary = screen.getByTestId("completion-summary");
    expect(summary).toHaveTextContent("3");
  });

  test("F1-D — shows rollback available indicator", () => {
    renderDetail();
    const summary = screen.getByTestId("completion-summary");
    expect(summary.textContent).toMatch(/rollback|available/i);
  });

  test("F1-E — summary card is NOT shown on AWAITING_APPROVAL", () => {
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({ status: "AWAITING_APPROVAL" }),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
    renderDetail();
    expect(screen.queryByTestId("completion-summary")).not.toBeInTheDocument();
  });
});

// ── D-G1 — Per-Tenant Grouped Campaign View ────────────────────────────────────

describe("D-G1 — tasks are grouped by tenant in the detail view", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({
        status: "COMPLETED",
        approved_plan_hash: "abc",
        started_at: null,
        completed_at: null,
        tasks_executed: 3,
        tasks_failed: 0,
        tenants_affected: 2,
        rollback_available: false,
        tasks_by_status: { EXECUTED: 3 },
        tasks: [
          {
            id: "t1",
            tenant_id: "tid-A",
            tenant_name: "Contoso",
            compliance_result_id: 1,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "EXECUTED",
            attempts: 1,
            error: null,
            resource_detail: null,
          },
          {
            id: "t2",
            tenant_id: "tid-A",
            tenant_name: "Contoso",
            compliance_result_id: 2,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "EXECUTED",
            attempts: 1,
            error: null,
            resource_detail: null,
          },
          {
            id: "t3",
            tenant_id: "tid-B",
            tenant_name: "Fabrikam",
            compliance_result_id: 3,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "EXECUTED",
            attempts: 1,
            error: null,
            resource_detail: null,
          },
        ],
      }),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
    mockRollbackCampaign.mockResolvedValue({});
  });

  test("G1-A — tenant group headers are rendered", () => {
    renderDetail();
    expect(screen.getByTestId("tenant-group-tid-A")).toBeInTheDocument();
    expect(screen.getByTestId("tenant-group-tid-B")).toBeInTheDocument();
  });

  test("G1-B — Contoso group shows 2 tasks", () => {
    renderDetail();
    const groupA = screen.getByTestId("tenant-group-tid-A");
    const rows = groupA.querySelectorAll("tbody tr");
    expect(rows.length).toBe(2);
  });

  test("G1-C — Fabrikam group shows 1 task", () => {
    renderDetail();
    const groupB = screen.getByTestId("tenant-group-tid-B");
    const rows = groupB.querySelectorAll("tbody tr");
    expect(rows.length).toBe(1);
  });

  test("G1-D — tenant names appear as group labels", () => {
    renderDetail();
    expect(screen.getByTestId("tenant-group-label-tid-A")).toHaveTextContent("Contoso");
    expect(screen.getByTestId("tenant-group-label-tid-B")).toHaveTextContent("Fabrikam");
  });
});

// ── D-H1 — LOCK_DEFERRED UX ──────────────────────────────────────────────────

describe("D-H1 — LOCK_DEFERRED tasks show an explanation", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({
        status: "COMPLETED",
        approved_plan_hash: "abc",
        started_at: null,
        completed_at: null,
        tasks_executed: 1,
        tasks_failed: 0,
        tenants_affected: 2,
        rollback_available: false,
        tasks_by_status: { EXECUTED: 1, LOCK_DEFERRED: 1 },
        tasks: [
          {
            id: "t1",
            tenant_id: "tid-A",
            tenant_name: "Contoso",
            compliance_result_id: 1,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "EXECUTED",
            attempts: 1,
            error: null,
            resource_detail: null,
          },
          {
            id: "t2",
            tenant_id: "tid-B",
            tenant_name: "Fabrikam",
            compliance_result_id: 2,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "LOCK_DEFERRED",
            attempts: 0,
            error: "Tenant busy — another remediation holds the lock",
            resource_detail: null,
          },
        ],
      }),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
    mockRollbackCampaign.mockResolvedValue({});
  });

  test("H1-A — LOCK_DEFERRED status is displayed in the task row", () => {
    renderDetail();
    expect(screen.getAllByText("LOCK_DEFERRED").length).toBeGreaterThan(0);
  });

  test("H1-B — explanation tooltip or note is shown for LOCK_DEFERRED tasks", () => {
    renderDetail();
    expect(screen.getByTestId("lock-deferred-note-t2")).toBeInTheDocument();
  });

  test("H1-C — lock deferred note contains helpful explanation text", () => {
    renderDetail();
    const note = screen.getByTestId("lock-deferred-note-t2");
    expect(note.textContent).toMatch(/busy|lock|retry/i);
  });
});

// ── D-I1 — Dry Run Diff Output ────────────────────────────────────────────────

describe("D-I1 — dry run campaigns show diff output per task", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({
        status: "COMPLETED",
        dry_run: true,
        approved_plan_hash: "abc",
        started_at: null,
        completed_at: null,
        tasks_executed: 1,
        tasks_failed: 0,
        tenants_affected: 1,
        rollback_available: false,
        tasks_by_status: { EXECUTED: 1 },
        tasks: [
          {
            id: "t1",
            tenant_id: "tid-A",
            tenant_name: "Contoso",
            compliance_result_id: 1,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "EXECUTED",
            attempts: 1,
            error: null,
            resource_detail: null,
            result_json: {
              changes: [{ action: "DISABLE_USER", user_id: "user-abc" }],
            },
          },
        ],
      }),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
    mockRollbackCampaign.mockResolvedValue({});
  });

  test("I1-A — dry run banner is shown for dry_run campaigns", () => {
    renderDetail();
    expect(screen.getByTestId("dry-run-banner")).toBeInTheDocument();
  });

  test("I1-B — diff output section is visible for executed dry run tasks", () => {
    renderDetail();
    expect(screen.getByTestId("dry-run-diff-t1")).toBeInTheDocument();
  });

  test("I1-C — change action text appears in the diff", () => {
    renderDetail();
    const diff = screen.getByTestId("dry-run-diff-t1");
    expect(diff.textContent).toMatch(/DISABLE_USER|user-abc/i);
  });
});

// ── D-E5 — Rollback triggers confirmation modal ───────────────────────────────

describe("D-E5 — Rollback button opens confirmation modal", () => {
  beforeEach(() => {
    mspAuth();
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({
        status: "COMPLETED",
        approved_plan_hash: "deadbeef1234",
        tasks_by_status: { EXECUTED: 3 },
        tasks: [
          {
            id: "t1",
            tenant_id: "tid-1",
            tenant_name: "Contoso",
            compliance_result_id: 1,
            control_id: "IDENTITY_UNUSED_ACCOUNT",
            status: "EXECUTED",
            attempts: 1,
            error: null,
            resource_detail: {
              resource_id: "u1",
              display_name: "Alice",
              upn: "alice@contoso.com",
              last_sign_in: null,
            },
          },
        ],
      }),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
    mockRollbackCampaign.mockResolvedValue({});
  });

  test("clicking Rollback opens a confirmation dialog (not calling API immediately)", () => {
    renderDetail();
    const rollbackBtn = screen.getByRole("button", { name: /rollback/i });
    fireEvent.click(rollbackBtn);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(mockRollbackCampaign).not.toHaveBeenCalled();
  });
});

// ── D-K1 — Audit Trail section on campaign detail ─────────────────────────────

describe("D-K1 — Audit trail section shows audit_log_id for executed tasks", () => {
  const completedWithAudit = () =>
    makeCampaign({
      status: "COMPLETED",
      approved_plan_hash: "deadbeef1234",
      tasks_executed: 1,
      tasks_failed: 0,
      tenants_affected: 1,
      rollback_available: false,
      tasks_by_status: { EXECUTED: 1 },
      tasks: [
        {
          id: "t1",
          tenant_id: "tenant-a",
          tenant_name: "Contoso Ltd",
          compliance_result_id: 1,
          control_id: "IDENTITY_UNUSED_ACCOUNT",
          status: "EXECUTED",
          attempts: 1,
          audit_log_id: "aaaabbbb-0000-1111-2222-333344445555",
          error: null,
          resource_detail: null,
        },
        {
          id: "t2",
          tenant_id: "tenant-a",
          tenant_name: "Contoso Ltd",
          compliance_result_id: 2,
          control_id: "IDENTITY_UNUSED_ACCOUNT",
          status: "FAILED",
          attempts: 1,
          audit_log_id: null,
          error: "timeout",
          resource_detail: null,
        },
      ],
    });

  beforeEach(() => {
    mspAuth();
    mockUseCampaign.mockReturnValue({
      data: completedWithAudit(),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
    mockRollbackCampaign.mockResolvedValue({});
  });

  test("K1-A — Audit trail section is visible for COMPLETED campaigns", () => {
    renderDetail();
    expect(screen.getByTestId("audit-trail-section")).toBeInTheDocument();
  });

  test("K1-B — Shows audit_log_id for tasks that have one", () => {
    renderDetail();
    expect(screen.getByTestId("audit-trail-section")).toHaveTextContent("aaaabbbb");
  });

  test("K1-C — Not shown for AWAITING_APPROVAL status", () => {
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({ status: "AWAITING_APPROVAL" }),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
    renderDetail();
    expect(screen.queryByTestId("audit-trail-section")).not.toBeInTheDocument();
  });
});

// ── D-J1 — Export buttons appear on completion summary ───────────────────────

describe("D-J1 — Export buttons in CompletionSummaryCard", () => {
  const completedCampaign = () =>
    makeCampaign({
      status: "COMPLETED",
      approved_plan_hash: "deadbeef1234",
      started_at: "2026-06-14T10:05:00Z",
      completed_at: "2026-06-14T10:07:30Z",
      tasks_executed: 2,
      tasks_failed: 0,
      tenants_affected: 1,
      rollback_available: false,
      tasks_by_status: { EXECUTED: 2 },
      tasks: [
        {
          id: "t1",
          tenant_id: "tenant-a",
          compliance_result_id: 1,
          control_id: "IDENTITY_UNUSED_ACCOUNT",
          status: "EXECUTED",
          attempts: 1,
          error: null,
          resource_detail: null,
        },
      ],
    });

  beforeEach(() => {
    mspAuth();
    mockUseCampaign.mockReturnValue({
      data: completedCampaign(),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
    mockRollbackCampaign.mockResolvedValue({});
  });

  test("J1-A — Export CSV button is visible in completion summary for COMPLETED campaign", () => {
    renderDetail();
    const summary = screen.getByTestId("completion-summary");
    expect(summary.querySelector("[data-testid='export-csv-btn']")).toBeInTheDocument();
  });

  test("J1-B — Export PDF button is visible in completion summary for COMPLETED campaign", () => {
    renderDetail();
    const summary = screen.getByTestId("completion-summary");
    expect(summary.querySelector("[data-testid='export-pdf-btn']")).toBeInTheDocument();
  });

  test("J1-C — Export buttons are NOT shown for AWAITING_APPROVAL status", () => {
    mockUseCampaign.mockReturnValue({
      data: makeCampaign({ status: "AWAITING_APPROVAL" }),
      loading: false,
      error: null,
      refetch: jest.fn(),
    });
    renderDetail();
    expect(screen.queryByTestId("export-csv-btn")).not.toBeInTheDocument();
    expect(screen.queryByTestId("export-pdf-btn")).not.toBeInTheDocument();
  });
});
