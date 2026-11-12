/**
 * Sprint 1 — My Work page.
 *
 * The landing screen answers "what work should I do today?" — not
 * "how secure is this tenant?". Product Bible §13.
 */

import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import React from "react";

const mockUseWorkQueue = jest.fn();
const mockUseAuth = jest.fn();
const mockReplace = jest.fn();

jest.mock("next/navigation", () => ({
  useRouter: () => ({ push: jest.fn(), replace: mockReplace }),
}));

jest.mock("@/lib/auth-context", () => ({
  useAuth: () => mockUseAuth(),
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

jest.mock("@/lib/api/hooks", () => ({
  useWorkQueue: () => mockUseWorkQueue(),
}));

import WorkPage from "../page";

const OAUTH_GROUP = {
  workflow_id: "OAUTH_REVIEW",
  workflow_name: "OAuth Review",
  category: "IDENTITY",
  tenant_id: "t1",
  tenant_name: "Contoso",
  item_count: 4,
  priority: "HIGH",
  estimated_minutes: 21,
  recommended_action: "Review and revoke unapproved application consent",
  summary: "4 items to review",
  cadence: "MONTHLY",
  items: [
    {
      id: 1,
      tenant_id: "t1",
      tenant_name: "Contoso",
      title: "Illicit Consent Grants",
      category: "IDENTITY",
      severity: "CRITICAL",
      priority: "HIGH",
      estimated_minutes: 5,
      recommended_action: "Review and revoke unapproved application consent",
      related_control: "IDENTITY_ILLICIT_CONSENT_GRANTS",
      created_at: "2026-07-01T00:00:00",
      compliance_result_id: 1,
      resource_type: "TENANT",
      resource_id: "t1",
      workflow_id: "OAUTH_REVIEW",
      drift_count: 0,
    },
  ],
};

const GUEST_GROUP = {
  ...OAUTH_GROUP,
  workflow_id: "GUEST_REVIEW",
  workflow_name: "Guest Access Review",
  item_count: 2,
  priority: "NORMAL",
  estimated_minutes: 11,
  recommended_action: "Review external guests and remove stale access",
  summary: "2 items to review",
  cadence: "QUARTERLY",
  items: [],
};

function queue(overrides: Record<string, unknown> = {}) {
  return {
    data: {
      tenant_id: "t1",
      tenant_name: "Contoso",
      generated_at: "2026-08-03T08:00:00",
      summary: {
        today_count: 2,
        item_count: 6,
        estimated_minutes: 32,
        high_priority: 1,
        normal_priority: 1,
        completed: 3,
      },
      groups: [OAUTH_GROUP, GUEST_GROUP],
      ...overrides,
    },
    loading: false,
    error: null,
    refetch: jest.fn(),
  };
}

beforeEach(() => {
  mockUseWorkQueue.mockReturnValue(queue());
  mockUseAuth.mockReturnValue({ tenants: [{ tenant_id: "t1" }] });
  mockReplace.mockClear();
});

test("page asks what work to do, not how secure the tenant is", () => {
  render(<WorkPage />);
  expect(screen.getByText(/my work/i)).toBeInTheDocument();
});

test("shows the count of work waiting today", () => {
  render(<WorkPage />);
  const todayTile = screen.getByTestId("stat-today");
  expect(todayTile).toHaveTextContent("2");
});

test("shows total estimated time for the queue", () => {
  render(<WorkPage />);
  expect(screen.getByTestId("stat-estimated")).toHaveTextContent("32");
});

test("shows the high priority count", () => {
  render(<WorkPage />);
  expect(screen.getByTestId("stat-high")).toHaveTextContent("1");
});

test("shows the completed count", () => {
  render(<WorkPage />);
  expect(screen.getByTestId("stat-completed")).toHaveTextContent("3");
});

test("renders one work card per workflow group", () => {
  render(<WorkPage />);
  expect(screen.getAllByTestId("work-card")).toHaveLength(2);
});

test("a work card names the workflow, the client, the item count, the priority, the time and the action", () => {
  render(<WorkPage />);
  const card = screen.getAllByTestId("work-card")[0];

  expect(card).toHaveTextContent("OAuth Review");
  expect(card).toHaveTextContent("Contoso");
  expect(card).toHaveTextContent("4");
  expect(card).toHaveTextContent(/high/i);
  expect(card).toHaveTextContent("21");
  expect(card).toHaveTextContent(/revoke unapproved application consent/i);
});

test("high priority work is rendered before normal priority work", () => {
  render(<WorkPage />);
  const cards = screen.getAllByTestId("work-card");
  expect(cards[0]).toHaveTextContent("OAuth Review");
  expect(cards[1]).toHaveTextContent("Guest Access Review");
});

test("does not render a posture score", () => {
  render(<WorkPage />);
  expect(screen.queryByText(/posture score/i)).not.toBeInTheDocument();
  expect(screen.queryByText(/security score/i)).not.toBeInTheDocument();
});

test("does not render charts", () => {
  const { container } = render(<WorkPage />);
  expect(container.querySelector(".recharts-wrapper")).toBeNull();
  expect(container.querySelector("svg.recharts-surface")).toBeNull();
});

test("empty queue celebrates rather than showing a blank table", () => {
  mockUseWorkQueue.mockReturnValue(
    queue({
      groups: [],
      summary: {
        today_count: 0,
        item_count: 0,
        estimated_minutes: 0,
        high_priority: 0,
        normal_priority: 0,
        completed: 0,
      },
    }),
  );

  render(<WorkPage />);

  expect(screen.queryAllByTestId("work-card")).toHaveLength(0);
  expect(screen.getByTestId("work-empty")).toBeInTheDocument();
});

test("shows a loading state while the queue is being fetched", () => {
  mockUseWorkQueue.mockReturnValue({
    data: null,
    loading: true,
    error: null,
    refetch: jest.fn(),
  });

  render(<WorkPage />);

  expect(screen.getByTestId("work-loading")).toBeInTheDocument();
});

test("surfaces an error instead of pretending there is no work", () => {
  mockUseWorkQueue.mockReturnValue({
    data: null,
    loading: false,
    error: "Request failed",
    refetch: jest.fn(),
  });

  render(<WorkPage />);

  expect(screen.getByText(/request failed/i)).toBeInTheDocument();
  expect(screen.queryByTestId("work-empty")).not.toBeInTheDocument();
});

// ── Sprint 2 — review memory breakdown on the work card ──────────────────────

test("work card shows previously reviewed, new, and changed counts when non-zero", () => {
  mockUseWorkQueue.mockReturnValue(
    queue({
      groups: [{ ...OAUTH_GROUP, reviewed_count: 10, new_count: 4, changed_count: 2 }, GUEST_GROUP],
    }),
  );

  render(<WorkPage />);
  const card = screen.getAllByTestId("work-card")[0];

  expect(card).toHaveTextContent(/10 previously reviewed/i);
  expect(card).toHaveTextContent(/4 new/i);
  expect(card).toHaveTextContent(/2 changed/i);
});

test("work card hides the reviewed line when reviewed_count is zero", () => {
  mockUseWorkQueue.mockReturnValue(
    queue({
      groups: [{ ...OAUTH_GROUP, reviewed_count: 0, new_count: 4, changed_count: 2 }, GUEST_GROUP],
    }),
  );

  render(<WorkPage />);
  const card = screen.getAllByTestId("work-card")[0];

  expect(card).not.toHaveTextContent(/previously reviewed/i);
});

test("work card hides the new line when new_count is zero", () => {
  mockUseWorkQueue.mockReturnValue(
    queue({
      groups: [{ ...OAUTH_GROUP, reviewed_count: 10, new_count: 0, changed_count: 2 }, GUEST_GROUP],
    }),
  );

  render(<WorkPage />);
  const card = screen.getAllByTestId("work-card")[0];

  expect(card).not.toHaveTextContent(/0 new/i);
  expect(card.textContent).not.toMatch(/\bnew\b/i);
});

test("work card hides the changed line when changed_count is zero", () => {
  mockUseWorkQueue.mockReturnValue(
    queue({
      groups: [{ ...OAUTH_GROUP, reviewed_count: 10, new_count: 4, changed_count: 0 }, GUEST_GROUP],
    }),
  );

  render(<WorkPage />);
  const card = screen.getAllByTestId("work-card")[0];

  expect(card).not.toHaveTextContent(/changed/i);
});

test("Review button links to the workflow review screen", () => {
  render(<WorkPage />);
  const card = screen.getAllByTestId("work-card")[0];
  const link = card.querySelector('a[href="/work/OAUTH_REVIEW"]');
  expect(link).toBeInTheDocument();
});

// ── Sprint 4 — run-state badge on the work card ───────────────────────────────

test("work card shows a run-state badge when run_state is set", () => {
  mockUseWorkQueue.mockReturnValue(
    queue({
      groups: [
        { ...OAUTH_GROUP, run_id: "run-1", run_state: "IN_REVIEW", run_started_at: "2026-07-30T10:00:00" },
        GUEST_GROUP,
      ],
    }),
  );

  render(<WorkPage />);
  const card = screen.getAllByTestId("work-card")[0];

  expect(screen.getByTestId("work-card-run-badge")).toBeInTheDocument();
  expect(card).toHaveTextContent(/in review/i);
});

// ── Gate 1 — zero-tenant landing must not look like a broken error ───────────

test("a brand-new user with zero connected tenants is sent to /tenants instead of seeing an error", () => {
  mockUseAuth.mockReturnValue({ tenants: [] });
  mockUseWorkQueue.mockReturnValue({
    data: null,
    loading: false,
    error: "Select a tenant to continue",
    refetch: jest.fn(),
  });

  render(<WorkPage />);

  expect(mockReplace).toHaveBeenCalledWith("/tenants");
  expect(screen.queryByText(/select a tenant to continue/i)).not.toBeInTheDocument();
});

test("a user who has tenants but hit a real queue error still sees the error, not a redirect", () => {
  mockUseAuth.mockReturnValue({ tenants: [{ tenant_id: "t1" }] });
  mockUseWorkQueue.mockReturnValue({
    data: null,
    loading: false,
    error: "Request failed",
    refetch: jest.fn(),
  });

  render(<WorkPage />);

  expect(mockReplace).not.toHaveBeenCalled();
  expect(screen.getByText(/request failed/i)).toBeInTheDocument();
});

test("work card shows no run-state badge when run_state is null", () => {
  mockUseWorkQueue.mockReturnValue(
    queue({
      groups: [{ ...OAUTH_GROUP, run_id: null, run_state: null, run_started_at: null }, GUEST_GROUP],
    }),
  );

  render(<WorkPage />);

  expect(screen.queryByTestId("work-card-run-badge")).not.toBeInTheDocument();
});
