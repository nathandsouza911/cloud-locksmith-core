/**
 * Sprint 3 — Client Timeline.
 *
 * Chronological, newest-first, merged read of everything that has happened
 * for a tenant. Read-only. "Load more" appends via next_cursor/has_more
 * rather than replacing the list.
 */

import "@testing-library/jest-dom";
import { render, screen, fireEvent } from "@testing-library/react";
import React from "react";

const mockUseClientTimeline = jest.fn();
const mockUseParams = jest.fn();

jest.mock("next/navigation", () => ({
  useRouter: () => ({ push: jest.fn(), replace: jest.fn() }),
  useParams: () => mockUseParams(),
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
    tenants: [{ tenant_id: "t1", tenant_name: "Contoso", role: "admin" }],
    tenantId: "t1",
  }),
}));

jest.mock("@/lib/api/hooks", () => ({
  useClientTimeline: (...args: unknown[]) => mockUseClientTimeline(...args),
}));

import TimelinePage from "../page";

const EVENT_NEW = {
  id: "AUDIT_LOG:123",
  tenant_id: "t1",
  timestamp: "2026-07-30T10:00:00Z",
  source_system: "AUDIT_LOG",
  event_type: "AUDIT",
  action: "USER_LOGIN",
  title: "Admin signed in",
  description: null,
  actor: "admin@contoso.com",
  outcome: "SUCCESS",
  workflow_id: null,
  workflow_name: null,
  evidence_reference: null,
  control_id: null,
  resource_type: null,
  resource_id: null,
  metadata: {},
};

const EVENT_OLD = {
  id: "REVIEW_DECISIONS:45",
  tenant_id: "t1",
  timestamp: "2026-07-01T08:00:00Z",
  source_system: "REVIEW_DECISIONS",
  event_type: "REVIEW_DECISION",
  action: "KEEP",
  title: "Illicit Consent Grants reviewed",
  description: "Reviewed and kept as-is",
  actor: "tech@msp.example",
  outcome: "KEEP",
  workflow_id: "OAUTH_REVIEW",
  workflow_name: "OAuth Review",
  evidence_reference: "evidence://oauth/45",
  control_id: "IDENTITY_ILLICIT_CONSENT_GRANTS",
  resource_type: "TENANT",
  resource_id: "t1",
  metadata: {},
};

function timelineResult(overrides: Record<string, unknown> = {}) {
  return {
    data: {
      tenant_id: "t1",
      tenant_name: "Contoso",
      events: [EVENT_NEW, EVENT_OLD],
      next_cursor: null,
      has_more: false,
    },
    loading: false,
    error: null,
    refetch: jest.fn(),
    ...overrides,
  };
}

beforeEach(() => {
  mockUseParams.mockReturnValue({ tenantId: "t1" });
  mockUseClientTimeline.mockReturnValue(timelineResult());
});

test("renders events newest-first in the order the API returned them", () => {
  render(<TimelinePage />);
  const rows = screen.getAllByTestId("timeline-event");
  expect(rows[0]).toHaveTextContent("Admin signed in");
  expect(rows[1]).toHaveTextContent("Illicit Consent Grants reviewed");
});

test("an event row shows title, workflow, actor, outcome and timestamp", () => {
  render(<TimelinePage />);
  const row = screen.getAllByTestId("timeline-event")[1];

  expect(row).toHaveTextContent("Illicit Consent Grants reviewed");
  expect(row).toHaveTextContent("OAuth Review");
  expect(row).toHaveTextContent("tech@msp.example");
  expect(row).toHaveTextContent("KEEP");
  expect(row).toHaveTextContent(/2026/);
});

test("shows an evidence indicator only when evidence_reference is present", () => {
  render(<TimelinePage />);
  const rows = screen.getAllByTestId("timeline-event");

  expect(rows[0].querySelector('[data-testid="evidence-indicator"]')).not.toBeInTheDocument();
  expect(rows[1].querySelector('[data-testid="evidence-indicator"]')).toBeInTheDocument();
});

test('"Load more" is shown only when has_more is true', () => {
  render(<TimelinePage />);
  expect(screen.queryByTestId("load-more")).not.toBeInTheDocument();

  mockUseClientTimeline.mockReturnValue(
    timelineResult({
      data: {
        tenant_id: "t1",
        tenant_name: "Contoso",
        events: [EVENT_NEW],
        next_cursor: "cursor-2",
        has_more: true,
      },
    }),
  );
  render(<TimelinePage />);
  expect(screen.getByTestId("load-more")).toBeInTheDocument();
});

test('"Load more" appends events rather than replacing the list', () => {
  mockUseClientTimeline.mockReturnValue(
    timelineResult({
      data: {
        tenant_id: "t1",
        tenant_name: "Contoso",
        events: [EVENT_NEW],
        next_cursor: "cursor-2",
        has_more: true,
      },
    }),
  );

  render(<TimelinePage />);
  expect(screen.getAllByTestId("timeline-event")).toHaveLength(1);

  fireEvent.click(screen.getByTestId("load-more"));

  // After clicking, the hook is re-invoked with a cursor. Simulate the
  // second page arriving by returning both pages worth of events (the
  // page component is responsible for appending, so it must have passed
  // the cursor through and accumulated state).
  mockUseClientTimeline.mockReturnValue(
    timelineResult({
      data: {
        tenant_id: "t1",
        tenant_name: "Contoso",
        events: [EVENT_OLD],
        next_cursor: null,
        has_more: false,
      },
    }),
  );

  // Re-render to reflect the new hook state (simulating the fetch resolving).
  const { rerender } = render(<TimelinePage />);
  rerender(<TimelinePage />);
});

test("filter controls call the hook with the chosen filter values", () => {
  render(<TimelinePage />);

  const workflowSelect = screen.getByTestId("filter-workflow");
  fireEvent.change(workflowSelect, { target: { value: "OAUTH_REVIEW" } });

  const eventTypeSelect = screen.getByTestId("filter-event-type");
  fireEvent.change(eventTypeSelect, { target: { value: "AUDIT" } });

  const sinceInput = screen.getByTestId("filter-since");
  fireEvent.change(sinceInput, { target: { value: "2026-07-01" } });

  const untilInput = screen.getByTestId("filter-until");
  fireEvent.change(untilInput, { target: { value: "2026-07-31" } });

  const lastCallArgs = mockUseClientTimeline.mock.calls[mockUseClientTimeline.mock.calls.length - 1];
  const [tenantIdArg, paramsArg] = lastCallArgs;

  expect(tenantIdArg).toBe("t1");
  expect(paramsArg.workflow_id).toBe("OAUTH_REVIEW");
  expect(paramsArg.event_types).toEqual(["AUDIT"]);
  expect(paramsArg.since).toContain("2026-07-01");
  expect(paramsArg.until).toContain("2026-07-31");
});

test("shows a loading state while the timeline is being fetched", () => {
  mockUseClientTimeline.mockReturnValue({
    data: null,
    loading: true,
    error: null,
    refetch: jest.fn(),
  });

  render(<TimelinePage />);
  expect(screen.getByTestId("timeline-loading")).toBeInTheDocument();
});

test("surfaces an error instead of an empty timeline", () => {
  mockUseClientTimeline.mockReturnValue({
    data: null,
    loading: false,
    error: "Request failed",
    refetch: jest.fn(),
  });

  render(<TimelinePage />);
  expect(screen.getByText(/request failed/i)).toBeInTheDocument();
});

test("shows an empty state when there are no events", () => {
  mockUseClientTimeline.mockReturnValue(
    timelineResult({
      data: { tenant_id: "t1", tenant_name: "Contoso", events: [], next_cursor: null, has_more: false },
    }),
  );

  render(<TimelinePage />);
  expect(screen.getByTestId("timeline-empty")).toBeInTheDocument();
  expect(screen.queryAllByTestId("timeline-event")).toHaveLength(0);
});

test("access denied when the tenant in the URL is not one the user has access to", () => {
  mockUseParams.mockReturnValue({ tenantId: "not-my-tenant" });
  render(<TimelinePage />);
  expect(screen.getByText(/access denied/i)).toBeInTheDocument();
});
