/**
 * Campaign create page tests (RED → GREEN).
 *
 *  C1 — control selector renders known SAFE controls
 *  C2 — tenant selector lists MSP's connected tenants
 *  C3 — dry-run toggle renders
 *  C4 — Submit calls createCampaign with correct payload
 *  C5 — Submit is disabled when no controls or tenants selected
 *  C6 — after successful create, redirects to /campaigns/{id}
 *  C7 — SMB users are redirected away
 */

import "@testing-library/jest-dom";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import React from "react";

// ── Top-level mock captures ───────────────────────────────────────────────────

const mockUseAuth = jest.fn();
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
    Card: ({ children, className }: any) =>
      React.createElement("div", { "data-testid": "card", className }, children),
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

jest.mock("@/lib/api/campaigns", () => ({
  createCampaign: (...args: any[]) => mockCreateCampaign(...args),
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

const TWO_TENANTS = [
  { tenant_id: "t1", tenant_name: "Alpha Corp" },
  { tenant_id: "t2", tenant_name: "Beta LLC" },
];

function mspAuth(tenants = TWO_TENANTS) {
  mockUseAuth.mockReturnValue({ isSmb: false, tenants });
}

function smbAuth() {
  mockUseAuth.mockReturnValue({ isSmb: true, tenants: [] });
}

function renderCreate() {
  const CreateCampaignPage = require("../new/page").default;
  return render(React.createElement(CreateCampaignPage));
}

// ── C1 — control selector ─────────────────────────────────────────────────────

describe("C1 — control selector lists SAFE controls", () => {
  beforeEach(() => mspAuth());

  test("IDENTITY_UNUSED_ACCOUNT control is selectable", () => {
    renderCreate();
    // Multiple spans contain this text; verify at least one exists
    expect(screen.getAllByText(/identity_unused_account|unused account/i).length).toBeGreaterThan(0);
  });

  test("C1-B — IDENTITY_GUEST_INVITES_OPEN control appears as a selectable option", () => {
    renderCreate();
    expect(screen.getAllByText(/identity_guest_invites_open|guest invit/i).length).toBeGreaterThan(0);
  });

  test("C1-C — IDENTITY_USER_CONSENT_POLICY control appears as a selectable option", () => {
    renderCreate();
    expect(screen.getAllByText(/identity_user_consent_policy|user consent/i).length).toBeGreaterThan(0);
  });
});

// ── C2 — tenant selector ──────────────────────────────────────────────────────

describe("C2 — tenant selector lists MSP tenants", () => {
  beforeEach(() => mspAuth());

  test("Alpha Corp tenant appears in the tenant selector", () => {
    renderCreate();
    expect(screen.getByText(/alpha corp/i)).toBeInTheDocument();
  });

  test("Beta LLC tenant appears in the tenant selector", () => {
    renderCreate();
    expect(screen.getByText(/beta llc/i)).toBeInTheDocument();
  });
});

// ── C3 — dry-run toggle ───────────────────────────────────────────────────────

describe("C3 — dry-run toggle renders", () => {
  beforeEach(() => mspAuth());

  test("dry run option is visible in the form", () => {
    renderCreate();
    expect(screen.getByText(/dry.?run/i)).toBeInTheDocument();
  });
});

// ── C4 — Submit calls createCampaign ─────────────────────────────────────────

describe("C4 — Submit calls createCampaign with correct payload", () => {
  beforeEach(() => {
    mspAuth();
    mockCreateCampaign.mockResolvedValue({
      campaign_id: "new-camp-uuid",
      status: "AWAITING_APPROVAL",
    });
  });

  test("clicking Submit calls createCampaign with selected control and tenant", async () => {
    renderCreate();

    // Select the first control checkbox / option
    const controlCheckbox = screen.getByLabelText(/identity_unused_account|unused account/i);
    if (!controlCheckbox.getAttribute("checked") && controlCheckbox.getAttribute("type") === "checkbox") {
      fireEvent.click(controlCheckbox);
    }

    // Select the first tenant checkbox
    const tenantCheckbox = screen.getByLabelText(/alpha corp/i);
    if (tenantCheckbox.getAttribute("type") === "checkbox") {
      fireEvent.click(tenantCheckbox);
    }

    // Submit
    const submitBtn = screen.getByRole("button", { name: /create campaign|submit/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(mockCreateCampaign).toHaveBeenCalled();
    });

    const call = mockCreateCampaign.mock.calls[0][0];
    expect(call.control_ids).toContain("IDENTITY_UNUSED_ACCOUNT");
    expect(call.target_tenant_ids).toContain("t1");
  });
});

// ── C5 — Submit disabled when nothing selected ────────────────────────────────

describe("C5 — Submit is disabled when no selections are made", () => {
  beforeEach(() => mspAuth());

  test("Create Campaign button is disabled with nothing selected", () => {
    renderCreate();
    const submitBtn = screen.getByRole("button", { name: /create campaign|submit/i });
    expect(submitBtn).toBeDisabled();
  });
});

// ── C6 — redirect after success ───────────────────────────────────────────────

describe("C6 — redirect to detail page after create", () => {
  beforeEach(() => {
    mspAuth();
    mockCreateCampaign.mockResolvedValue({
      campaign_id: "created-uuid",
      status: "AWAITING_APPROVAL",
    });
  });

  test("router.push is called with the new campaign detail URL", async () => {
    renderCreate();

    const controlCheckbox = screen.getByLabelText(/identity_unused_account|unused account/i);
    if (controlCheckbox.getAttribute("type") === "checkbox") fireEvent.click(controlCheckbox);

    const tenantCheckbox = screen.getByLabelText(/alpha corp/i);
    if (tenantCheckbox.getAttribute("type") === "checkbox") fireEvent.click(tenantCheckbox);

    const submitBtn = screen.getByRole("button", { name: /create campaign|submit/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(mockRouterPush).toHaveBeenCalledWith(expect.stringContaining("created-uuid"));
    });
  });
});

// ── C7 — SMB redirect ────────────────────────────────────────────────────────

describe("C7 — SMB users are redirected from create page", () => {
  beforeEach(() => smbAuth());

  test("Create Campaign form is absent for SMB users", () => {
    renderCreate();
    expect(screen.queryByText(/create campaign|new campaign/i)).not.toBeInTheDocument();
  });
});
