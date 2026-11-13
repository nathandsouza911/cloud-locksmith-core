import "@testing-library/jest-dom";
import { fireEvent, render, screen } from "@testing-library/react";
import SettingsPage from "../page";

// ── External mocks ────────────────────────────────────────────────────────────

jest.mock("next/navigation", () => ({
  useRouter: () => ({ push: jest.fn() }),
  useSearchParams: () => ({ get: () => null }),
}));

jest.mock("lucide-react", () => {
  const React = require("react");
  const stub = ({ size, ...rest }: any) => React.createElement("svg", rest);
  return {
    User: stub,
    Key: stub,
    Bell: stub,
    Shield: stub,
    Save: stub,
    CheckCircle: stub,
    RefreshCw: stub,
    Trash2: stub,
  };
});

jest.mock("@/components/ui", () => {
  const React = require("react");
  return {
    Card: ({ children, className }: any) =>
      React.createElement("div", { "data-testid": "card", className }, children),
    PageHeader: ({ title, subtitle, actions }: any) =>
      React.createElement(
        "div",
        null,
        React.createElement("h1", null, title),
        subtitle && React.createElement("p", null, subtitle),
        actions && React.createElement("div", null, actions),
      ),
    Button: ({ children, onClick, disabled, loading, variant, size, className, ...rest }: any) =>
      React.createElement(
        "button",
        { onClick, disabled: disabled || loading, "data-variant": variant, ...rest },
        children,
      ),
    SimulationPanel: ({ loading }: any) =>
      React.createElement("div", { "data-testid": "simulation-panel" }, loading ? "Loading..." : "Result"),
  };
});

const mockUseAuth = jest.fn();

jest.mock("@/lib/auth-context", () => ({
  useAuth: () => mockUseAuth(),
}));

jest.mock("@/lib/auth", () => ({
  getApiBaseUrl: () => "http://localhost:8000",
  startMicrosoftOAuth: jest.fn(),
}));

jest.mock("@/lib/api/hooks", () => ({
  useSimulation: () => ({
    runSimulation: jest.fn(),
    loading: false,
    result: null,
  }),
  useUsers: () => mockUsersState,
}));

let mockUsersState: { data: unknown[] | null; loading: boolean; error: string | null } = {
  data: [],
  loading: false,
  error: null,
};

jest.mock("@/lib/api/endpoints", () => ({
  deleteTenant: jest.fn(),
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

function renderSettings() {
  return render(<SettingsPage />);
}

function authWith(overrides: Record<string, unknown> = {}) {
  return {
    user: { email: "admin@example.com", userId: "u1" },
    logout: jest.fn(),
    tenantId: "tenant-abc",
    isSmb: false,
    loading: false,
    tenants: [],
    selectedTenant: null,
    token: null,
    sessionContext: null,
    switchTenant: jest.fn(),
    ...overrides,
  };
}

beforeEach(() => {
  mockUseAuth.mockReturnValue(authWith());
  mockUsersState = { data: [], loading: false, error: null };
});

// ── Tests: removed elements (RED on current, GREEN on new) ───────────────────

describe("removed elements", () => {
  test("does not render a Notifications tab", () => {
    renderSettings();
    expect(screen.queryByRole("button", { name: /^notifications$/i })).not.toBeInTheDocument();
    // Also confirm the text "Notifications" is absent as navigation
    const tabButtons = screen.queryAllByRole("button");
    const notifTab = tabButtons.find((btn) => /^notifications$/i.test(btn.textContent?.trim() ?? ""));
    expect(notifTab).toBeUndefined();
  });

  test("does not render a Save Changes button", () => {
    renderSettings();
    expect(screen.queryByRole("button", { name: /save changes/i })).not.toBeInTheDocument();
  });

  test("does not render a Display Name input or label", () => {
    renderSettings();
    expect(screen.queryByText(/display name/i)).not.toBeInTheDocument();
  });

  test("does not render an Organization Name input or label", () => {
    renderSettings();
    expect(screen.queryByText(/organization name/i)).not.toBeInTheDocument();
  });

  test("does not render an API Base URL field", () => {
    renderSettings();
    expect(screen.queryByText(/api base url/i)).not.toBeInTheDocument();
  });

  test("does not render Alert Thresholds section", () => {
    renderSettings();
    expect(screen.queryByText(/alert thresholds/i)).not.toBeInTheDocument();
  });

  test("does not render a Scan Interval dropdown", () => {
    renderSettings();
    expect(screen.queryByText(/scan interval/i)).not.toBeInTheDocument();
  });

  test("does not render an Audit Log Retention dropdown", () => {
    renderSettings();
    expect(screen.queryByText(/audit log retention/i)).not.toBeInTheDocument();
  });

  test("does not render Remediation Policy toggles", () => {
    renderSettings();
    expect(screen.queryByText(/remediation policy/i)).not.toBeInTheDocument();
  });
});

// ── Tests: kept elements always visible without tab navigation ────────────────

describe("kept elements — always visible", () => {
  test("renders the Settings page heading", () => {
    renderSettings();
    expect(screen.getByRole("heading", { name: /settings/i })).toBeInTheDocument();
  });

  test("renders Microsoft 365 Connection section", () => {
    renderSettings();
    expect(screen.getByText(/microsoft 365 connection/i)).toBeInTheDocument();
  });

  test("renders Re-authorize Microsoft OAuth button", () => {
    renderSettings();
    expect(screen.getByRole("button", { name: /re-authorize microsoft oauth/i })).toBeInTheDocument();
  });

  test("has no subscription plan or billing controls", () => {
    renderSettings();
    expect(screen.queryByText(/subscription plan/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/billing/i)).not.toBeInTheDocument();
  });

  test("renders Simulate Fix button", () => {
    renderSettings();
    expect(screen.getByRole("button", { name: /simulate fix/i })).toBeInTheDocument();
  });

  test("Simulate Fix shows why users are unavailable instead of 'still loading'", async () => {
    const reason = "This needs a full connect to Microsoft.";
    mockUsersState = { data: null, loading: false, error: reason };
    renderSettings();

    fireEvent.click(screen.getByRole("button", { name: /simulate fix/i }));

    expect(await screen.findByText(reason)).toBeInTheDocument();
    expect(screen.queryByText(/still loading/i)).not.toBeInTheDocument();
  });

  test("renders Sign Out button", () => {
    renderSettings();
    expect(screen.getByRole("button", { name: /sign out/i })).toBeInTheDocument();
  });
});

// ── Tests: SMB-specific Delete Account ────────────────────────────────────────

describe("Delete Account — non-SMB user", () => {
  test("does not render Delete Account button for non-SMB users", () => {
    renderSettings();
    // The card heading should be absent when isSmb=false
    expect(screen.queryByText(/delete account/i)).not.toBeInTheDocument();
  });
});

// ── Tests: Gate 1 — Microsoft connection badge reflects real tenant state ─────

describe("Microsoft 365 Connection badge — Gate 1", () => {
  test("shows 'Not connected' when no tenant has been added yet", () => {
    mockUseAuth.mockReturnValue(authWith({ tenants: [], selectedTenant: null }));
    renderSettings();
    expect(screen.getByText(/not connected/i)).toBeInTheDocument();
    expect(screen.queryByText(/^connected$/i)).not.toBeInTheDocument();
  });

  test("shows 'Connected' when the selected tenant does not need re-auth", () => {
    mockUseAuth.mockReturnValue(
      authWith({
        tenants: [{ tenant_id: "t1", tenant_name: "Contoso", role: "OWNER", needs_reauth: false }],
        selectedTenant: { tenant_id: "t1", tenant_name: "Contoso", role: "OWNER", needs_reauth: false },
      }),
    );
    renderSettings();
    expect(screen.getByText(/^connected$/i)).toBeInTheDocument();
  });

  test("shows 'Needs Re-auth' instead of a false 'Connected' when the token has expired", () => {
    mockUseAuth.mockReturnValue(
      authWith({
        tenants: [{ tenant_id: "t1", tenant_name: "Contoso", role: "OWNER", needs_reauth: true }],
        selectedTenant: { tenant_id: "t1", tenant_name: "Contoso", role: "OWNER", needs_reauth: true },
      }),
    );
    renderSettings();
    expect(screen.getByText(/needs re-auth/i)).toBeInTheDocument();
    expect(screen.queryByText(/^connected$/i)).not.toBeInTheDocument();
  });
});
