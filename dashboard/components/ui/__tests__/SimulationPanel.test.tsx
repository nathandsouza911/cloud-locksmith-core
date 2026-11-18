import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";

import SimulationPanel from "@/components/ui/SimulationPanel";
import type { SimulationRunResponse } from "@/lib/api/endpoints";

function result(overrides: Partial<SimulationRunResponse>): SimulationRunResponse {
  return {
    status: "completed",
    risk_level: "medium",
    blocked_users: 0,
    mfa_required_users: 12,
    unaffected_users: 2,
    impacted_users: 12,
    impacted_admins: 2,
    newly_affected_users: 0,
    security_defaults_enabled: false,
    conflicts: [],
    impact: { users: 12, admins: 2 },
    ...overrides,
  } as SimulationRunResponse;
}

function renderPanel(simulation: SimulationRunResponse) {
  render(
    <SimulationPanel simulation={simulation} onApply={jest.fn()} onCancel={jest.fn()} showActions={false} />,
  );
}

describe("SimulationPanel", () => {
  test("warns that security defaults already cover users and stop CA enforcement", () => {
    renderPanel(result({ security_defaults_enabled: true }));
    expect(screen.getByText(/security defaults are on/i)).toBeInTheDocument();
    expect(screen.getByText(/turn security defaults off/i)).toBeInTheDocument();
  });

  test("shows no security defaults warning when they are off", () => {
    renderPanel(result({ security_defaults_enabled: false, newly_affected_users: 2 }));
    expect(screen.getByText(/newly affected/i)).toBeInTheDocument();
    expect(screen.queryByText(/security defaults are on/i)).not.toBeInTheDocument();
  });
});
