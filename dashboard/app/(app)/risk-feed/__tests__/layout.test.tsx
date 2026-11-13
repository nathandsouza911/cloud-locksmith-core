/**
 * Risk Feed layout: the Risk Distribution chart sits above the findings and both use
 * the full width. Side by side, the feed had two thirds of the page, so a finding's
 * text and its fix button could not be read together.
 */
import "@testing-library/jest-dom";
import { render, screen, within } from "@testing-library/react";

import RiskFeedPage from "../page";

jest.mock("next/navigation", () => ({
  useRouter: () => ({ push: jest.fn(), replace: jest.fn() }),
  usePathname: () => "/risk-feed",
  useSearchParams: () => ({ get: () => null, toString: () => "" }),
}));

jest.mock("lucide-react", () => {
  const React = require("react");
  return new Proxy(
    {},
    { get: () => (props: any) => React.createElement("svg", { "data-size": props?.size }) },
  );
});

jest.mock("recharts", () => {
  const React = require("react");
  const passthrough = ({ children }: any) => React.createElement("div", null, children);
  return new Proxy({}, { get: () => passthrough });
});

jest.mock("@/lib/auth-context", () => ({
  useAuth: () => ({ tenantId: "tenant-1", setActiveTenantId: jest.fn(), isPreviewMode: false }),
}));

jest.mock("@/lib/auth", () => ({
  startMicrosoftOAuth: jest.fn(),
  getApiBaseUrl: () => "http://localhost:8000",
}));

jest.mock("@/lib/api/hooks", () => {
  const empty = { data: [], loading: false, error: null, refetch: jest.fn() };
  return {
    useRiskFeed: () => empty,
    useFleetPosture: () => ({ data: null, loading: false, error: null, refetch: jest.fn() }),
    useComplianceResults: () => empty,
    useControlCapabilities: () => ({ data: {}, loading: false, error: null, refetch: jest.fn() }),
    useAttackPaths: () => empty,
    useUsers: () => empty,
    useSimulation: () => ({
      runSimulation: jest.fn(),
      loading: false,
      result: null,
      error: null,
      reset: jest.fn(),
    }),
  };
});

jest.mock("@/lib/api/endpoints", () => ({}));

it("puts the risk distribution above the findings, both full width", () => {
  render(<RiskFeedPage />);
  const layout = screen.getByTestId("risk-feed-layout");
  const [first, second] = Array.from(layout.children) as HTMLElement[];

  expect(within(first).getByText("Risk Distribution")).toBeInTheDocument();
  expect(within(second).getByText("Live Risk Feed")).toBeInTheDocument();

  const classes = (el: Element) => (el.getAttribute("class") ?? "").split(/\s+/);
  expect(classes(layout)).not.toContain("lg:grid-cols-3");
  for (const card of [first, second]) {
    expect(classes(card).some((name) => name.startsWith("lg:col-span"))).toBe(false);
  }
});
