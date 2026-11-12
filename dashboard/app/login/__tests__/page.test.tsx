/**
 * Login page: the Microsoft button normally, and only the demo sign-in in demo mode.
 */
import "@testing-library/jest-dom";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import React from "react";

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: jest.fn(), push: jest.fn() }),
}));

jest.mock("@/lib/auth-context", () => ({
  useAuth: () => ({ authed: false, loading: false }),
}));

const mockStartMicrosoftOAuth = jest.fn(() => true);
jest.mock("@/lib/auth", () => ({
  startMicrosoftOAuth: () => mockStartMicrosoftOAuth(),
  POST_LOGIN_LANDING: "/work",
  getApiBaseUrl: () => "http://api.test",
}));

const ORIGINAL_ENV = process.env.NEXT_PUBLIC_DEMO_MODE;

function renderLogin() {
  const LoginPage = require("../page").default;
  return render(React.createElement(LoginPage));
}

afterEach(() => {
  process.env.NEXT_PUBLIC_DEMO_MODE = ORIGINAL_ENV;
  jest.restoreAllMocks();
});

describe("normal mode", () => {
  beforeEach(() => {
    process.env.NEXT_PUBLIC_DEMO_MODE = "false";
  });

  test("shows Microsoft sign-in and no demo sign-in", () => {
    renderLogin();
    expect(screen.getByRole("button", { name: /sign in with microsoft/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /sign in to the demo/i })).not.toBeInTheDocument();
  });
});

describe("demo mode", () => {
  beforeEach(() => {
    process.env.NEXT_PUBLIC_DEMO_MODE = "true";
  });

  test("shows only the demo sign-in", () => {
    renderLogin();
    expect(screen.getByRole("button", { name: /sign in to the demo/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /sign in with microsoft/i })).not.toBeInTheDocument();
  });

  test("posts to the demo login route with credentials and sends nothing else", async () => {
    const fetchMock = jest.fn().mockResolvedValue({ ok: false, status: 404 });
    global.fetch = fetchMock as unknown as typeof fetch;

    renderLogin();
    fireEvent.click(screen.getByRole("button", { name: /sign in to the demo/i }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("http://api.test/api/v1/demo/login");
    expect(init).toEqual({ method: "POST", credentials: "include" });
    expect(await screen.findByRole("alert")).toHaveTextContent(/not running in demo mode/i);
    expect(mockStartMicrosoftOAuth).not.toHaveBeenCalled();
  });
});

describe("DemoBanner", () => {
  test("renders only in demo mode", () => {
    const { DemoBanner } = require("@/components/DemoBanner");
    process.env.NEXT_PUBLIC_DEMO_MODE = "false";
    const { container, rerender } = render(React.createElement(DemoBanner));
    expect(container).toBeEmptyDOMElement();

    process.env.NEXT_PUBLIC_DEMO_MODE = "true";
    rerender(React.createElement(DemoBanner));
    expect(screen.getByRole("status")).toHaveTextContent(/demo mode/i);
  });
});
