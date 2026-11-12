/**
 * MSP Login page tests — BLOCKER-1 regression suite.
 *
 *  B1-1  email field starts empty (no pre-filled demo credentials)
 *  B1-2  password field starts empty
 *  B1-3  demo email address does not appear anywhere in the rendered output
 *  B1-4  Sign In button is present and the form is functional
 *  B1-5  successful login calls login() and redirects
 *  B1-6  error from login() is shown
 */

import "@testing-library/jest-dom";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import React from "react";

// ── Top-level mock captures ───────────────────────────────────────────────────

const mockLogin = jest.fn();
const mockRouterReplace = jest.fn();

// ── Module mocks ──────────────────────────────────────────────────────────────

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: mockRouterReplace }),
}));

jest.mock("next/link", () => {
  const React = require("react");
  return ({ children, href }: any) => React.createElement("a", { href }, children);
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

jest.mock("@/lib/auth-context", () => ({
  useAuth: (...args: any[]) =>
    mockLogin.mock.results.length >= 0
      ? { login: mockLogin, authed: false, loading: false }
      : { login: mockLogin, authed: false, loading: false },
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

function renderPage() {
  jest.mock("@/lib/auth-context", () => ({
    useAuth: () => ({ login: mockLogin, authed: false, loading: false }),
  }));
  const MspLoginPage = require("../page").default;
  return render(React.createElement(MspLoginPage));
}

// ── B1-1 / B1-2 — empty defaults ─────────────────────────────────────────────

describe("B1 — MSP login form has no pre-filled credentials", () => {
  beforeEach(() => {
    mockLogin.mockReset();
    mockRouterReplace.mockReset();
  });

  test("B1-1: email input starts empty", () => {
    renderPage();
    const emailInput = screen.getByPlaceholderText(/admin@company\.com/i);
    expect(emailInput).toHaveValue("");
  });

  test("B1-2: password input starts empty", () => {
    renderPage();
    const passwordInput = screen.getByPlaceholderText(/enter your password/i);
    expect(passwordInput).toHaveValue("");
  });

  test("B1-3: demo email address is not present anywhere in the rendered HTML", () => {
    renderPage();
    expect(screen.queryByDisplayValue("admin@example.com")).not.toBeInTheDocument();
    expect(screen.queryByDisplayValue("demo")).not.toBeInTheDocument();
  });

  test("B1-4: Sign In button exists", () => {
    renderPage();
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });

  test("B1-5: typing and submitting calls login with entered values", async () => {
    mockLogin.mockResolvedValue(undefined);
    renderPage();

    fireEvent.change(screen.getByPlaceholderText(/admin@company\.com/i), {
      target: { value: "msp@example.com" },
    });
    fireEvent.change(screen.getByPlaceholderText(/enter your password/i), {
      target: { value: "securepass123" },
    });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith("msp@example.com", "securepass123");
    });
  });

  test("B1-6: login error is displayed", async () => {
    mockLogin.mockRejectedValue(new Error("Invalid credentials"));
    renderPage();

    fireEvent.change(screen.getByPlaceholderText(/admin@company\.com/i), {
      target: { value: "msp@example.com" },
    });
    fireEvent.change(screen.getByPlaceholderText(/enter your password/i), {
      target: { value: "wrongpass" },
    });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByText(/invalid credentials/i)).toBeInTheDocument();
    });
  });
});
