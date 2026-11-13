import { loginPathKeepingConnectError, signInErrorMessage } from "@/lib/connect-errors";

describe("loginPathKeepingConnectError", () => {
  it("keeps only the connect_error code when bouncing to /login", () => {
    expect(
      loginPathKeepingConnectError("?connect_error=tenant_already_owned&connect_error_message=anything"),
    ).toBe("/login?connect_error=tenant_already_owned");
  });

  it("is plain /login when there is no error", () => {
    expect(loginPathKeepingConnectError("")).toBe("/login");
    expect(loginPathKeepingConnectError("?foo=bar")).toBe("/login");
  });

  it("drops a code that is not a simple identifier", () => {
    expect(loginPathKeepingConnectError("?connect_error=%3Cscript%3E")).toBe("/login");
  });
});

describe("signInErrorMessage", () => {
  it("explains an owned tenant without naming anyone", () => {
    const message = signInErrorMessage("tenant_already_owned");
    expect(message).toMatch(/already connected by another account/i);
  });

  it("uses fixed text for unknown codes, never text from the URL", () => {
    expect(signInErrorMessage("connection_failed")).toBe("Sign-in could not be completed. Please try again.");
  });

  it("is null without a code", () => {
    expect(signInErrorMessage(null)).toBeNull();
  });
});
