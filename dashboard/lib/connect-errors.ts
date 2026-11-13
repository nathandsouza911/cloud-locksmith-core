/**
 * Microsoft sign-in failures arrive as `?connect_error=<code>` (see the backend's
 * `_connect_error_redirect`). On the public login page only the code is used, mapped to
 * fixed text here, so a crafted link cannot put its own words on the sign-in screen.
 */

const CODE_PATTERN = /^[a-z_]{1,64}$/;

const MESSAGES: Record<string, string> = {
  tenant_already_owned:
    "This Microsoft tenant is already connected by another account. Ask that account's owner to give you access.",
  cancelled: "Sign-in was cancelled.",
};

const GENERIC_MESSAGE = "Sign-in could not be completed. Please try again.";

function connectErrorCode(search: string): string | null {
  const code = new URLSearchParams(search).get("connect_error");
  return code && CODE_PATTERN.test(code) ? code : null;
}

/** Where to send a signed-out user, keeping only a valid connect_error code. */
export function loginPathKeepingConnectError(search: string): string {
  const code = connectErrorCode(search);
  return code ? `/login?connect_error=${code}` : "/login";
}

export function signInErrorMessage(code: string | null): string | null {
  if (!code) return null;
  return MESSAGES[code] ?? GENERIC_MESSAGE;
}

export function signInErrorFromSearch(search: string): string | null {
  return signInErrorMessage(connectErrorCode(search));
}
