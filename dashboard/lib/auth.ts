"use client";

const SELECTED_TENANT_KEY = "cl_selected_tenant_id";
let microsoftOAuthRedirectInFlight = false;

/**
 * Where an authenticated user lands.
 *
 * Sprint 1: a technician opens the product to see their work, not a posture
 * dashboard (Product Bible §13). Centralised so the auth entry points cannot
 * drift apart — `lib/__tests__/post-login-landing.test.ts` enforces that none
 * of them hardcodes a destination.
 */
export const POST_LOGIN_LANDING = "/work";

function canUseStorage() {
  return typeof window !== "undefined";
}

// JWT is stored in an HttpOnly cookie set by the backend.
// The frontend never reads or stores the token directly.

export function getToken(): string | null {
  return null;
}

export function setToken(_token: string): void {
  // No-op: auth is handled via HttpOnly cookie, not localStorage.
}

export function clearToken(): void {
  if (!canUseStorage()) return;
  // Purge any legacy token left over from previous versions.
  localStorage.removeItem("cl_token");
}

export function getSelectedTenantId(): string | null {
  if (!canUseStorage()) return null;
  return localStorage.getItem(SELECTED_TENANT_KEY);
}

export function setSelectedTenantId(tenantId: string): void {
  if (!canUseStorage()) return;
  localStorage.setItem(SELECTED_TENANT_KEY, tenantId);
}

export function clearSelectedTenantId(): void {
  if (!canUseStorage()) return;
  localStorage.removeItem(SELECTED_TENANT_KEY);
}

export function logout(redirectTo = "/login"): void {
  if (!canUseStorage()) return;
  clearToken();
  clearSelectedTenantId();
  window.location.href = redirectTo;
}

export function getApiBaseUrl(): string {
  const apiUrl = process.env.NEXT_PUBLIC_API_URL;
  if (!apiUrl) {
    console.error("Missing NEXT_PUBLIC_API_URL");
    return "";
  }
  return apiUrl;
}

export function getMicrosoftConnectUrl(): string {
  const connectUrl = process.env.NEXT_PUBLIC_MICROSOFT_CONNECT_URL;
  if (connectUrl) {
    return connectUrl;
  }
  const apiUrl = getApiBaseUrl();
  if (!apiUrl) {
    console.error("Missing NEXT_PUBLIC_API_URL");
    return "";
  }
  return `${apiUrl}/api/v1/auth/microsoft/start`;
}

export type MicrosoftOAuthIntent = "smb_onboarding" | "msp_connect" | "preview" | "cost_checker";

export interface MicrosoftOAuthOptions {
  /** Tenant hint forwarded to Microsoft's authorize endpoint and validated in the callback. */
  tenantId?: string;
  /** Override the backend start URL (e.g. when a full re-auth URL is pre-built). */
  baseUrl?: string;
  /** Frontend route to land on once the backend finishes the OAuth callback. */
  frontendPath?: string;
}

export function startMicrosoftOAuth(
  intent: MicrosoftOAuthIntent = "smb_onboarding",
  options: MicrosoftOAuthOptions = {},
): boolean {
  if (typeof window === "undefined") return false;
  if (microsoftOAuthRedirectInFlight) return false;

  microsoftOAuthRedirectInFlight = true;

  const base = options.baseUrl ?? getMicrosoftConnectUrl();
  const params = new URLSearchParams({ intent });
  if (options.tenantId) params.set("tenant_id", options.tenantId);
  if (options.frontendPath) {
    params.set("frontend_path", options.frontendPath);
  } else if (intent === "cost_checker") {
    params.set("frontend_path", "/cost-checker/callback");
  }

  window.location.assign(`${base}?${params.toString()}`);
  return true;
}
