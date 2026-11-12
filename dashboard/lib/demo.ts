import { getApiBaseUrl } from "@/lib/auth";

/** True when the dashboard is built for the demo stack (NEXT_PUBLIC_DEMO_MODE=true). */
export function isDemoMode(): boolean {
  return process.env.NEXT_PUBLIC_DEMO_MODE === "true";
}

export const DEMO_LANDING = "/dashboard";

/**
 * Sign in as the demo's fictional owner. The API decides who that is; nothing about the
 * identity or tenant is sent from here. The route only exists when the API runs with DEMO_MODE.
 */
export async function signInToDemo(): Promise<void> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/demo/login`, {
    method: "POST",
    credentials: "include",
  });
  if (!res.ok) {
    throw new Error(
      res.status === 404 ? "The API is not running in demo mode." : `Demo sign-in failed (${res.status})`,
    );
  }
}
