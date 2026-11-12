"use client";

import { useEffect } from "react";
import { getApiBaseUrl, setSelectedTenantId, POST_LOGIN_LANDING } from "@/lib/auth";

function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return match ? decodeURIComponent(match[1]) : null;
}

function clearCookie(name: string): void {
  document.cookie = `${name}=; Max-Age=0; Path=/; SameSite=None; Secure`;
}

export default function AuthCallbackPage() {
  useEffect(() => {
    // Consume the non-secret tenant hint set by the backend (60s TTL, UUID only)
    const tenantId = readCookie("cl_post_oauth_tenant");
    if (tenantId) {
      setSelectedTenantId(tenantId);
      clearCookie("cl_post_oauth_tenant");
    }

    // Verify the session via the HttpOnly cookie.
    // window.location.href (full reload) ensures AuthProvider initialises fresh on
    // the destination page with the cookie already present in the browser — avoiding
    // a stale auth-context state carried over from a concurrent restore() failure.
    let cancelled = false;

    async function completeAuth() {
      for (let attempt = 0; attempt < 4; attempt++) {
        if (attempt > 0) {
          await new Promise<void>((r) => setTimeout(r, 500 * attempt));
        }
        if (cancelled) return;

        try {
          const res = await fetch(`${getApiBaseUrl()}/api/auth/me`, {
            credentials: "include",
          });

          if (res.ok) {
            window.location.href = POST_LOGIN_LANDING;
            return;
          }

          // Non-401 responses (5xx, 403, etc.) are not transient — stop retrying.
          if (res.status !== 401) break;

          // 401 = cookie not yet available; fall through to next attempt.
        } catch {
          // Network / CORS error — retry.
        }
      }

      if (!cancelled) {
        window.location.href = "/login?error=auth_failed";
      }
    }

    completeAuth();

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        height: "100vh",
        fontFamily: "sans-serif",
        color: "#6b7280",
      }}
    >
      Completing sign-in…
    </div>
  );
}
