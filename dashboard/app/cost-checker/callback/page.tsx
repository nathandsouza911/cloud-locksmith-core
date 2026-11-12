"use client";

import { useEffect } from "react";

import { getApiBaseUrl, setSelectedTenantId } from "@/lib/auth";

function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return match ? decodeURIComponent(match[1]) : null;
}

function clearCookie(name: string): void {
  document.cookie = `${name}=; Max-Age=0; Path=/; SameSite=None; Secure`;
}

export default function CostCheckerCallbackPage() {
  useEffect(() => {
    const tenantId = readCookie("cl_post_oauth_tenant");
    if (tenantId) {
      setSelectedTenantId(tenantId);
      clearCookie("cl_post_oauth_tenant");
    }

    let cancelled = false;

    async function completeAuth() {
      for (let attempt = 0; attempt < 4; attempt++) {
        if (attempt > 0) {
          await new Promise<void>((resolve) => setTimeout(resolve, 500 * attempt));
        }
        if (cancelled) return;

        try {
          const res = await fetch(`${getApiBaseUrl()}/api/auth/me`, {
            credentials: "include",
          });
          if (res.ok) {
            window.location.href = "/cost-checker";
            return;
          }
          if (res.status !== 401) break;
        } catch {
          // Retry a few times while the cookie settles.
        }
      }

      if (!cancelled) {
        window.location.href = "/cost-checker?error=auth_failed";
      }
    }

    void completeAuth();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950 text-sm text-gray-400">
      Completing secure Microsoft sign-in...
    </div>
  );
}
