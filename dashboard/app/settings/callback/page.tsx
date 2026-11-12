"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api/client";
import { setSelectedTenantId } from "@/lib/auth";

function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return match ? decodeURIComponent(match[1]) : null;
}

function clearCookie(name: string): void {
  document.cookie = `${name}=; Max-Age=0; Path=/; SameSite=None; Secure`;
}

export default function SettingsCallbackPage() {
  const router = useRouter();

  useEffect(() => {
    // Consume the non-secret tenant hint set by the backend after MSP tenant connect
    const tenantId = readCookie("cl_post_oauth_tenant");
    if (tenantId) {
      setSelectedTenantId(tenantId);
      clearCookie("cl_post_oauth_tenant");
    }

    // Refresh tenant list so the newly connected tenant appears immediately,
    // then return to settings. The HttpOnly cookie authenticates the request.
    api
      .get("/api/v1/tenants/my")
      .then(() => router.replace("/settings?connected=1"))
      .catch(() => router.replace("/settings?error=connect_failed"));
  }, [router]);

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
      Connecting tenant…
    </div>
  );
}
