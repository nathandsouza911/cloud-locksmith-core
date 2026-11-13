import { getApiBaseUrl, getSelectedTenantId, getToken } from "@/lib/auth";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public code?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

const DEMO_DISABLED_DETAIL = "disabled_in_demo_mode";

interface RequestOptions {
  omitTenantHeader?: boolean;
}

const PUBLIC_PATHS = new Set([
  "/api/v1/auth/microsoft/start",
  "/api/v1/auth/microsoft/callback",
  "/api/v1/health",
  "/api/auth/login",
  "/api/auth/login-password",
  "/api/auth/signup-password",
  "/api/auth/verify-email",
  "/api/auth/logout",
  "/api/auth/me",
]);

async function request<T>(path: string, init: RequestInit = {}, options: RequestOptions = {}): Promise<T> {
  const token = getToken();
  const tenantId = getSelectedTenantId();
  const headers = new Headers(init.headers ?? {});
  const isPublicPath = PUBLIC_PATHS.has(path);

  if (!headers.has("Content-Type") && init.body != null) {
    headers.set("Content-Type", "application/json");
  }
  if (token && !isPublicPath) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  if (tenantId && !options.omitTenantHeader && !isPublicPath) {
    headers.set("X-Tenant-ID", tenantId);
  }

  const res = await fetch(`${getApiBaseUrl()}${path}`, {
    credentials: "include",
    ...init,
    headers,
  });

  if (res.status === 401) {
    throw new ApiError(401, "Unauthorized");
  }

  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    let message = text || res.statusText;
    let errorCode: string | undefined;

    try {
      const parsed = JSON.parse(text) as {
        detail?: string | { message?: string };
        message?: string;
        error?: string;
      };
      if (typeof parsed.detail === "string") {
        message = parsed.detail;
      } else if (parsed.detail?.message) {
        message = parsed.detail.message;
      } else if (parsed.message) {
        message = parsed.message;
      }
      errorCode = typeof parsed.error === "string" ? parsed.error : undefined;
    } catch {
      // fall back to plain text
    }

    if (res.status === 403 && !message) {
      message = "Access denied";
    }
    if (res.status === 403 && message === DEMO_DISABLED_DETAIL) {
      // Demo mode refuses every change; say so in plain words (see backend app/demo).
      errorCode = DEMO_DISABLED_DETAIL;
      message = "Changes are disabled in the demo. Connect your own tenant to apply fixes.";
    }
    if (res.status === 400 && message.includes("X-Tenant-ID")) {
      message = "Select a tenant to continue";
    }

    throw new ApiError(res.status, message, errorCode);
  }

  const contentType = res.headers.get("content-type") ?? "";
  if (contentType.includes("application/pdf")) {
    return (await res.blob()) as unknown as T;
  }
  if (contentType.includes("application/json")) {
    return res.json() as Promise<T>;
  }
  return (await res.text()) as unknown as T;
}

export const api = {
  get: <T>(path: string, options?: RequestOptions) => request<T>(path, { method: "GET" }, options),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: "POST",
      body: body != null ? JSON.stringify(body) : undefined,
    }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: "PATCH",
      body: body != null ? JSON.stringify(body) : undefined,
    }),
  delete: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: "DELETE",
      body: body != null ? JSON.stringify(body) : undefined,
    }),
};
