"use client";

import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

import * as authStorage from "@/lib/auth";
import { api } from "@/lib/api/client";
import { getSessionContext } from "@/lib/api/endpoints";
import type { SessionContext } from "@/lib/api/endpoints";
import type { UserTenantAccessItem } from "@/types";

interface AuthUser {
  userId: string;
  email: string;
}

interface MeResponse {
  user_id: string;
  email: string;
  role: string;
  tenants: string[];
}

interface AuthContextValue {
  token: string | null;
  user: AuthUser | null;
  tenants: UserTenantAccessItem[];
  tenantId: string | null;
  selectedTenant: UserTenantAccessItem | null;
  loading: boolean;
  isReady: boolean;
  authed: boolean;
  requiresTenantSelection: boolean;
  isSmb: boolean;
  isPreviewMode: boolean;
  sessionContext: SessionContext | null;
  login: (email: string, password: string) => Promise<void>;
  signup: (email: string, password: string, name?: string, isMsp?: boolean) => Promise<void>;
  logout: () => void | Promise<void>;
  setActiveTenantId: (tenantId: string | null) => void;
  refreshTenants: () => Promise<UserTenantAccessItem[]>;
  error: string | null;
}

const AuthContext = createContext<AuthContextValue>({
  token: null,
  user: null,
  tenants: [],
  tenantId: null,
  selectedTenant: null,
  loading: true,
  isReady: false,
  authed: false,
  requiresTenantSelection: false,
  isSmb: false,
  isPreviewMode: false,
  sessionContext: null,
  login: async () => {},
  signup: async () => {},
  logout: () => {},
  setActiveTenantId: () => {},
  refreshTenants: async () => [],
  error: null,
});

function resolveSelectedTenantId(tenants: UserTenantAccessItem[]): string | null {
  if (tenants.length === 0) {
    authStorage.clearSelectedTenantId();
    return null;
  }

  const storedTenantId = authStorage.getSelectedTenantId();
  const matchingStored = tenants.find((tenant) => tenant.tenant_id === storedTenantId);
  if (matchingStored) {
    return matchingStored.tenant_id;
  }

  if (tenants.length === 1) {
    authStorage.setSelectedTenantId(tenants[0].tenant_id);
    return tenants[0].tenant_id;
  }

  authStorage.clearSelectedTenantId();
  return null;
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [tenants, setTenants] = useState<UserTenantAccessItem[]>([]);
  const [tenantId, setTenantId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [isReady, setIsReady] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sessionContext, setSessionContext] = useState<SessionContext | null>(null);

  const setActiveTenantId = useCallback((nextTenantId: string | null) => {
    if (!nextTenantId) {
      authStorage.clearSelectedTenantId();
      setTenantId(null);
      return;
    }
    authStorage.setSelectedTenantId(nextTenantId);
    setTenantId(nextTenantId);
  }, []);

  const applyTenantList = useCallback((nextTenants: UserTenantAccessItem[]) => {
    setTenants(nextTenants);
    setTenantId(resolveSelectedTenantId(nextTenants));
  }, []);

  const resetAuthState = useCallback((redirect = false) => {
    authStorage.clearToken();
    authStorage.clearSelectedTenantId();
    if (redirect) {
      authStorage.logout();
      return;
    }
    setUser(null);
    setTenants([]);
    setTenantId(null);
    setSessionContext(null);
  }, []);

  const refreshTenants = useCallback(async () => {
    const nextTenants = await api.get<UserTenantAccessItem[]>("/api/v1/tenants/my");
    applyTenantList(nextTenants);
    return nextTenants;
  }, [applyTenantList]);

  // Hydrate auth state from the HttpOnly session cookie via /me.
  // No token is ever stored client-side.
  const completeAuth = useCallback(async () => {
    const me = await api.get<MeResponse>("/api/auth/me");
    if (!me.user_id) throw new Error("Invalid session");
    setUser({ userId: me.user_id, email: me.email });
    const nextTenants = await api.get<UserTenantAccessItem[]>("/api/v1/tenants/my");
    applyTenantList(nextTenants);
    const ctx = await getSessionContext();
    setSessionContext(ctx);
  }, [applyTenantList]);

  useEffect(() => {
    let active = true;

    async function restore() {
      try {
        // Restore is intentionally passive: it only checks the existing session
        // cookie and must never kick off a new OAuth /start request.
        const me = await api.get<MeResponse>("/api/auth/me");
        if (!active) return;
        setUser({ userId: me.user_id, email: me.email });

        const nextTenants = await api.get<UserTenantAccessItem[]>("/api/v1/tenants/my");
        if (!active) return;
        applyTenantList(nextTenants);

        const ctx = await getSessionContext();
        if (!active) return;
        setSessionContext(ctx);
      } catch {
        // 401 = no valid session cookie; not an error condition
        if (active) resetAuthState();
      } finally {
        if (active) {
          setLoading(false);
          setIsReady(true);
        }
      }
    }

    restore();
    return () => {
      active = false;
    };
  }, [applyTenantList, resetAuthState]);

  const login = useCallback(
    async (email: string, password: string) => {
      setError(null);
      setLoading(true);
      try {
        // Backend sets HttpOnly cookie; we ignore the token in the response body.
        await api.post("/api/auth/login-password", { email, password });
        await completeAuth();
      } catch (err) {
        resetAuthState();
        throw err;
      } finally {
        setLoading(false);
        setIsReady(true);
      }
    },
    [completeAuth, resetAuthState],
  );

  const signup = useCallback(
    async (email: string, password: string, name?: string, isMsp?: boolean) => {
      // Verified signup: creates an unverified account and emails a verification
      // link. NO session is issued here — the user must verify their email before
      // they can sign in. (The legacy unverified /auth/signup endpoint is gone.)
      setError(null);
      setLoading(true);
      try {
        await api.post("/api/auth/signup-password", {
          email,
          password,
          ...(name ? { name } : {}),
          ...(isMsp ? { is_msp: true } : {}),
        });
      } catch (err) {
        resetAuthState();
        throw err;
      } finally {
        setLoading(false);
        setIsReady(true);
      }
    },
    [resetAuthState],
  );

  const logout = useCallback(async () => {
    try {
      // Ask the backend to expire the HttpOnly cookie — the frontend cannot do this directly.
      await api.post("/api/auth/logout");
    } catch {
      // Best-effort; proceed with local cleanup regardless
    }
    resetAuthState();
    authStorage.logout("/login");
  }, [resetAuthState]);

  const selectedTenant = useMemo(
    () => tenants.find((tenant) => tenant.tenant_id === tenantId) ?? null,
    [tenantId, tenants],
  );

  // authed is derived from user presence, not a stored token.
  const authed = !loading && !!user;
  const requiresTenantSelection = authed && tenants.length > 1 && !tenantId;
  const isSmb =
    sessionContext !== null
      ? sessionContext.mode === "SMB"
      : tenants.length > 0 && tenants.every((t) => t.account_type === "SMB");
  const isPreviewMode =
    sessionContext !== null ? sessionContext.is_preview : selectedTenant?.role === "READ_ONLY";

  return (
    <AuthContext.Provider
      value={{
        token: null, // JWT is HttpOnly; never exposed to the frontend
        user,
        tenants,
        tenantId,
        selectedTenant,
        loading,
        isReady,
        authed,
        requiresTenantSelection,
        isSmb,
        isPreviewMode: isPreviewMode ?? false,
        sessionContext,
        login,
        signup,
        logout,
        setActiveTenantId,
        refreshTenants,
        error,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
