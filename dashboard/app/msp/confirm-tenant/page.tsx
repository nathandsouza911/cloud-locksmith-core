"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { AlertCircle, CheckCircle2, ShieldCheck } from "lucide-react";

import { getApiBaseUrl, POST_LOGIN_LANDING } from "@/lib/auth";
import { useAuth } from "@/lib/auth-context";

interface PendingMspConnect {
  session_id: string;
  tenant_id: string;
  tenant_name: string | null;
  domain: string | null;
  existing_organization_id: string | null;
  msp_organization_id: string | null;
}

function MspConfirmTenantBody() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { refreshTenants } = useAuth();
  const sessionId = searchParams.get("session_id");
  const [pending, setPending] = useState<PendingMspConnect | null>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const tenantLabel = useMemo(() => {
    if (!pending) return "";
    return pending.tenant_name || pending.domain || pending.tenant_id;
  }, [pending]);

  useEffect(() => {
    let active = true;

    async function loadPending() {
      if (!sessionId) {
        setError("Missing confirmation session.");
        setLoading(false);
        return;
      }
      try {
        const response = await fetch(
          `${getApiBaseUrl()}/api/v1/auth/microsoft/msp-connect/pending/${encodeURIComponent(sessionId)}`,
          { credentials: "include" },
        );
        if (!response.ok) {
          throw new Error("This connection request is no longer available.");
        }
        const data = (await response.json()) as PendingMspConnect;
        if (active) setPending(data);
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : "Unable to load connection request.");
      } finally {
        if (active) setLoading(false);
      }
    }

    loadPending();
    return () => {
      active = false;
    };
  }, [sessionId]);

  async function confirmAttach() {
    if (!sessionId) return;
    setSubmitting(true);
    setError(null);
    try {
      const response = await fetch(`${getApiBaseUrl()}/api/v1/auth/microsoft/msp-connect/confirm`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_id: sessionId }),
      });
      if (!response.ok) {
        throw new Error("Tenant attachment was not confirmed.");
      }
      // AuthProvider fetches the tenant list once, at mount -- router.replace()
      // is a client-side SPA navigation and does not remount it, so without
      // this the newly attached tenant is invisible until a full page
      // refresh. Refresh the cached list before navigating away.
      await refreshTenants();
      router.replace(POST_LOGIN_LANDING);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Tenant attachment failed.");
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
      <div className="w-full max-w-lg rounded-lg border border-gray-800 bg-gray-900 p-8 shadow-2xl">
        <div className="mb-7 flex items-start gap-4">
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-lg bg-cyan-600 text-white">
            <ShieldCheck size={25} />
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-tight text-white">Confirm Tenant Attachment</h1>
            <p className="mt-1 text-sm text-gray-400">
              Review the Microsoft tenant before adding it to this MSP account.
            </p>
          </div>
        </div>

        {loading ? (
          <div className="flex items-center gap-3 rounded-lg border border-gray-800 bg-gray-950 px-4 py-4 text-sm text-gray-400">
            <span className="h-4 w-4 rounded-full border-2 border-cyan-500 border-t-transparent animate-spin" />
            Loading connection request...
          </div>
        ) : error ? (
          <div className="flex gap-3 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-4 text-sm text-red-300">
            <AlertCircle size={17} className="mt-0.5 shrink-0" />
            <span>{error}</span>
          </div>
        ) : pending ? (
          <div className="space-y-5">
            <div className="rounded-lg border border-gray-800 bg-gray-950">
              <div className="border-b border-gray-800 px-4 py-3">
                <p className="text-sm font-medium text-white">{tenantLabel}</p>
                <p className="mt-0.5 text-xs text-gray-500">{pending.domain || pending.tenant_id}</p>
              </div>
              <div className="grid gap-3 px-4 py-4 text-sm sm:grid-cols-2">
                <div>
                  <p className="text-xs uppercase tracking-wider text-gray-500">Tenant ID</p>
                  <p className="mt-1 break-all font-mono text-xs text-gray-300">{pending.tenant_id}</p>
                </div>
                <div>
                  <p className="text-xs uppercase tracking-wider text-gray-500">Attachment</p>
                  <p className="mt-1 text-gray-300">
                    {pending.existing_organization_id ? "Existing tenant" : "New tenant"}
                  </p>
                </div>
              </div>
            </div>

            <div className="flex flex-col-reverse gap-3 sm:flex-row sm:justify-end">
              <button
                type="button"
                onClick={() => router.replace(POST_LOGIN_LANDING)}
                className="rounded-lg border border-gray-700 px-4 py-2.5 text-sm font-medium text-gray-300 transition-colors hover:border-gray-600 hover:bg-gray-800"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={confirmAttach}
                disabled={submitting}
                className="inline-flex items-center justify-center gap-2 rounded-lg bg-cyan-600 px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-cyan-500 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {submitting ? (
                  <span className="h-4 w-4 rounded-full border-2 border-white border-t-transparent animate-spin" />
                ) : (
                  <CheckCircle2 size={16} />
                )}
                Attach Tenant
              </button>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

export default function MspConfirmTenantPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
          <div className="flex items-center gap-3 rounded-lg border border-gray-800 bg-gray-900 px-4 py-4 text-sm text-gray-400">
            <span className="h-4 w-4 rounded-full border-2 border-cyan-500 border-t-transparent animate-spin" />
            Loading connection request...
          </div>
        </div>
      }
    >
      <MspConfirmTenantBody />
    </Suspense>
  );
}
