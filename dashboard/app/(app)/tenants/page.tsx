"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { ExternalLink, Plus, RefreshCw, Search, Trash2 } from "lucide-react";

import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  FilterSelect,
  PageHeader,
  StatCard,
  TableSkeleton,
} from "@/components/ui";
import { useFleetPosture } from "@/lib/api/hooks";
import { useAuth } from "@/lib/auth-context";
import { startMicrosoftOAuth } from "@/lib/auth";
import * as ep from "@/lib/api/endpoints";
import type { ScoreBand } from "@/types";
import { scoreBandAccent, scoreBandLabel } from "@/utils/posture";

// Gate 1 (P0): the backend now redirects every onboarding-connect failure
// here instead of leaving a raw JSON error in the user's browser. Mapping
// the codes to plain-language messages is what actually closes the loop --
// a redirect the user can't interpret is barely better than the JSON page
// it replaced.
const CONNECT_ERROR_MESSAGES: Record<string, string> = {
  cancelled: 'You cancelled the Microsoft sign-in. Click "Add Tenant" to try again.',
  microsoft_error: 'Microsoft couldn\'t complete this connection. Click "Add Tenant" to try again.',
  missing_parameters: 'The connection request was incomplete. Click "Add Tenant" to try again.',
  connection_failed: 'The connection couldn\'t be completed. Click "Add Tenant" to try again.',
  tenant_admin_required:
    "You need to be a Global Administrator or Privileged Role Administrator on that Microsoft 365 tenant to connect it. Ask your admin to complete this step, or sign in with an account that has that role.",
};

const ADMIN_ROLE_REQUIREMENT_COPY =
  "You'll need to sign in as a Global Administrator (or Privileged Role Administrator) on the Microsoft 365 tenant you're connecting.";

function scoreLabel(
  scoreBand: ScoreBand | null | undefined,
  hasSnapshot: boolean,
): { label: string; cls: string } {
  if (!hasSnapshot) return { label: "Awaiting scan", cls: "text-gray-400" };
  return {
    label: scoreBandLabel(scoreBand ?? null),
    cls: scoreBandAccent(scoreBand ?? null),
  };
}

export default function TenantsPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const {
    tenants: linkedTenants,
    setActiveTenantId,
    tenantId: selectedTenantId,
    refreshTenants,
    isSmb,
  } = useAuth();

  const connectErrorCode = searchParams.get("connect_error") || searchParams.get("error");
  const connectErrorMessage = connectErrorCode
    ? (CONNECT_ERROR_MESSAGES[connectErrorCode] ??
      searchParams.get("connect_error_message") ??
      'The connection couldn\'t be completed. Click "Add Tenant" to try again.')
    : null;
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [reconnectTenantId, setReconnectTenantId] = useState<string | null>(null);
  const [scanningTenantIds, setScanningTenantIds] = useState<string[]>([]);
  const [scanAllLoading, setScanAllLoading] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<{ id: string; name: string } | null>(null);
  const [deleteConfirmText, setDeleteConfirmText] = useState("");
  const [deleteLoading, setDeleteLoading] = useState(false);
  const fleetQuery = useFleetPosture();

  const postureByTenantId = useMemo(() => {
    const entries = fleetQuery.data?.tenants ?? [];
    return new Map(entries.map((tenant) => [tenant.tenant_id, tenant]));
  }, [fleetQuery.data?.tenants]);

  const rows = useMemo(
    () =>
      linkedTenants
        .map((tenant) => {
          const posture = postureByTenantId.get(tenant.tenant_id);
          return {
            ...tenant,
            posture_score: posture?.posture_score ?? null,
            score_band: posture?.score_band ?? null,
            failed_controls: posture?.failed_controls ?? 0,
            has_snapshot: posture?.has_snapshot ?? false,
            posture_status: posture?.status ?? "Awaiting scan",
            latest_snapshot_at: posture?.latest_snapshot_at ?? null,
          };
        })
        .filter((tenant) => {
          if (search && !tenant.tenant_name.toLowerCase().includes(search.toLowerCase())) return false;
          if (statusFilter === "good") return tenant.score_band === "GOOD";
          if (statusFilter === "moderate") return tenant.score_band === "MODERATE";
          if (statusFilter === "high") return tenant.score_band === "HIGH";
          if (statusFilter === "critical") return tenant.score_band === "CRITICAL";
          if (statusFilter === "reauth") return tenant.needs_reauth === true;
          return true;
        }),
    [linkedTenants, postureByTenantId, search, statusFilter],
  );

  async function handleDeleteTenant() {
    if (!deleteTarget || deleteConfirmText !== "DELETE") return;
    setDeleteLoading(true);
    try {
      await ep.deleteTenant(deleteTarget.id);
      setDeleteTarget(null);
      setDeleteConfirmText("");
      setToast("Tenant permanently deleted");
      void refreshTenants();
      fleetQuery.refetch();
    } catch (error) {
      setToast(error instanceof Error ? error.message : "Failed to delete tenant");
    } finally {
      setDeleteLoading(false);
    }
  }

  function handleReconnect(tenantId: string) {
    setReconnectTenantId(tenantId);
    const started = startMicrosoftOAuth("msp_connect", { tenantId });
    if (!started) {
      setReconnectTenantId(null);
    }
  }

  useEffect(() => {
    if (!toast) return undefined;
    const timeout = window.setTimeout(() => setToast(null), 2500);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  async function handleScanTenant(tenantId: string) {
    setScanningTenantIds((current) => (current.includes(tenantId) ? current : [...current, tenantId]));
    try {
      await ep.startTenantScan(tenantId);
      window.dispatchEvent(new CustomEvent("cloud-locksmith:scan-started", { detail: { tenantId } }));
      void refreshTenants();
      fleetQuery.refetch();
      window.setTimeout(() => {
        void refreshTenants();
        fleetQuery.refetch();
      }, 3000);
      window.setTimeout(() => {
        void refreshTenants();
        fleetQuery.refetch();
      }, 10000);
      setToast("Scan started successfully");
    } catch (error) {
      setToast(error instanceof Error ? error.message : "Unable to start scan");
    } finally {
      setScanningTenantIds((current) => current.filter((id) => id !== tenantId));
    }
  }

  async function handleScanAllTenants() {
    setScanAllLoading(true);
    setScanningTenantIds(linkedTenants.map((tenant) => tenant.tenant_id));
    try {
      await ep.startAllTenantScans();
      window.dispatchEvent(new Event("cloud-locksmith:scan-started"));
      void refreshTenants();
      fleetQuery.refetch();
      window.setTimeout(() => {
        void refreshTenants();
        fleetQuery.refetch();
      }, 3000);
      window.setTimeout(() => {
        void refreshTenants();
        fleetQuery.refetch();
      }, 10000);
      setToast("Scan started successfully");
    } catch (error) {
      setToast(error instanceof Error ? error.message : "Unable to start scans");
    } finally {
      setScanAllLoading(false);
      setScanningTenantIds([]);
    }
  }

  const good = rows.filter((tenant) => tenant.score_band === "GOOD").length;
  const moderate = rows.filter((tenant) => tenant.score_band === "MODERATE").length;
  const critical = rows.filter((tenant) => tenant.score_band === "CRITICAL").length;

  const addTenantAction = (
    <Button
      variant="primary"
      size="sm"
      onClick={() => {
        startMicrosoftOAuth("msp_connect");
      }}
    >
      <Plus size={13} />
      Add Tenant
    </Button>
  );

  useEffect(() => {
    if (isSmb) {
      router.replace("/dashboard");
    }
  }, [isSmb, router]);

  if (isSmb) {
    return null;
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Tenants"
        subtitle={`${linkedTenants.length} linked tenant${linkedTenants.length === 1 ? "" : "s"}`}
        actions={
          <>
            {linkedTenants.length > 0 ? (
              <Button variant="secondary" size="sm" loading={scanAllLoading} onClick={handleScanAllTenants}>
                <RefreshCw size={13} className={scanAllLoading ? "animate-spin" : ""} />
                Scan All Tenants
              </Button>
            ) : null}
            {addTenantAction}
            <Button variant="secondary" size="sm" onClick={() => fleetQuery.refetch()}>
              <RefreshCw size={13} className={fleetQuery.loading ? "animate-spin" : ""} />
              Refresh
            </Button>
          </>
        }
      />

      {toast && (
        <Card className="px-4 py-3 border-cyan-500/30 bg-cyan-500/10 text-sm text-cyan-100">{toast}</Card>
      )}

      {connectErrorMessage && (
        <Card
          data-testid="connect-error-banner"
          className="px-4 py-3 border-red-500/30 bg-red-500/10 text-sm text-red-200"
        >
          {connectErrorMessage}
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard label="Good" value={good} sub="score 80+" accent="text-cyan-400" />
        <StatCard label="Moderate" value={moderate} sub="score 60-79" accent="text-yellow-400" />
        <StatCard label="Critical" value={critical} sub="score below 40" accent="text-red-400" />
      </div>

      <Card className="overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-800 flex flex-col sm:flex-row gap-3 items-start sm:items-center justify-between">
          <div className="flex items-center gap-2 bg-gray-800/60 border border-gray-700 rounded-lg px-3 py-1.5 flex-1 max-w-xs">
            <Search size={14} className="text-gray-400 shrink-0" />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search tenants..."
              className="flex-1 bg-transparent text-sm text-gray-300 placeholder:text-gray-500 outline-none"
            />
          </div>
          <FilterSelect
            value={statusFilter}
            onChange={setStatusFilter}
            options={[
              { label: "Good", value: "good" },
              { label: "Moderate", value: "moderate" },
              { label: "High", value: "high" },
              { label: "Critical", value: "critical" },
              { label: "Needs Re-auth", value: "reauth" },
            ]}
            placeholder="All statuses"
          />
        </div>

        {linkedTenants.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-gray-500 text-center px-6">
            <p className="text-sm">No tenants connected</p>
            <p className="text-xs text-gray-600 mt-2 max-w-sm">{ADMIN_ROLE_REQUIREMENT_COPY}</p>
            <div className="mt-4">{addTenantAction}</div>
          </div>
        ) : fleetQuery.loading ? (
          <div className="p-5">
            <TableSkeleton rows={6} cols={5} />
          </div>
        ) : fleetQuery.error ? (
          <ErrorState message={fleetQuery.error} />
        ) : rows.length === 0 ? (
          <EmptyState message="No tenants match the current filter" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  {["Tenant", "Role", "Status", "Posture", "Failed Controls", "Actions"].map((heading) => (
                    <th
                      key={heading}
                      className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider whitespace-nowrap"
                    >
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/50">
                {rows.map((tenant) => {
                  const { label, cls } = scoreLabel(tenant.score_band, tenant.has_snapshot);
                  return (
                    <tr key={tenant.tenant_id} className="hover:bg-gray-800/40 transition-colors">
                      <td className="px-5 py-3.5">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-lg bg-gray-800 border border-gray-700 flex items-center justify-center text-xs font-bold text-gray-300">
                            {tenant.tenant_name.slice(0, 2).toUpperCase()}
                          </div>
                          <div>
                            <p className="font-medium text-gray-200">{tenant.tenant_name}</p>
                            <p className="text-xs text-gray-500 font-mono">{tenant.tenant_id}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-5 py-3.5 text-gray-300">{tenant.role}</td>
                      <td className="px-5 py-3.5">
                        <div className="space-y-1">
                          <span
                            className={`text-xs font-semibold ${tenant.needs_reauth ? "text-yellow-300" : tenant.has_snapshot ? "text-green-300" : "text-gray-400"}`}
                          >
                            {tenant.needs_reauth ? (tenant.status ?? "Needs Re-auth") : tenant.posture_status}
                          </span>
                          <p className="text-[11px] text-gray-500">
                            {tenant.latest_snapshot_at
                              ? `Last snapshot: ${new Date(tenant.latest_snapshot_at).toLocaleString()}`
                              : tenant.last_token_refresh
                                ? `Last refresh: ${new Date(tenant.last_token_refresh).toLocaleString()}`
                                : "No snapshot recorded"}
                          </p>
                        </div>
                      </td>
                      <td className="px-5 py-3.5">
                        <div className="flex items-center gap-2">
                          <span className="font-bold tabular-nums text-gray-200">
                            {tenant.posture_score ?? "-"}
                          </span>
                          <span className={`text-xs font-semibold ${cls}`}>{label}</span>
                        </div>
                      </td>
                      <td className="px-5 py-3.5 text-gray-400 tabular-nums">{tenant.failed_controls}</td>
                      <td className="px-5 py-3.5">
                        <div className="flex gap-2">
                          <Button
                            variant="secondary"
                            size="sm"
                            loading={scanAllLoading || scanningTenantIds.includes(tenant.tenant_id)}
                            onClick={() => handleScanTenant(tenant.tenant_id)}
                          >
                            <RefreshCw
                              size={12}
                              className={
                                scanAllLoading || scanningTenantIds.includes(tenant.tenant_id)
                                  ? "animate-spin"
                                  : ""
                              }
                            />
                            Scan Now
                          </Button>
                          <Button
                            variant="secondary"
                            size="sm"
                            onClick={() => {
                              setActiveTenantId(tenant.tenant_id);
                            }}
                          >
                            {selectedTenantId === tenant.tenant_id ? "Selected" : "Switch"}
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setActiveTenantId(tenant.tenant_id);
                              router.push(`/tenants/${tenant.tenant_id}`);
                            }}
                          >
                            <ExternalLink size={12} />
                            View
                          </Button>
                          <Button
                            variant={tenant.needs_reauth ? "primary" : "secondary"}
                            size="sm"
                            loading={reconnectTenantId === tenant.tenant_id}
                            onClick={() => handleReconnect(tenant.tenant_id)}
                          >
                            Reconnect
                          </Button>
                          {(tenant.role === "OWNER" || tenant.role === "ADMIN") && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                setDeleteTarget({ id: tenant.tenant_id, name: tenant.tenant_name });
                                setDeleteConfirmText("");
                              }}
                              className="text-red-400 hover:text-red-300 hover:bg-red-900/20"
                            >
                              <Trash2 size={12} />
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {deleteTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-xl border border-red-800/60 bg-gray-900 p-6 shadow-2xl">
            <div className="mb-4 flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-red-900/40 text-red-400">
                <Trash2 size={18} />
              </div>
              <div>
                <h2 className="text-base font-semibold text-white">Delete Tenant</h2>
                <p className="text-xs text-gray-400 font-mono">{deleteTarget.id}</p>
              </div>
            </div>

            <div className="mb-5 rounded-lg border border-red-800/40 bg-red-950/30 px-4 py-3 text-sm text-red-300">
              <p className="font-semibold mb-1">This will permanently delete all data including:</p>
              <ul className="list-disc list-inside space-y-0.5 text-red-400 text-xs">
                <li>All compliance results and remediation history</li>
                <li>All snapshots, reports, and alerts</li>
                <li>OAuth tokens and user access mappings</li>
                <li>All scan and audit data</li>
              </ul>
              <p className="mt-2 font-semibold">This action cannot be undone.</p>
            </div>

            <div className="mb-5">
              <label className="mb-1.5 block text-xs font-medium text-gray-400">
                Type <span className="font-mono font-bold text-red-400">DELETE</span> to confirm
              </label>
              <input
                type="text"
                value={deleteConfirmText}
                onChange={(e) => setDeleteConfirmText(e.target.value)}
                placeholder="DELETE"
                className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder:text-gray-600 outline-none focus:border-red-600 font-mono"
                autoFocus
              />
            </div>

            <div className="flex gap-3 justify-end">
              <Button
                variant="secondary"
                size="sm"
                onClick={() => {
                  setDeleteTarget(null);
                  setDeleteConfirmText("");
                }}
                disabled={deleteLoading}
              >
                Cancel
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={handleDeleteTenant}
                loading={deleteLoading}
                disabled={deleteConfirmText !== "DELETE" || deleteLoading}
                className="bg-red-700 hover:bg-red-600 disabled:bg-red-900/40 disabled:text-red-700"
              >
                <Trash2 size={12} />
                Permanently Delete
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
