"use client";

import { useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { RefreshCw, Trash2 } from "lucide-react";
import { Card, PageHeader, Button, SimulationPanel } from "@/components/ui";
import { useAuth } from "@/lib/auth-context";
import { startMicrosoftOAuth } from "@/lib/auth";
import { useSimulation, useUsers } from "@/lib/api/hooks";
import { buildTenantIdentitySnapshot } from "@/lib/simulation";
import { deleteTenant } from "@/lib/api/endpoints";

export default function SettingsPage() {
  const { user, logout, tenantId, isSmb, selectedTenant } = useAuth();
  const router = useRouter();
  const searchParams = useSearchParams();

  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteConfirmText, setDeleteConfirmText] = useState("");
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [deleteToast, setDeleteToast] = useState<string | null>(null);

  const [simulationError, setSimulationError] = useState<string | null>(null);
  const [showSimulationPanel, setShowSimulationPanel] = useState(false);

  const { runSimulation, loading: simulationLoading, result: simulationResult } = useSimulation();
  const usersQuery = useUsers(tenantId);

  const onboardingStatus = searchParams.get("status");
  const onboardingReason = searchParams.get("reason");
  const onboardingMessage = searchParams.get("message");

  async function handleDeleteAccount() {
    if (!tenantId || deleteConfirmText !== "DELETE") return;
    setDeleteLoading(true);
    try {
      await deleteTenant(tenantId);
      setDeleteOpen(false);
      setDeleteToast("Account deleted successfully");
      setTimeout(() => {
        logout();
        router.push("/login");
      }, 1500);
    } catch (error) {
      setDeleteToast(error instanceof Error ? error.message : "Failed to delete account");
      setDeleteLoading(false);
    }
  }

  async function handleSimulateFix() {
    setSimulationError(null);
    setShowSimulationPanel(true);
    try {
      const tenantSnapshot = buildTenantIdentitySnapshot(usersQuery.data ?? []);
      if (!tenantSnapshot) {
        throw new Error("Tenant identity data is still loading.");
      }
      await runSimulation({
        tenant_snapshot: { ...tenantSnapshot },
        proposed_change: {
          id: "settings-simulation-policy",
          control_id: "CA_MFA_ALL_USERS",
          conditions: { users: { includeUsers: ["All"] } },
          grantControls: { builtInControls: ["mfa"] },
          state: "enabled",
        },
        role_mapping: tenantSnapshot.roles,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Simulation failed";
      setSimulationError(message);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Settings" subtitle="Manage your Cloud Locksmith platform configuration" />

      {onboardingStatus === "blocked" &&
        onboardingReason === "application_disabled_in_tenant" &&
        onboardingMessage && (
          <Card className="p-4 border-red-500/20 bg-red-500/5">
            <p className="text-sm font-semibold text-red-400">Microsoft tenant connection blocked</p>
            <p className="mt-1 text-sm text-gray-300">{onboardingMessage}</p>
          </Card>
        )}

      {/* Microsoft 365 Connection */}
      <Card className="p-6 space-y-4 max-w-2xl">
        <h2 className="text-sm font-semibold text-gray-200">Microsoft 365 Connection</h2>
        <div className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg border border-gray-700">
          <div>
            <p className="text-sm font-medium text-gray-200">Microsoft Graph API</p>
            <p className="text-xs text-gray-500">OAuth 2.0 delegated permissions</p>
          </div>
          {selectedTenant == null ? (
            <span className="text-xs font-semibold text-gray-400 bg-gray-500/10 border border-gray-500/20 px-2 py-1 rounded-md">
              Not connected
            </span>
          ) : selectedTenant.needs_reauth ? (
            <span className="text-xs font-semibold text-yellow-400 bg-yellow-500/10 border border-yellow-500/20 px-2 py-1 rounded-md">
              Needs Re-auth
            </span>
          ) : (
            <span className="text-xs font-semibold text-green-400 bg-green-500/10 border border-green-500/20 px-2 py-1 rounded-md">
              Connected
            </span>
          )}
        </div>
        <Button variant="secondary" size="sm" onClick={() => startMicrosoftOAuth("msp_connect")}>
          <RefreshCw size={13} /> Re-authorize Microsoft OAuth
        </Button>
      </Card>

      {/* Simulation */}
      <Card className="p-6 space-y-4 max-w-2xl">
        <div className="flex items-center justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-gray-200">Simulation</h2>
            <p className="text-xs text-gray-500">Run a quick dry-run before applying a fix.</p>
          </div>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => void handleSimulateFix()}
            disabled={simulationLoading || usersQuery.loading}
          >
            {simulationLoading ? "Simulating..." : "Simulate Fix"}
          </Button>
        </div>

        {simulationError && <p className="text-xs text-red-400">{simulationError}</p>}

        {showSimulationPanel && (simulationLoading || simulationResult) && (
          <SimulationPanel
            simulation={simulationResult}
            loading={simulationLoading}
            showActions={false}
            onApply={() => setShowSimulationPanel(false)}
            onCancel={() => {
              setSimulationError(null);
              setShowSimulationPanel(false);
            }}
          />
        )}
      </Card>

      {/* Danger Zone */}
      <Card className="p-4 border-red-500/20 bg-red-500/5 max-w-2xl">
        <p className="text-sm font-semibold text-red-400 mb-2">Danger Zone</p>
        <p className="text-xs text-gray-400 mb-3">
          Signed in as {user?.email ?? "unknown"}. Sign out of all active sessions.
        </p>
        <Button variant="danger" size="sm" onClick={logout}>
          Sign Out
        </Button>
      </Card>

      {isSmb && (
        <Card className="p-4 border-red-700/40 bg-red-950/20 max-w-2xl">
          <p className="text-sm font-semibold text-red-400 mb-1">Delete Account</p>
          <p className="text-xs text-gray-400 mb-3">
            This will permanently delete your account and all associated data. This action cannot be undone.
          </p>
          <Button
            variant="danger"
            size="sm"
            onClick={() => {
              setDeleteOpen(true);
              setDeleteConfirmText("");
            }}
          >
            <Trash2 size={13} />
            Delete Account
          </Button>
        </Card>
      )}

      {deleteToast && (
        <Card className="px-4 py-3 border-red-500/30 bg-red-500/10 text-sm text-red-200 max-w-2xl">
          {deleteToast}
        </Card>
      )}

      {deleteOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-xl border border-red-800/60 bg-gray-900 p-6 shadow-2xl">
            <div className="mb-4 flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-red-900/40 text-red-400">
                <Trash2 size={18} />
              </div>
              <div>
                <h2 className="text-base font-semibold text-white">Delete Account</h2>
                <p className="text-xs text-gray-400">This cannot be undone</p>
              </div>
            </div>

            <div className="mb-5 rounded-lg border border-red-800/40 bg-red-950/30 px-4 py-3 text-sm text-red-300">
              <p className="font-semibold mb-1">Permanently deletes all data including:</p>
              <ul className="list-disc list-inside space-y-0.5 text-red-400 text-xs">
                <li>All compliance results and remediation history</li>
                <li>All snapshots, reports, and alerts</li>
                <li>OAuth tokens and user access</li>
                <li>All scan and audit data</li>
              </ul>
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
                autoFocus
                className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder:text-gray-600 outline-none focus:border-red-600 font-mono"
              />
            </div>

            <div className="flex gap-3 justify-end">
              <Button
                variant="secondary"
                size="sm"
                onClick={() => setDeleteOpen(false)}
                disabled={deleteLoading}
              >
                Cancel
              </Button>
              <Button
                variant="danger"
                size="sm"
                onClick={handleDeleteAccount}
                loading={deleteLoading}
                disabled={deleteConfirmText !== "DELETE" || deleteLoading}
              >
                <Trash2 size={12} />
                Delete Account
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
