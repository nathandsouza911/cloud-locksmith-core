"use client";

import { useEffect, useMemo, useState } from "react";

import { Card } from "@/components/ui";
import { runSimulation, type SimulationRunResponse } from "@/lib/api/endpoints";
import { useUsers } from "@/lib/api/hooks";
import { useAuth } from "@/lib/auth-context";
import { requireTenantIdentitySnapshot } from "@/lib/simulation";

export type EditablePolicy = {
  id: string;
  name?: string;
  users: string[];
  apps: string[];
  controls: string[];
};

type PolicyEditorProps = {
  policies: EditablePolicy[];
  value?: EditablePolicy | null;
  onChange?: (policy: EditablePolicy) => void;
};

function toMultiline(values: string[]) {
  return values.join("\n");
}

function fromMultiline(value: string) {
  return value
    .split("\n")
    .map((item) => item.trim())
    .filter(Boolean);
}

export default function PolicyEditor({ policies, value, onChange }: PolicyEditorProps) {
  const { tenantId } = useAuth();
  const usersQuery = useUsers(tenantId);
  const initialPolicy = value ?? policies[0] ?? null;
  const [selectedPolicyId, setSelectedPolicyId] = useState<string>(initialPolicy?.id ?? "");
  const [drafts, setDrafts] = useState<Record<string, EditablePolicy>>(() =>
    Object.fromEntries(policies.map((policy) => [policy.id, policy])),
  );
  const [simulationLoading, setSimulationLoading] = useState(false);
  const [simulationError, setSimulationError] = useState<string | null>(null);
  const [simulationResult, setSimulationResult] = useState<SimulationRunResponse | null>(null);

  useEffect(() => {
    setDrafts(Object.fromEntries(policies.map((policy) => [policy.id, policy])));
    if (!policies.some((policy) => policy.id === selectedPolicyId)) {
      setSelectedPolicyId(policies[0]?.id ?? "");
    }
  }, [policies, selectedPolicyId]);

  const selectedPolicy = useMemo(() => drafts[selectedPolicyId] ?? null, [drafts, selectedPolicyId]);

  useEffect(() => {
    if (!selectedPolicy) {
      setSimulationResult(null);
      setSimulationError(null);
      setSimulationLoading(false);
      return;
    }
    if (usersQuery.loading) {
      setSimulationLoading(false);
      return;
    }

    const timeout = window.setTimeout(async () => {
      setSimulationLoading(true);
      setSimulationError(null);

      try {
        const tenantSnapshot = requireTenantIdentitySnapshot(usersQuery.data, usersQuery.error);

        const allPolicies = Object.values(drafts);
        const payload = {
          tenant_snapshot: {
            ...tenantSnapshot,
            policies: allPolicies.map((policy) => ({
              id: policy.id,
              conditions: {
                users: {
                  includeUsers: policy.users,
                },
              },
              applications: {
                includeApplications: policy.apps,
              },
              grantControls: {
                builtInControls: policy.controls,
              },
              state: "enabled",
            })),
          },
          proposed_change: {
            id: selectedPolicy.id,
            conditions: {
              users: {
                includeUsers: selectedPolicy.users,
              },
            },
            applications: {
              includeApplications: selectedPolicy.apps,
            },
            grantControls: {
              builtInControls: selectedPolicy.controls,
            },
            state: "enabled",
          },
          role_mapping: tenantSnapshot.roles,
        };

        const result = await runSimulation(payload);
        setSimulationResult(result);
      } catch (error) {
        setSimulationResult(null);
        setSimulationError(error instanceof Error ? error.message : "Simulation failed");
      } finally {
        setSimulationLoading(false);
      }
    }, 500);

    return () => window.clearTimeout(timeout);
  }, [drafts, selectedPolicy, usersQuery.data, usersQuery.error, usersQuery.loading]);

  function updatePolicy(patch: Partial<EditablePolicy>) {
    if (!selectedPolicy) return;

    const nextPolicy = {
      ...selectedPolicy,
      ...patch,
    };

    setDrafts((current) => ({
      ...current,
      [selectedPolicy.id]: nextPolicy,
    }));

    onChange?.(nextPolicy);
  }

  return (
    <Card className="p-5">
      <div className="flex flex-col gap-5 lg:flex-row">
        <div className="lg:w-72">
          <p className="text-sm font-semibold text-gray-100">Policies</p>
          <div className="mt-3 space-y-2">
            {policies.length === 0 ? (
              <p className="rounded-lg border border-gray-800 bg-gray-950/50 px-3 py-3 text-sm text-gray-500">
                No policies available.
              </p>
            ) : (
              policies.map((policy) => {
                const isSelected = policy.id === selectedPolicyId;
                return (
                  <button
                    key={policy.id}
                    type="button"
                    onClick={() => setSelectedPolicyId(policy.id)}
                    className={`w-full rounded-lg border px-3 py-3 text-left transition-colors ${
                      isSelected
                        ? "border-cyan-500/40 bg-cyan-500/10"
                        : "border-gray-800 bg-gray-950/50 hover:border-gray-700 hover:bg-gray-900"
                    }`}
                  >
                    <p className="text-sm font-medium text-gray-100">{policy.name || policy.id}</p>
                    <p className="mt-1 text-xs text-gray-500">{policy.id}</p>
                  </button>
                );
              })
            )}
          </div>
        </div>

        <div className="min-w-0 flex-1">
          {!selectedPolicy ? (
            <div className="rounded-lg border border-gray-800 bg-gray-950/50 px-4 py-6 text-sm text-gray-500">
              Select a policy to edit.
            </div>
          ) : (
            <div className="space-y-4">
              <div>
                <p className="text-sm font-semibold text-gray-100">
                  {selectedPolicy.name || selectedPolicy.id}
                </p>
                <p className="mt-1 text-xs text-gray-500">{selectedPolicy.id}</p>
              </div>

              <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium uppercase tracking-[0.2em] text-gray-500">
                    Users
                  </label>
                  <textarea
                    value={toMultiline(selectedPolicy.users)}
                    onChange={(event) => {
                      updatePolicy({ users: fromMultiline(event.target.value) });
                    }}
                    className="min-h-40 w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2.5 text-sm text-gray-200 outline-none transition-colors focus:border-cyan-500"
                    placeholder="One user per line"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-medium uppercase tracking-[0.2em] text-gray-500">
                    Controls
                  </label>
                  <textarea
                    value={toMultiline(selectedPolicy.controls)}
                    onChange={(event) => {
                      updatePolicy({ controls: fromMultiline(event.target.value) });
                    }}
                    className="min-h-40 w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2.5 text-sm text-gray-200 outline-none transition-colors focus:border-cyan-500"
                    placeholder="One control per line"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium uppercase tracking-[0.2em] text-gray-500">Apps</label>
                <div className="rounded-lg border border-gray-800 bg-gray-950/50 px-3 py-3">
                  {selectedPolicy.apps.length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                      {selectedPolicy.apps.map((app) => (
                        <span
                          key={app}
                          className="rounded-full border border-gray-700 bg-gray-900 px-2.5 py-1 text-xs text-gray-300"
                        >
                          {app}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-gray-500">No apps assigned.</p>
                  )}
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium uppercase tracking-[0.2em] text-gray-500">
                  Live Simulation Preview
                </label>
                <div className="rounded-lg border border-gray-800 bg-gray-950/50 px-3 py-3">
                  {simulationLoading ? (
                    <p className="text-sm text-gray-400">Updating simulation...</p>
                  ) : simulationError ? (
                    <p className="text-sm text-red-400">{simulationError}</p>
                  ) : simulationResult ? (
                    <>
                      <div className="grid grid-cols-1 gap-3 sm:grid-cols-4">
                        <div>
                          <p className="text-[11px] uppercase tracking-[0.2em] text-gray-500">Risk Level</p>
                          <p className="mt-1 text-sm font-semibold text-gray-100">
                            {simulationResult.risk_level}
                          </p>
                        </div>
                        <div>
                          <p className="text-[11px] uppercase tracking-[0.2em] text-gray-500">Blocked</p>
                          <p className="mt-1 text-sm font-semibold text-red-300">
                            {simulationResult.blocked_users}
                          </p>
                        </div>
                        <div>
                          <p className="text-[11px] uppercase tracking-[0.2em] text-gray-500">MFA Required</p>
                          <p className="mt-1 text-sm font-semibold text-yellow-300">
                            {simulationResult.mfa_required_users}
                          </p>
                        </div>
                        <div>
                          <p className="text-[11px] uppercase tracking-[0.2em] text-gray-500">Conflicts</p>
                          <p className="mt-1 text-sm font-semibold text-gray-100">
                            {simulationResult.conflicts?.length ?? 0}
                          </p>
                        </div>
                      </div>
                      <p className="mt-3 text-sm text-gray-400">
                        {simulationResult.blocked_users} blocked, {simulationResult.mfa_required_users}{" "}
                        require MFA.
                      </p>
                    </>
                  ) : (
                    <p className="text-sm text-gray-500">Edit users or controls to preview live impact.</p>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}
