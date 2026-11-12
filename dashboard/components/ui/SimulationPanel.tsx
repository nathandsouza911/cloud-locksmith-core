"use client";

import { useState } from "react";
import { AlertTriangle, ChevronDown, ChevronRight, ShieldAlert } from "lucide-react";

import { Button, Card, Skeleton } from "@/components/ui";
import type { SimulationRunResponse } from "@/lib/api/endpoints";

export type SimulationConflict = {
  type: string;
  policy_ids?: Array<string | null>;
  users?: string[];
  grant_controls?: Array<{ left: string; right: string }>;
};

export type SimulationResult = SimulationRunResponse;

type SimulationPanelProps = {
  simulation: SimulationResult | null;
  loading?: boolean;
  onApply: () => void;
  onCancel: () => void;
  applyLoading?: boolean;
  showActions?: boolean;
};

function getRiskStyles(riskLevel: string) {
  const normalized = riskLevel?.toUpperCase?.() ?? "UNKNOWN";

  if (normalized === "HIGH" || normalized === "CRITICAL") {
    return "border-red-500/30 bg-red-500/10 text-red-300";
  }

  if (normalized === "MEDIUM") {
    return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
  }

  return "border-green-500/30 bg-green-500/10 text-green-300";
}

function formatConflictTitle(type: string) {
  switch (type) {
    case "overlapping_users":
      return "Overlapping users";
    case "conflicting_grant_controls":
      return "Conflicting grant controls";
    default:
      return type.replaceAll("_", " ");
  }
}

function renderConflictDetails(conflict: SimulationConflict) {
  if (conflict.type === "overlapping_users") {
    return <p className="text-xs text-gray-400">Users: {(conflict.users ?? []).join(", ") || "None"}</p>;
  }

  if (conflict.type === "conflicting_grant_controls") {
    return (
      <div className="space-y-1">
        {(conflict.grant_controls ?? []).map((pair, index) => (
          <p key={`${pair.left}-${pair.right}-${index}`} className="text-xs text-gray-400">
            {pair.left} vs {pair.right}
          </p>
        ))}
      </div>
    );
  }

  return <p className="text-xs text-gray-400">No additional details available.</p>;
}

export default function SimulationPanel({
  simulation,
  loading = false,
  onApply,
  onCancel,
  applyLoading = false,
  showActions = true,
}: SimulationPanelProps) {
  const [showConflicts, setShowConflicts] = useState(false);
  const isLoading = loading;
  const riskStyles = getRiskStyles(simulation?.risk_level ?? "UNKNOWN");
  const conflicts = simulation?.conflicts ?? [];

  return (
    <Card className="p-5 shadow-sm">
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <h3 className="text-sm font-semibold text-gray-100">Simulation Result</h3>
          <p className="text-xs text-gray-500">Review projected impact before applying this remediation.</p>
        </div>

        <span
          className={`inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.2em] ${riskStyles}`}
        >
          {simulation?.risk_level || "UNKNOWN"}
        </span>
      </div>

      {isLoading ? (
        <div className="mt-5 space-y-3">
          <Skeleton className="h-4 w-40" />
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <Skeleton className="h-20 rounded-lg" />
            <Skeleton className="h-20 rounded-lg" />
            <Skeleton className="h-20 rounded-lg" />
          </div>
          <Skeleton className="h-24 rounded-lg" />
        </div>
      ) : (
        <>
          <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-lg border border-gray-800 bg-gray-950/60 p-4">
              <p className="text-[11px] uppercase tracking-[0.2em] text-gray-500">Blocked Users</p>
              <p className="mt-2 text-sm font-semibold text-red-300">{simulation?.blocked_users ?? 0}</p>
            </div>

            <div className="rounded-lg border border-gray-800 bg-gray-950/60 p-4">
              <p className="text-[11px] uppercase tracking-[0.2em] text-gray-500">MFA Required</p>
              <p className="mt-2 text-sm font-semibold text-yellow-300">
                {simulation?.mfa_required_users ?? 0}
              </p>
            </div>

            <div className="rounded-lg border border-gray-800 bg-gray-950/60 p-4">
              <p className="text-[11px] uppercase tracking-[0.2em] text-gray-500">Unaffected</p>
              <p className="mt-2 text-sm font-semibold text-green-300">{simulation?.unaffected_users ?? 0}</p>
            </div>

            <div className="rounded-lg border border-gray-800 bg-gray-950/60 p-4">
              <div className="flex items-center gap-2 text-gray-400">
                <ShieldAlert size={14} />
                <p className="text-[11px] uppercase tracking-[0.2em] text-gray-500">Impacted Admins</p>
              </div>
              <p className="mt-2 text-sm font-semibold text-gray-100">{simulation?.impacted_admins ?? 0}</p>
            </div>
          </div>

          <div className="mt-4 rounded-lg border border-gray-800 bg-gray-950/50">
            <button
              type="button"
              onClick={() => setShowConflicts((value) => !value)}
              className="flex w-full items-center justify-between px-4 py-3 text-left"
            >
              <div className="flex items-center gap-2">
                <AlertTriangle size={14} className="text-yellow-400" />
                <span className="text-sm font-semibold text-gray-100">Conflicts ({conflicts.length})</span>
              </div>
              {showConflicts ? (
                <ChevronDown size={16} className="text-gray-500" />
              ) : (
                <ChevronRight size={16} className="text-gray-500" />
              )}
            </button>

            {showConflicts && (
              <div className="border-t border-gray-800 px-4 py-3">
                {conflicts.length > 0 ? (
                  <div className="space-y-3">
                    {conflicts.map((conflict, index) => (
                      <div
                        key={`${conflict.type}-${index}`}
                        className="rounded-md border border-gray-800 bg-gray-900/70 p-3"
                      >
                        <p className="text-sm font-medium capitalize text-gray-200">
                          {formatConflictTitle(conflict.type)}
                        </p>
                        {!!conflict.policy_ids?.length && (
                          <p className="mt-1 text-xs text-gray-500">
                            Policies: {conflict.policy_ids.filter(Boolean).join(", ")}
                          </p>
                        )}
                        <div className="mt-2">{renderConflictDetails(conflict)}</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-gray-500">No conflicts detected.</p>
                )}
              </div>
            )}
          </div>

          {showActions ? (
            <div className="mt-5 flex items-center justify-end gap-3">
              <Button type="button" variant="secondary" size="md" onClick={onCancel}>
                Cancel
              </Button>
              <Button
                type="button"
                variant="primary"
                size="md"
                onClick={onApply}
                loading={applyLoading}
                disabled={applyLoading}
              >
                Apply Fix
              </Button>
            </div>
          ) : null}
        </>
      )}
    </Card>
  );
}
