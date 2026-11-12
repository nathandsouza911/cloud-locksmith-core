"use client";

import { useState, useMemo } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { CheckCircle, Play, RotateCcw, Eye, ShieldCheck, RefreshCw } from "lucide-react";
import {
  Card,
  PageHeader,
  SeverityBadge,
  FilterSelect,
  Button,
  EmptyState,
  TableSkeleton,
  ErrorState,
  ConfirmModal,
} from "@/components/ui";
import { useRemediationStats, useRemediationDecisions, usePriorityQueue } from "@/lib/api/hooks";
import * as ep from "@/lib/api/endpoints";
import { useAuth } from "@/lib/auth-context";
import { startMicrosoftOAuth } from "@/lib/auth";
import type { Severity } from "@/types";

// Risk classification for confirmation gates.
const HIGH_RISK_ACTIONS = new Set(["execute", "rollback"]);
const MEDIUM_RISK_ACTIONS = new Set(["approve"]);

function actionLabel(kind: string): string {
  return (
    { execute: "Execute Remediation", rollback: "Roll Back", approve: "Approve", verify: "Verify" }[kind] ??
    kind
  );
}

function actionMessage(kind: string, controlId?: string): string {
  if (kind === "execute")
    return `This will apply changes to your Microsoft 365 tenant for control: ${controlId ?? "unknown"}. This action modifies live security settings and cannot be undone automatically.`;
  if (kind === "rollback")
    return `This will reverse the remediation for control: ${controlId ?? "unknown"}. Rolling back may re-expose a security finding.`;
  if (kind === "approve")
    return `You are approving this finding for remediation. The finding will be executed in the next step. Approvals expire after 48 hours.`;
  return "Please confirm this action.";
}

const FUNNEL_COLORS = ["#6366f1", "#3b82f6", "#22d3ee", "#22c55e", "#a855f7"];

function relDate(iso: string) {
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

interface PendingAction {
  kind: string;
  complianceResultId: string;
  controlId?: string;
}

export default function RemediationQueuePage() {
  const { isPreviewMode } = useAuth();
  const [severityFilter, setSeverityFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [loadingId, setLoadingId] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<PendingAction | null>(null);

  const statsQuery = useRemediationStats();
  const decisionsQuery = useRemediationDecisions();
  const priorityQuery = usePriorityQueue();

  const isLoading = decisionsQuery.loading || priorityQuery.loading;
  const stats = statsQuery.data;
  const decisions = decisionsQuery.data ?? [];
  const priorityQueue = priorityQuery.data ?? [];

  const enriched = useMemo(() => {
    const pMap = Object.fromEntries(priorityQueue.map((p) => [p.compliance_result_id, p.priority_score]));
    return decisions.map((d) => ({
      ...d,
      priority: d.compliance_result_id ? (pMap[d.compliance_result_id] ?? 0) : 0,
    }));
  }, [decisions, priorityQueue]);

  const filtered = useMemo(
    () =>
      enriched
        .filter((d) => {
          if (severityFilter && d.severity !== severityFilter) return false;
          if (statusFilter && d.decision !== statusFilter) return false;
          return true;
        })
        .sort((a, b) => b.priority - a.priority),
    [enriched, severityFilter, statusFilter],
  );

  const funnelData = stats
    ? [
        { name: "Pending", value: stats.pending_approvals },
        { name: "Approved", value: stats.auto_remediated + stats.executed },
        { name: "Executed", value: stats.executed },
        { name: "Verified", value: stats.verified },
        { name: "Rolled Back", value: stats.rolled_back },
      ]
    : [];

  // Gate: show confirmation modal before executing any action that modifies tenant state.
  function requestAction(kind: string, complianceResultId: string, controlId?: string) {
    if (isPreviewMode) {
      startMicrosoftOAuth("smb_onboarding");
      return;
    }
    // "verify" is read-only — no confirmation needed.
    if (kind === "verify") {
      void doAction(kind, complianceResultId);
      return;
    }
    setPendingAction({ kind, complianceResultId, controlId });
  }

  async function doAction(kind: string, complianceResultId: string) {
    const key = `${kind}-${complianceResultId}`;
    setLoadingId(key);
    try {
      if (kind === "approve") await ep.approveByResult(complianceResultId);
      else if (kind === "execute") await ep.executeRemediation(complianceResultId);
      else if (kind === "verify") await ep.verifyRemediation(complianceResultId);
      else if (kind === "rollback") await ep.rollbackRemediation(complianceResultId);
      decisionsQuery.refetch();
      statsQuery.refetch();
    } catch {
      /* error is shown via re-fetch */
    } finally {
      setLoadingId(null);
    }
  }

  function handleConfirm() {
    if (!pendingAction) return;
    const { kind, complianceResultId } = pendingAction;
    setPendingAction(null);
    void doAction(kind, complianceResultId);
  }

  return (
    <div className="space-y-6">
      <ConfirmModal
        open={pendingAction !== null}
        title={pendingAction ? actionLabel(pendingAction.kind) : ""}
        message={pendingAction ? actionMessage(pendingAction.kind, pendingAction.controlId) : ""}
        confirmLabel={pendingAction ? actionLabel(pendingAction.kind) : "Confirm"}
        variant={pendingAction && HIGH_RISK_ACTIONS.has(pendingAction.kind) ? "danger" : "warning"}
        requireTypedConfirm={pendingAction ? HIGH_RISK_ACTIONS.has(pendingAction.kind) : false}
        onConfirm={handleConfirm}
        onCancel={() => setPendingAction(null)}
      />
      <PageHeader
        title="Remediation Queue"
        subtitle="Prioritized findings with approval, execution, and rollback controls"
        actions={
          <Button
            variant="primary"
            size="sm"
            onClick={() => {
              statsQuery.refetch();
              decisionsQuery.refetch();
              priorityQuery.refetch();
            }}
          >
            <RefreshCw size={13} className={isLoading ? "animate-spin" : ""} /> Refresh
          </Button>
        }
      />

      {/* Stats strip */}
      {statsQuery.loading ? (
        <div className="h-16">
          <TableSkeleton rows={1} cols={8} />
        </div>
      ) : statsQuery.error ? (
        <ErrorState message={statsQuery.error} />
      ) : (
        stats && (
          <div className="grid grid-cols-4 lg:grid-cols-8 gap-3">
            {[
              { label: "Total", value: stats.total, color: "text-gray-200" },
              { label: "Pending", value: stats.pending_approvals, color: "text-yellow-400" },
              { label: "System-Fixed", value: stats.auto_remediated, color: "text-green-400" },
              { label: "Blocked", value: stats.blocked, color: "text-red-400" },
              { label: "Executed", value: stats.executed, color: "text-blue-400" },
              { label: "Failed", value: stats.failed, color: "text-red-400" },
              { label: "Verified", value: stats.verified, color: "text-cyan-400" },
              { label: "Rolled Back", value: stats.rolled_back, color: "text-purple-400" },
            ].map((s) => (
              <Card key={s.label} className="p-3 text-center col-span-2 lg:col-span-1">
                <p className={`text-xl font-bold tabular-nums ${s.color}`}>{s.value}</p>
                <p className="text-[10px] text-gray-500 uppercase tracking-wide mt-0.5">{s.label}</p>
              </Card>
            ))}
          </div>
        )
      )}

      {/* Funnel */}
      {funnelData.length > 0 && (
        <Card className="p-5">
          <p className="text-sm font-semibold text-gray-200 mb-4">Execution Funnel</p>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={funnelData} layout="vertical" barSize={20}>
              <XAxis
                type="number"
                tick={{ fill: "#6b7280", fontSize: 11 }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                type="category"
                dataKey="name"
                tick={{ fill: "#9ca3af", fontSize: 11 }}
                axisLine={false}
                tickLine={false}
                width={80}
              />
              <Tooltip
                contentStyle={{
                  background: "#111827",
                  border: "1px solid #374151",
                  borderRadius: 8,
                  color: "#e5e7eb",
                  fontSize: 12,
                }}
                cursor={{ fill: "rgba(255,255,255,0.03)" }}
              />
              <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                {funnelData.map((_, i) => (
                  <Cell key={i} fill={FUNNEL_COLORS[i]} opacity={0.8} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>
      )}

      {/* Queue table */}
      <Card className="overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-800 flex flex-col sm:flex-row sm:items-center gap-3 justify-between">
          <div className="flex items-center gap-2">
            <p className="text-sm font-semibold text-gray-200">Priority Queue</p>
            {!isLoading && (
              <span className="text-xs text-gray-500 bg-gray-800 px-2 py-0.5 rounded-full">
                {filtered.length} items
              </span>
            )}
          </div>
          <div className="flex gap-2">
            <FilterSelect
              value={severityFilter}
              onChange={setSeverityFilter}
              options={["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => ({ label: s, value: s }))}
              placeholder="All severities"
            />
            <FilterSelect
              value={statusFilter}
              onChange={setStatusFilter}
              options={["PENDING", "APPROVED", "EXECUTED", "BLOCKED"].map((s) => ({ label: s, value: s }))}
              placeholder="All statuses"
            />
          </div>
        </div>

        {isLoading ? (
          <div className="p-5">
            <TableSkeleton rows={5} cols={6} />
          </div>
        ) : decisionsQuery.error ? (
          <ErrorState message={decisionsQuery.error} />
        ) : decisions.length === 0 ? (
          <EmptyState message="No data available" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  {["Priority", "Control", "Severity", "Decision", "Created", "Actions"].map((h) => (
                    <th
                      key={h}
                      className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider whitespace-nowrap"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/50">
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={6}>
                      <EmptyState message="No items match filters" />
                    </td>
                  </tr>
                ) : (
                  filtered.map((d) => {
                    const crid = d.compliance_result_id ?? String(d.id);
                    const isActing = (k: string) => loadingId === `${k}-${crid}`;
                    return (
                      <tr key={d.id} className="hover:bg-gray-800/40 transition-colors">
                        <td className="px-5 py-3.5">
                          <span className="text-xs font-bold text-gray-300">{d.priority}</span>
                        </td>
                        <td className="px-5 py-3.5 font-mono text-xs text-gray-200">
                          {d.control_id.replace(/_/g, " ")}
                        </td>
                        <td className="px-5 py-3.5">
                          <SeverityBadge value={d.severity as Severity} />
                        </td>
                        <td className="px-5 py-3.5">
                          <span className="text-xs font-semibold text-gray-300">{d.decision}</span>
                        </td>
                        <td className="px-5 py-3.5 text-gray-500 text-xs whitespace-nowrap">
                          {relDate(d.created_at)}
                        </td>
                        <td className="px-5 py-3.5">
                          <div className="flex items-center gap-1.5">
                            {d.decision === "PENDING" && (
                              <Button
                                variant="primary"
                                size="sm"
                                loading={isActing("approve")}
                                onClick={() => requestAction("approve", crid, d.control_id)}
                              >
                                <CheckCircle size={11} /> Approve
                              </Button>
                            )}
                            {d.decision === "APPROVED" && (
                              <Button
                                variant="primary"
                                size="sm"
                                loading={isActing("execute")}
                                onClick={() => requestAction("execute", crid, d.control_id)}
                              >
                                <Play size={11} /> Execute
                              </Button>
                            )}
                            {d.decision === "EXECUTED" && (
                              <>
                                <Button
                                  variant="secondary"
                                  size="sm"
                                  loading={isActing("verify")}
                                  onClick={() => requestAction("verify", crid, d.control_id)}
                                >
                                  <ShieldCheck size={11} /> Verify
                                </Button>
                                <Button
                                  variant="danger"
                                  size="sm"
                                  loading={isActing("rollback")}
                                  onClick={() => requestAction("rollback", crid, d.control_id)}
                                >
                                  <RotateCcw size={11} /> Rollback
                                </Button>
                              </>
                            )}
                            <Button variant="ghost" size="sm">
                              <Eye size={11} />
                            </Button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
