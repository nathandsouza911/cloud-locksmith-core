"use client";

import React, { useState, useCallback, useEffect } from "react";
import Link from "next/link";
import { useRouter, useParams } from "next/navigation";
import { CheckCircle, XCircle, Clock, AlertTriangle, RotateCcw, ArrowLeft } from "lucide-react";
import { Button, Card, ConfirmModal, ErrorState, PageHeader, TableSkeleton } from "@/components/ui";
import { useAuth } from "@/lib/auth-context";
import { useCampaign } from "@/lib/api/hooks";
import { approveCampaign, executeCampaign, rollbackCampaign, cancelCampaign } from "@/lib/api/campaigns";
import type {
  Campaign,
  CampaignStatus,
  CampaignTask,
  CampaignTaskChange,
  TaskStatus,
} from "@/types/campaign";
import { useRealtimeEvents } from "@/lib/hooks/useRealtimeEvents";
import type { RealtimeEvent } from "@/types/realtime";

// ── Status display helpers ────────────────────────────────────────────────────

const STATUS_LABEL: Record<CampaignStatus, string> = {
  PLAN: "Planning",
  AWAITING_APPROVAL: "Awaiting Approval",
  EXECUTING: "Executing",
  COMPLETED: "Completed",
  FAILED: "Failed",
  CANCELLED: "Cancelled",
  ROLLED_BACK: "Rolled Back",
};

const STATUS_CLASS: Record<CampaignStatus, string> = {
  PLAN: "bg-gray-700 text-gray-300",
  AWAITING_APPROVAL: "bg-yellow-900/60 text-yellow-300",
  EXECUTING: "bg-blue-900/60 text-blue-300",
  COMPLETED: "bg-green-900/60 text-green-300",
  FAILED: "bg-red-900/60 text-red-300",
  CANCELLED: "bg-gray-700 text-gray-400",
  ROLLED_BACK: "bg-purple-900/60 text-purple-300",
};

const TASK_STATUS_CLASS: Partial<Record<TaskStatus, string>> = {
  PLANNED: "text-gray-400",
  EXECUTING: "text-blue-300",
  EXECUTED: "text-green-300",
  VERIFIED: "text-green-400",
  FAILED: "text-red-400",
  LOCK_DEFERRED: "text-yellow-400",
  SKIPPED: "text-gray-500",
  ROLLED_BACK: "text-purple-300",
};

function StatusBadge({ status }: { status: CampaignStatus }) {
  return (
    <span
      className={`inline-block rounded-full px-3 py-1 text-sm font-semibold ${STATUS_CLASS[status] ?? "bg-gray-700 text-gray-300"}`}
    >
      {STATUS_LABEL[status] ?? status}
    </span>
  );
}

// ── Task row ─────────────────────────────────────────────────────────────────

function TaskRow({ task }: { task: CampaignTask }) {
  const cls = TASK_STATUS_CLASS[task.status] ?? "text-gray-400";
  const resourceLabel = task.resource_detail?.upn ?? task.resource_detail?.resource_id ?? null;
  return (
    <tr className="border-b border-gray-800/50">
      <td className="px-4 py-2.5">
        <div className="text-sm text-gray-300">{task.tenant_name ?? task.tenant_id}</div>
        {task.tenant_name && <div className="font-mono text-xs text-gray-600 mt-0.5">{task.tenant_id}</div>}
      </td>
      <td className="px-4 py-2.5">
        <div className="font-mono text-xs text-gray-400">{task.control_id}</div>
        {task.resource_detail?.display_name && (
          <div className="text-xs text-gray-300 mt-0.5">{task.resource_detail.display_name}</div>
        )}
        {resourceLabel && <div className="text-xs text-gray-500 mt-0.5">{resourceLabel}</div>}
        {task.resource_detail?.last_sign_in && (
          <div className="text-xs text-gray-600 mt-0.5">
            Last sign-in: {new Date(task.resource_detail.last_sign_in).toLocaleDateString()}
          </div>
        )}
      </td>
      <td className={`px-4 py-2.5 text-xs font-semibold ${cls}`}>{task.status}</td>
      <td className="px-4 py-2.5 text-xs text-gray-500 tabular-nums">{task.attempts}</td>
      <td className="px-4 py-2.5 text-xs text-red-400">{task.error ?? ""}</td>
    </tr>
  );
}

// ── Task status breakdown ─────────────────────────────────────────────────────

function TaskBreakdown({ byStatus, total }: { byStatus: Campaign["tasks_by_status"]; total: number }) {
  return (
    <div className="flex flex-wrap gap-3">
      {Object.entries(byStatus).map(([status, count]) => (
        <span key={status} className="text-xs font-mono text-gray-400">
          <span className={`font-semibold ${TASK_STATUS_CLASS[status as TaskStatus] ?? ""}`}>{status}</span>:{" "}
          {count}
        </span>
      ))}
      <span className="text-xs text-gray-600">/ {total} total</span>
    </div>
  );
}

// ── Dry Run Banner ────────────────────────────────────────────────────────────

function DryRunBanner() {
  return (
    <div
      data-testid="dry-run-banner"
      className="rounded-lg border border-orange-700/50 bg-orange-950/30 px-4 py-3 text-sm text-orange-300 font-semibold"
    >
      Dry Run — no changes have been applied to tenants. Review the diff below before executing live.
    </div>
  );
}

// ── Per-tenant grouped task view ──────────────────────────────────────────────

const TABLE_HEADERS = ["Control", "Status", "Attempts", "Error"];

function TenantGroupedTasks({ tasks, dryRun = false }: { tasks: CampaignTask[]; dryRun?: boolean }) {
  const groups: Map<string, CampaignTask[]> = new Map();
  for (const task of tasks) {
    const existing = groups.get(task.tenant_id) ?? [];
    existing.push(task);
    groups.set(task.tenant_id, existing);
  }

  return (
    <div className="space-y-6">
      {Array.from(groups.entries()).map(([tenantId, tenantTasks]) => {
        const tenantName = tenantTasks[0]?.tenant_name;
        return (
          <div key={tenantId} data-testid={`tenant-group-${tenantId}`}>
            <div className="flex items-center gap-3 mb-2">
              <span
                data-testid={`tenant-group-label-${tenantId}`}
                className="text-sm font-semibold text-gray-200"
              >
                {tenantName ?? tenantId}
              </span>
              {tenantName && <span className="font-mono text-xs text-gray-600">{tenantId}</span>}
              <span className="text-xs text-gray-500">
                ({tenantTasks.length} task{tenantTasks.length !== 1 ? "s" : ""})
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-800">
                    {TABLE_HEADERS.map((h) => (
                      <th
                        key={h}
                        className="px-4 py-2 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {tenantTasks.map((task) => (
                    <TaskRowGrouped key={task.id} task={task} dryRun={dryRun} />
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function TaskRowGrouped({ task, dryRun = false }: { task: CampaignTask; dryRun?: boolean }) {
  const cls = TASK_STATUS_CLASS[task.status] ?? "text-gray-400";
  const resourceLabel = task.resource_detail?.upn ?? task.resource_detail?.resource_id ?? null;
  const isLockDeferred = task.status === "LOCK_DEFERRED";
  return (
    <tr className="border-b border-gray-800/50">
      <td className="px-4 py-2.5">
        <div className="font-mono text-xs text-gray-400">{task.control_id}</div>
        {task.resource_detail?.display_name && (
          <div className="text-xs text-gray-300 mt-0.5">{task.resource_detail.display_name}</div>
        )}
        {resourceLabel && <div className="text-xs text-gray-500 mt-0.5">{resourceLabel}</div>}
        {task.resource_detail?.last_sign_in && (
          <div className="text-xs text-gray-600 mt-0.5">
            Last sign-in: {new Date(task.resource_detail.last_sign_in).toLocaleDateString()}
          </div>
        )}
      </td>
      <td className={`px-4 py-2.5 text-xs font-semibold ${cls}`}>
        {task.status}
        {isLockDeferred && (
          <span
            data-testid={`lock-deferred-note-${task.id}`}
            className="block text-yellow-500/70 font-normal mt-0.5"
          >
            Tenant busy — retry after active remediation completes
          </span>
        )}
      </td>
      <td className="px-4 py-2.5 text-xs text-gray-500 tabular-nums">{task.attempts}</td>
      <td className="px-4 py-2.5 text-xs text-red-400">
        {task.error ?? ""}
        {dryRun && task.result_json?.changes && task.result_json.changes.length > 0 && (
          <div data-testid={`dry-run-diff-${task.id}`} className="mt-1.5 space-y-1 text-orange-300">
            {task.result_json.changes.map((change: CampaignTaskChange, i: number) => (
              <div key={i} className="font-mono text-xs bg-orange-950/30 rounded px-2 py-1">
                {change.action}
                {Object.entries(change)
                  .filter(([k]) => k !== "action")
                  .map(([k, v]) => ` ${k}=${JSON.stringify(v)}`)
                  .join("")}
              </div>
            ))}
          </div>
        )}
      </td>
    </tr>
  );
}

// ── Completion Summary Card ───────────────────────────────────────────────────

const COMPLETION_STATUSES = new Set<string>(["COMPLETED", "FAILED", "ROLLED_BACK"]);

function CompletionSummaryCard({ campaign }: { campaign: Campaign }) {
  if (!COMPLETION_STATUSES.has(campaign.status)) return null;

  const durationMs =
    campaign.started_at && campaign.completed_at
      ? new Date(campaign.completed_at).getTime() - new Date(campaign.started_at).getTime()
      : null;
  const durationLabel = durationMs !== null ? `${Math.round(durationMs / 1000)}s` : "—";

  return (
    <Card data-testid="completion-summary" className="p-5">
      <h2 className="text-sm font-semibold text-gray-200 uppercase tracking-wider mb-4">Execution Summary</h2>
      <dl className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
        <div>
          <dt className="text-xs text-gray-500 uppercase tracking-wider mb-1">Tenants Affected</dt>
          <dd className="text-2xl font-bold text-gray-100">{campaign.tenants_affected}</dd>
        </div>
        <div>
          <dt className="text-xs text-gray-500 uppercase tracking-wider mb-1">Tasks Executed</dt>
          <dd className="text-2xl font-bold text-green-300">{campaign.tasks_executed}</dd>
        </div>
        <div>
          <dt className="text-xs text-gray-500 uppercase tracking-wider mb-1">Tasks Failed</dt>
          <dd
            className={`text-2xl font-bold ${campaign.tasks_failed > 0 ? "text-red-400" : "text-gray-500"}`}
          >
            {campaign.tasks_failed}
          </dd>
        </div>
        <div>
          <dt className="text-xs text-gray-500 uppercase tracking-wider mb-1">Duration</dt>
          <dd className="text-2xl font-bold text-gray-100">{durationLabel}</dd>
        </div>
      </dl>
      {campaign.rollback_available && (
        <p className="mt-4 text-xs text-purple-400 font-semibold">
          Rollback available — all executed tasks can be reversed.
        </p>
      )}
      {!campaign.rollback_available && campaign.status === "COMPLETED" && (
        <p className="mt-4 text-xs text-gray-500">Rollback not available for this campaign.</p>
      )}
      <div className="mt-4 flex gap-3">
        <a
          data-testid="export-csv-btn"
          href={`/api/v1/fleet/campaigns/${campaign.campaign_id}/export/csv`}
          download
          className="text-xs text-blue-400 hover:text-blue-300 underline"
        >
          Export CSV
        </a>
        <a
          data-testid="export-pdf-btn"
          href={`/api/v1/fleet/campaigns/${campaign.campaign_id}/export/pdf`}
          download
          className="text-xs text-blue-400 hover:text-blue-300 underline"
        >
          Export PDF
        </a>
      </div>
    </Card>
  );
}

// ── Audit trail section ───────────────────────────────────────────────────────

function AuditTrailSection({ campaign }: { campaign: Campaign }) {
  if (!COMPLETION_STATUSES.has(campaign.status)) return null;

  const tasksWithAudit = campaign.tasks.filter((t) => t.audit_log_id);

  return (
    <Card data-testid="audit-trail-section" className="p-5">
      <h2 className="text-sm font-semibold text-gray-200 uppercase tracking-wider mb-4">Audit Trail</h2>
      {tasksWithAudit.length === 0 ? (
        <p className="text-sm text-gray-500">No audit records linked to tasks.</p>
      ) : (
        <table className="w-full text-xs text-gray-300">
          <thead>
            <tr className="text-gray-500 text-left">
              <th className="py-1 pr-4">Tenant</th>
              <th className="py-1 pr-4">Control</th>
              <th className="py-1 pr-4">Status</th>
              <th className="py-1">Audit Log ID</th>
            </tr>
          </thead>
          <tbody>
            {campaign.tasks.map((t) => (
              <tr key={t.id} className="border-t border-gray-700">
                <td className="py-1 pr-4">{t.tenant_name || t.tenant_id}</td>
                <td className="py-1 pr-4">{t.control_id}</td>
                <td className="py-1 pr-4">{t.status}</td>
                <td className="py-1 font-mono text-gray-400">
                  {t.audit_log_id || <span className="text-gray-600 italic">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

// ── Action panel — renders the correct action buttons for each state ──────────

function ActionPanel({
  campaign,
  onApprove,
  onExecute,
  onRollback,
  onCancel,
  actionLoading,
}: {
  campaign: Campaign;
  onApprove: () => void;
  onExecute: () => void;
  onRollback: () => void;
  onCancel: () => void;
  actionLoading: string | null;
}) {
  const isApproved = !!campaign.approved_plan_hash;

  if (campaign.status === "AWAITING_APPROVAL" && !isApproved) {
    return (
      <div className="flex gap-3">
        <Button variant="primary" onClick={onApprove} loading={actionLoading === "approve"}>
          <CheckCircle size={13} />
          Approve
        </Button>
        <Button
          variant="ghost"
          onClick={onCancel}
          loading={actionLoading === "cancel"}
          className="text-red-400 hover:text-red-300"
        >
          <XCircle size={13} />
          Cancel
        </Button>
      </div>
    );
  }

  if (campaign.status === "AWAITING_APPROVAL" && isApproved) {
    return (
      <div className="flex gap-3">
        <Button variant="primary" onClick={onExecute} loading={actionLoading === "execute"}>
          <CheckCircle size={13} />
          Execute
        </Button>
        <Button
          variant="ghost"
          onClick={onCancel}
          loading={actionLoading === "cancel"}
          className="text-red-400 hover:text-red-300"
        >
          <XCircle size={13} />
          Cancel
        </Button>
      </div>
    );
  }

  if (campaign.status === "COMPLETED") {
    return (
      <Button variant="secondary" onClick={onRollback} loading={actionLoading === "rollback"}>
        <RotateCcw size={13} />
        Rollback
      </Button>
    );
  }

  if (campaign.status === "ROLLED_BACK") {
    return (
      <Link href="/campaigns">
        <Button variant="secondary">
          <ArrowLeft size={13} />
          Back to Campaigns
        </Button>
      </Link>
    );
  }

  return null;
}

// ── Page ──────────────────────────────────────────────────────────────────────

type PendingAction = "execute" | "rollback" | null;

export default function CampaignDetailPage() {
  const { isSmb } = useAuth();
  const router = useRouter();
  const params = useParams();
  const campaignId = params?.campaignId as string | null;

  const { data: campaign, loading, error, refetch } = useCampaign(campaignId ?? null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<PendingAction>(null);

  const handleRealtimeEvent = useCallback(
    (event: RealtimeEvent) => {
      const campaignEvents = [
        "CampaignExecuting",
        "CampaignCompleted",
        "CampaignRolledBack",
        "TaskExecuted",
        "TaskFailed",
        "TaskLockDeferred",
      ];
      if (
        campaignEvents.includes(event.event_type) &&
        "campaign_id" in event.payload &&
        event.payload.campaign_id === campaignId
      ) {
        refetch();
      }
    },
    [campaignId, refetch],
  );

  const handleReconnect = useCallback(() => {
    refetch();
  }, [refetch]);

  const { connected: sseConnected } = useRealtimeEvents({
    onEvent: handleRealtimeEvent,
    onReconnect: handleReconnect,
    enabled: campaign?.status === "EXECUTING",
  });

  // Auto-poll every 5s while the campaign is executing (fallback when SSE is not connected).
  useEffect(() => {
    if (campaign?.status !== "EXECUTING") return;
    if (sseConnected) return; // SSE connected — no polling needed
    const interval = setInterval(refetch, 5000);
    return () => clearInterval(interval);
  }, [campaign?.status, refetch, sseConnected]);

  const runAction = useCallback(
    async (key: string, fn: () => Promise<unknown>) => {
      setActionLoading(key);
      setActionError(null);
      try {
        await fn();
        refetch();
      } catch (err) {
        setActionError(err instanceof Error ? err.message : "Action failed");
      } finally {
        setActionLoading(null);
      }
    },
    [refetch],
  );

  if (isSmb) {
    router.replace("/dashboard");
    return null;
  }

  if (loading) return <TableSkeleton rows={8} cols={5} />;
  if (error || !campaign) return <ErrorState message={error ?? "Campaign not found"} />;

  const isApproved = !!campaign.approved_plan_hash;

  // Unique tenant count for confirmation message.
  const uniqueTenants = new Set(campaign.tasks.map((t) => t.tenant_id)).size;
  const executeMessage = `This will execute ${campaign.total_tasks} task(s) across ${uniqueTenants} tenant(s) in production. Type CONFIRM to proceed.`;
  const rollbackMessage = `This will roll back all executed tasks (${campaign.tasks.filter((t) => t.status === "EXECUTED").length} account(s) will be re-enabled). Continue?`;

  return (
    <>
      <ConfirmModal
        open={pendingAction === "execute"}
        title="Execute Campaign"
        message={executeMessage}
        confirmLabel="Execute"
        variant="danger"
        requireTypedConfirm
        onConfirm={() => {
          setPendingAction(null);
          runAction("execute", () => executeCampaign(campaign.campaign_id));
        }}
        onCancel={() => setPendingAction(null)}
      />
      <ConfirmModal
        open={pendingAction === "rollback"}
        title="Rollback Campaign"
        message={rollbackMessage}
        confirmLabel="Rollback"
        variant="warning"
        onConfirm={() => {
          setPendingAction(null);
          runAction("rollback", () => rollbackCampaign(campaign.campaign_id));
        }}
        onCancel={() => setPendingAction(null)}
      />
      <div className="space-y-6">
        <PageHeader
          title={`Campaign`}
          subtitle={`${campaign.control_ids.join(", ")} · ${campaign.dry_run ? "Dry Run" : "Live"}`}
          actions={
            <ActionPanel
              campaign={campaign}
              actionLoading={actionLoading}
              onApprove={() =>
                runAction("approve", () =>
                  approveCampaign(campaign.campaign_id, { expected_plan_hash: campaign.plan_hash! }),
                )
              }
              onExecute={() => setPendingAction("execute")}
              onRollback={() => setPendingAction("rollback")}
              onCancel={() => runAction("cancel", () => cancelCampaign(campaign.campaign_id))}
            />
          }
        />

        {actionError && (
          <Card className="px-4 py-3 border-red-800/50 bg-red-950/30 text-sm text-red-300">
            {actionError}
          </Card>
        )}

        {/* Status + metadata */}
        <Card className="p-5 space-y-4">
          <div className="flex items-center gap-4 flex-wrap">
            <StatusBadge status={campaign.status} />
            {campaign.dry_run && (
              <span className="inline-block rounded-full px-2.5 py-0.5 text-xs font-semibold bg-orange-900/50 text-orange-300">
                Dry Run
              </span>
            )}
          </div>

          <dl className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
            <div>
              <dt className="text-xs text-gray-500 uppercase tracking-wider mb-1">Campaign ID</dt>
              <dd className="font-mono text-xs text-gray-300">{campaign.campaign_id}</dd>
            </div>
            <div>
              <dt className="text-xs text-gray-500 uppercase tracking-wider mb-1">Created By</dt>
              <dd className="text-gray-300">{campaign.created_by}</dd>
            </div>
            <div>
              <dt className="text-xs text-gray-500 uppercase tracking-wider mb-1">Controls</dt>
              <dd className="font-mono text-xs text-gray-300">{campaign.control_ids.join(", ")}</dd>
            </div>
            {campaign.approved_by && (
              <div>
                <dt className="text-xs text-gray-500 uppercase tracking-wider mb-1">Approved By</dt>
                <dd className="text-gray-300">{campaign.approved_by}</dd>
              </div>
            )}
          </dl>

          {/* Plan hash — show prominently when waiting for approval */}
          {campaign.status === "AWAITING_APPROVAL" && !isApproved && campaign.plan_hash && (
            <div className="rounded-lg border border-yellow-800/40 bg-yellow-950/20 p-4">
              <p className="text-xs text-yellow-400 font-semibold uppercase tracking-wider mb-2 flex items-center gap-2">
                <AlertTriangle size={13} />
                Review Required — Plan Hash
              </p>
              <p className="text-xs text-gray-500 mb-2">
                Verify this hash matches the plan below before approving.
              </p>
              <code className="block font-mono text-sm text-yellow-300 break-all">{campaign.plan_hash}</code>
            </div>
          )}

          {/* Approved confirmation */}
          {isApproved && (
            <div className="rounded-lg border border-green-800/40 bg-green-950/20 p-4">
              <p className="text-xs text-green-400 font-semibold uppercase tracking-wider mb-1">
                Plan Approved
              </p>
              <code className="block font-mono text-xs text-green-300 break-all">
                {campaign.approved_plan_hash}
              </code>
            </div>
          )}
        </Card>

        <CompletionSummaryCard campaign={campaign} />

        <AuditTrailSection campaign={campaign} />

        {campaign.dry_run && <DryRunBanner />}

        {/* Task breakdown */}
        <Card className="p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-gray-200 uppercase tracking-wider">
              Tasks ({campaign.total_tasks})
            </h2>
            <TaskBreakdown byStatus={campaign.tasks_by_status} total={campaign.total_tasks} />
          </div>

          {campaign.tasks.length > 0 ? (
            <TenantGroupedTasks tasks={campaign.tasks} dryRun={campaign.dry_run} />
          ) : (
            <p className="text-sm text-gray-500">No tasks in this campaign.</p>
          )}
        </Card>
      </div>
    </>
  );
}
