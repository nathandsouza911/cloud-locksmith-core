"use client";

/**
 * My Work — the technician landing screen (Sprint 1).
 *
 * Answers "what work should I do today?" rather than "how secure is this
 * tenant?" (Product Bible §13). Deliberately contains no charts and no posture
 * score: those live on the Fleet dashboard, which is unchanged.
 *
 * Everything here is read-only. Actions deep-link into the existing screens
 * that already know how to review and remediate — Sprint 1 adds no new
 * execution, approval or write path.
 */

import { useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { AlertTriangle, ArrowRight, CheckCircle2, Clock, ListChecks, RefreshCw } from "lucide-react";

import { Button, Card, ErrorState, PageHeader, StatCard, TableSkeleton } from "@/components/ui";
import { useAuth } from "@/lib/auth-context";
import { useWorkQueue } from "@/lib/api/hooks";
import type { WorkGroup, WorkPriority } from "@/types/work";

function formatMinutes(minutes: number): string {
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  const remainder = minutes % 60;
  return remainder === 0 ? `${hours} hr` : `${hours} hr ${remainder} min`;
}

function priorityLabel(priority: WorkPriority): string {
  return priority === "HIGH" ? "High Priority" : "Normal Priority";
}

function priorityClasses(priority: WorkPriority): string {
  return priority === "HIGH"
    ? "bg-orange-500/15 text-orange-400 border-orange-500/30"
    : "bg-gray-700/40 text-gray-300 border-gray-600/40";
}

const RUN_STATE_BADGE_STYLES: Record<string, string> = {
  CREATED: "bg-gray-700/40 text-gray-300 border-gray-600/40",
  DISCOVERING: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  READY_FOR_REVIEW: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  IN_REVIEW: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  EXECUTING: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  VERIFYING: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  COMPLETED: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  FAILED: "bg-red-500/15 text-red-400 border-red-500/30",
  CANCELLED: "bg-gray-700/40 text-gray-400 border-gray-600/40",
};

function RunStateBadge({ runState }: { runState: string }) {
  const classes = RUN_STATE_BADGE_STYLES[runState] ?? RUN_STATE_BADGE_STYLES.CREATED;
  return (
    <span
      data-testid="work-card-run-badge"
      className={`px-2 py-0.5 rounded-md border text-[10px] font-semibold uppercase tracking-wider ${classes}`}
    >
      {runState.replace(/_/g, " ")}
    </span>
  );
}

function WorkCard({ group }: { group: WorkGroup }) {
  const driftedItems = group.items.filter((item) => item.drift_count > 0).length;

  return (
    <Card data-testid="work-card" className="p-5 flex flex-col gap-4 hover:border-gray-700 transition-colors">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="text-base font-semibold text-white">{group.workflow_name}</h3>
            <span
              className={`px-2 py-0.5 rounded-md border text-[10px] font-semibold uppercase tracking-wider ${priorityClasses(
                group.priority,
              )}`}
            >
              {priorityLabel(group.priority)}
            </span>
            {group.run_state && <RunStateBadge runState={group.run_state} />}
          </div>
          <p className="text-sm text-gray-400 mt-1">{group.tenant_name ?? group.tenant_id}</p>
        </div>

        <div className="flex items-center gap-4 text-sm shrink-0">
          <span className="flex items-center gap-1.5 text-gray-300">
            <ListChecks size={14} className="text-gray-500" />
            <span className="tabular-nums font-semibold">{group.item_count}</span>
            <span className="text-gray-500">{group.item_count === 1 ? "item" : "items"}</span>
          </span>
          <span className="flex items-center gap-1.5 text-gray-300">
            <Clock size={14} className="text-gray-500" />
            <span className="tabular-nums">{formatMinutes(group.estimated_minutes)}</span>
          </span>
        </div>
      </div>

      {driftedItems > 0 && (
        <p className="flex items-center gap-1.5 text-xs text-orange-400">
          <AlertTriangle size={13} />
          {driftedItems} {driftedItems === 1 ? "item has" : "items have"} regressed since a previous fix
        </p>
      )}

      {(group.reviewed_count > 0 || group.new_count > 0 || group.changed_count > 0) && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
          {group.reviewed_count > 0 && (
            <span className="flex items-center gap-1.5 text-gray-400">
              <CheckCircle2 size={12} className="text-emerald-400" />
              {group.reviewed_count} previously reviewed
            </span>
          )}
          {group.new_count > 0 && (
            <span className="flex items-center gap-1.5 text-orange-400">
              <AlertTriangle size={12} />
              {group.new_count} new
            </span>
          )}
          {group.changed_count > 0 && (
            <span className="flex items-center gap-1.5 text-yellow-400">
              <RefreshCw size={12} />
              {group.changed_count} changed
            </span>
          )}
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3 pt-1 border-t border-gray-800/60">
        <p className="text-sm text-gray-400">{group.recommended_action}</p>
        <Link href={`/work/${encodeURIComponent(group.workflow_id)}`}>
          <Button variant="primary" size="sm">
            Review
            <ArrowRight size={13} />
          </Button>
        </Link>
      </div>
    </Card>
  );
}

export default function WorkPage() {
  const { data, loading, error, refetch } = useWorkQueue();
  const { tenants } = useAuth();
  const router = useRouter();

  // A brand-new user with zero connected tenants isn't experiencing an
  // error -- they just haven't onboarded yet. /tenants already renders a
  // correct empty state with an "Add Tenant" call to action; landing them
  // here instead of on a bare "Select a tenant to continue" message (which
  // reads exactly like a broken page) is the fix.
  const hasNoTenants = tenants.length === 0;
  useEffect(() => {
    if (hasNoTenants) {
      router.replace("/tenants");
    }
  }, [hasNoTenants, router]);

  if (hasNoTenants) {
    return null;
  }

  const summary = data?.summary;
  const groups = data?.groups ?? [];
  const highPriorityGroups = groups.filter((g) => g.priority === "HIGH");
  const normalPriorityGroups = groups.filter((g) => g.priority !== "HIGH");

  return (
    <div>
      <PageHeader
        title="My Work"
        subtitle={
          data?.tenant_name
            ? `Outstanding security work for ${data.tenant_name}`
            : "Outstanding security work"
        }
        actions={
          <Button onClick={() => refetch()} disabled={loading}>
            <RefreshCw size={13} />
            Refresh
          </Button>
        }
      />

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <div data-testid="stat-today">
          <StatCard
            label="Today's Work"
            value={summary?.today_count ?? 0}
            sub={
              summary
                ? `${summary.item_count} ${summary.item_count === 1 ? "item" : "items"} total`
                : undefined
            }
            icon={<ListChecks size={16} />}
          />
        </div>
        <div data-testid="stat-estimated">
          <StatCard
            label="Estimated Time"
            value={summary ? formatMinutes(summary.estimated_minutes) : "0 min"}
            sub="To clear the queue"
            icon={<Clock size={16} />}
          />
        </div>
        <div data-testid="stat-high">
          <StatCard
            label="High Priority"
            value={summary?.high_priority ?? 0}
            sub={`${summary?.normal_priority ?? 0} normal priority`}
            accent="text-orange-400"
            icon={<AlertTriangle size={16} />}
          />
        </div>
        <div data-testid="stat-completed">
          <StatCard
            label="Completed"
            value={summary?.completed ?? 0}
            sub="Resolved in the last 7 days"
            accent="text-emerald-400"
            icon={<CheckCircle2 size={16} />}
          />
        </div>
      </div>

      {loading && (
        <div data-testid="work-loading">
          <TableSkeleton rows={4} cols={4} />
        </div>
      )}

      {!loading && error && <ErrorState message={error} />}

      {!loading && !error && groups.length === 0 && (
        <Card data-testid="work-empty" className="p-12 text-center">
          <CheckCircle2 size={32} className="mx-auto text-emerald-400 mb-3" />
          <p className="text-base font-semibold text-white">No outstanding work</p>
          <p className="text-sm text-gray-400 mt-1">
            Every open finding for this client has been actioned. New work appears here after the next scan.
          </p>
        </Card>
      )}

      {!loading && !error && groups.length > 0 && (
        <div className="space-y-6">
          {highPriorityGroups.length > 0 && (
            <section>
              <h2 className="text-xs font-semibold tracking-widest text-orange-400/80 uppercase mb-3">
                High Priority
              </h2>
              <div className="space-y-3">
                {highPriorityGroups.map((group) => (
                  <WorkCard key={group.workflow_id} group={group} />
                ))}
              </div>
            </section>
          )}

          {normalPriorityGroups.length > 0 && (
            <section>
              <h2 className="text-xs font-semibold tracking-widest text-gray-500 uppercase mb-3">
                Normal Priority
              </h2>
              <div className="space-y-3">
                {normalPriorityGroups.map((group) => (
                  <WorkCard key={group.workflow_id} group={group} />
                ))}
              </div>
            </section>
          )}
        </div>
      )}
    </div>
  );
}
