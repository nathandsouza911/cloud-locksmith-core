"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Lock,
  RefreshCw,
  ShieldCheck,
  WandSparkles,
} from "lucide-react";

import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  PageHeader,
  SeverityBadge,
  StatusBadge,
  TableSkeleton,
} from "@/components/ui";
import { useAttackPathRemediationPlan } from "@/lib/api/hooks";
import * as ep from "@/lib/api/endpoints";
import { useAuth } from "@/lib/auth-context";
import type { AttackPathRemediationStep } from "@/types";

type ToastState = { tone: "success"; message: string } | { tone: "error"; message: string } | null;

function formatControlLabel(controlId: string): string {
  return controlId
    .replace(/^IDENTITY_/, "")
    .split("_")
    .filter(Boolean)
    .map((segment) => segment.charAt(0) + segment.slice(1).toLowerCase())
    .join(" ");
}

function isLocked(steps: AttackPathRemediationStep[], index: number): boolean {
  if (index === 0) return false;
  return steps.slice(0, index).some((step) => step.status !== "completed");
}

function impactSummary(scoreIncrease?: number, pathsResolved?: number): string {
  if (typeof scoreIncrease === "number" && typeof pathsResolved === "number") {
    return `Fixing this will increase your score by +${scoreIncrease} and remove ${pathsResolved} attack path${pathsResolved === 1 ? "" : "s"}.`;
  }
  if (typeof scoreIncrease === "number") {
    return `Fixing this will increase your score by +${scoreIncrease}.`;
  }
  return "Fixing these steps will resolve the selected attack path in order.";
}

function toastClasses(tone: "success" | "error"): string {
  return tone === "success"
    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-100"
    : "border-red-500/30 bg-red-500/10 text-red-100";
}

export default function AttackPathDetailPage() {
  const params = useParams<{ pathId: string }>();
  const router = useRouter();
  const { tenantId, requiresTenantSelection, setActiveTenantId } = useAuth();
  const pathId = typeof params?.pathId === "string" ? params.pathId : "";
  const planQuery = useAttackPathRemediationPlan(pathId || null);

  const [executingControlId, setExecutingControlId] = useState<string | null>(null);
  const [executingAll, setExecutingAll] = useState(false);
  const [toast, setToast] = useState<ToastState>(null);
  const [failedStep, setFailedStep] = useState<string | null>(null);

  const plan = planQuery.data;
  const steps = plan?.steps ?? [];
  const pendingSteps = steps.filter((step) => step.status === "pending");
  const allCompleted = steps.length > 0 && steps.every((step) => step.status === "completed");

  useEffect(() => {
    if (!toast) return undefined;
    const timeout = window.setTimeout(() => setToast(null), 3000);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  useEffect(() => {
    if (!tenantId) return;
    setActiveTenantId(tenantId);
  }, [setActiveTenantId, tenantId]);

  const subtitle = useMemo(() => {
    if (!plan) return "Load the remediation plan for this attack path.";
    return impactSummary(plan.estimated_impact?.score_increase, plan.estimated_impact?.paths_resolved);
  }, [plan]);

  async function refreshPlan() {
    await planQuery.refetch();
    router.refresh();
  }

  async function handleExecuteStep(controlId: string) {
    setExecutingControlId(controlId);
    setFailedStep(null);
    setToast(null);
    try {
      const response = await ep.executeAttackPathStep(pathId, controlId);
      await refreshPlan();
      if (response.status === "completed" && response.step_completed) {
        setToast({ tone: "success", message: "Step completed successfully." });
        return;
      }
      setFailedStep(response.control_id);
      setToast({ tone: "error", message: response.error ?? "Step execution failed." });
    } catch (error) {
      setFailedStep(controlId);
      setToast({
        tone: "error",
        message: error instanceof Error ? error.message : "Step execution failed.",
      });
    } finally {
      setExecutingControlId(null);
    }
  }

  async function handleExecuteAll() {
    setExecutingAll(true);
    setFailedStep(null);
    setToast(null);
    try {
      const response = await ep.executeAttackPathAll(pathId);
      await refreshPlan();
      if (response.partial) {
        setFailedStep(response.failed_step);
        setToast({
          tone: "error",
          message: response.failed_step
            ? `Execution stopped at ${formatControlLabel(response.failed_step)}.`
            : response.message,
        });
        return;
      }
      setToast({
        tone: "success",
        message: allCompleted ? "Attack path already resolved." : "Attack path resolved.",
      });
    } catch (error) {
      setToast({
        tone: "error",
        message: error instanceof Error ? error.message : "Attack path execution failed.",
      });
    } finally {
      setExecutingAll(false);
    }
  }

  if (requiresTenantSelection || !tenantId) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Attack Path Remediation"
          subtitle="Select a tenant to execute the remediation workflow."
          actions={
            <Link href="/dashboard/attack-paths">
              <Button variant="secondary" size="sm">
                <ArrowLeft size={12} />
                Back
              </Button>
            </Link>
          }
        />
        <Card className="p-8">
          <EmptyState message="Select a tenant to view this attack path workflow" />
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={plan?.name ?? "Attack Path Remediation"}
        subtitle={subtitle}
        actions={
          <>
            <Link href="/dashboard/attack-paths">
              <Button variant="secondary" size="sm">
                <ArrowLeft size={12} />
                Back
              </Button>
            </Link>
            <Button variant="secondary" size="sm" onClick={refreshPlan} loading={planQuery.loading}>
              <RefreshCw size={12} />
              Refresh
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={handleExecuteAll}
              loading={executingAll}
              disabled={pendingSteps.length === 0 || executingControlId !== null}
            >
              <WandSparkles size={12} />
              Fix Entire Path
            </Button>
          </>
        }
      />

      {toast ? (
        <Card className={`px-4 py-3 text-sm ${toastClasses(toast.tone)}`}>{toast.message}</Card>
      ) : null}

      {failedStep ? (
        <Card className="border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-100">
          Execution stopped at <span className="font-semibold">{formatControlLabel(failedStep)}</span>.
        </Card>
      ) : null}

      {allCompleted ? (
        <Card className="border-emerald-500/30 bg-emerald-500/10 p-5">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div className="flex items-start gap-3">
              <ShieldCheck size={18} className="mt-0.5 text-emerald-300" />
              <div>
                <p className="text-sm font-semibold text-emerald-100">Attack path resolved</p>
                <p className="mt-1 text-sm text-emerald-50/80">
                  All required steps are complete. The latest risk feed and score views will reflect the
                  updated backend state.
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Link href="/dashboard/attack-paths">
                <Button variant="secondary" size="sm">
                  Back to Attack Paths
                </Button>
              </Link>
              <Link href="/risk-feed">
                <Button variant="primary" size="sm">
                  Open Risk Feed
                </Button>
              </Link>
            </div>
          </div>
        </Card>
      ) : null}

      <Card className="p-5">
        {planQuery.loading ? (
          <TableSkeleton rows={4} cols={1} />
        ) : planQuery.error ? (
          <ErrorState message={planQuery.error} />
        ) : !plan ? (
          <EmptyState message="No remediation plan available for this attack path" />
        ) : (
          <div className="space-y-5">
            <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
              <div className="space-y-2">
                <div className="flex flex-wrap items-center gap-3">
                  <p className="text-lg font-semibold text-gray-100">{plan.name ?? plan.path_id}</p>
                  <SeverityBadge value={plan.severity} />
                </div>
                {plan.description ? (
                  <p className="max-w-3xl text-sm text-gray-300">{plan.description}</p>
                ) : null}
              </div>
              {plan.estimated_impact ? (
                <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 px-4 py-3 text-sm text-cyan-100">
                  <p>
                    Score change:{" "}
                    <span className="font-semibold">+{plan.estimated_impact.score_increase ?? 0}</span>
                  </p>
                  <p className="mt-1 text-cyan-100/80">
                    {plan.estimated_impact.score_before ?? "-"} to {plan.estimated_impact.score_after ?? "-"}
                  </p>
                </div>
              ) : null}
            </div>

            <div className="space-y-3">
              {steps.map((step, index) => {
                const locked = isLocked(steps, index);
                const statusLabel =
                  locked && step.status !== "completed" ? "LOCKED" : step.status.toUpperCase();
                const isRunning = executingControlId === step.control_id;

                return (
                  <div
                    key={step.control_id}
                    className={`rounded-xl border px-4 py-4 ${
                      step.status === "completed"
                        ? "border-emerald-500/20 bg-emerald-500/5"
                        : locked
                          ? "border-gray-800 bg-gray-950/80"
                          : "border-gray-800 bg-gray-900/60"
                    }`}
                  >
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                      <div className="min-w-0 space-y-2">
                        <div className="flex flex-wrap items-center gap-3">
                          <span className="inline-flex h-7 w-7 items-center justify-center rounded-full border border-gray-700 bg-gray-950 text-xs font-semibold text-gray-300">
                            {step.step}
                          </span>
                          <p className="text-sm font-semibold text-gray-100">{step.title}</p>
                          <StatusBadge value={statusLabel} />
                        </div>
                        <p className="text-xs uppercase tracking-wide text-gray-500">
                          {formatControlLabel(step.control_id)}
                        </p>
                        <p className="text-sm text-gray-400">
                          {step.active_finding_count} active finding
                          {step.active_finding_count === 1 ? "" : "s"} in this step
                        </p>
                        {step.status === "completed" ? (
                          <div className="inline-flex items-center gap-2 text-sm text-emerald-300">
                            <CheckCircle2 size={14} />
                            Step complete
                          </div>
                        ) : locked ? (
                          <div className="inline-flex items-center gap-2 text-sm text-gray-400">
                            <Lock size={14} />
                            Complete previous step first
                          </div>
                        ) : null}
                      </div>

                      <div className="flex shrink-0 items-center gap-2">
                        <Button
                          variant={step.status === "completed" ? "secondary" : "primary"}
                          size="sm"
                          onClick={() => handleExecuteStep(step.control_id)}
                          loading={isRunning}
                          disabled={step.status === "completed" || locked || executingAll}
                        >
                          {step.status === "completed" ? "Completed" : "Fix Step"}
                        </Button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </Card>

      {!planQuery.loading && !planQuery.error && steps.length === 0 ? (
        <Card className="border-yellow-500/20 bg-yellow-500/5 px-4 py-3 text-sm text-yellow-100">
          No executable steps were returned for this attack path.
        </Card>
      ) : null}

      {plan?.estimated_impact?.paths_resolved ? (
        <Card className="border-cyan-500/20 bg-cyan-500/5 px-4 py-3 text-sm text-cyan-100">
          Fixing this path is expected to resolve {plan.estimated_impact.paths_resolved} active attack path
          {plan.estimated_impact.paths_resolved === 1 ? "" : "s"}.
        </Card>
      ) : null}

      {toast?.tone === "error" && !failedStep ? (
        <Card className="border-red-500/20 bg-red-500/5 px-4 py-3 text-sm text-red-100">
          <div className="flex items-center gap-2">
            <AlertTriangle size={14} />
            Review the current step state and try again after the blocking condition is cleared.
          </div>
        </Card>
      ) : null}
    </div>
  );
}
