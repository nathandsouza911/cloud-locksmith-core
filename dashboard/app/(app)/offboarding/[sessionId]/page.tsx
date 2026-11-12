"use client";

import { useEffect, useMemo, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { ArrowLeft, CheckCircle2, RefreshCw, WandSparkles } from "lucide-react";

import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  PageHeader,
  StatusBadge,
  TableSkeleton,
} from "@/components/ui";
import * as ep from "@/lib/api/endpoints";
import type { OffboardingSession, OffboardingStep } from "@/types";

function stepActionLabel(step: OffboardingStep) {
  if (step.status === "completed") return "Completed";
  if (step.disabled) return "Blocked";
  return step.type === "automated" ? "Execute" : "Mark Complete";
}

function stepTypeLabel(step: OffboardingStep) {
  return step.type === "automated" ? "Automated Step" : "Manual Step";
}

export default function OffboardingSessionPage() {
  const params = useParams<{ sessionId: string }>();
  const router = useRouter();
  const sessionId = Array.isArray(params?.sessionId) ? params.sessionId[0] : params?.sessionId;
  const [session, setSession] = useState<OffboardingSession | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionStepId, setActionStepId] = useState<string | null>(null);

  async function loadSession() {
    if (!sessionId) return;
    setLoading(true);
    setError(null);
    try {
      const nextSession = await ep.getOffboardingSession(sessionId);
      setSession(nextSession);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load guided fix session");
      setSession(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadSession();
  }, [sessionId]);

  const completedSteps = useMemo(
    () => (session?.steps ?? []).filter((step) => step.status === "completed").length,
    [session?.steps],
  );
  const totalSteps = session?.steps.length ?? 0;
  const progress = totalSteps > 0 ? Math.round((completedSteps / totalSteps) * 100) : 0;

  async function handleStepExecute(stepId: string) {
    if (!sessionId) return;
    setActionStepId(stepId);
    setError(null);
    try {
      const nextSession = await ep.executeOffboardingStep(sessionId, stepId);
      setSession((current) =>
        current
          ? {
              ...current,
              status: nextSession.status,
              steps: nextSession.steps,
              error: nextSession.error ?? null,
              retryable: nextSession.retryable ?? false,
            }
          : null,
      );
      setError(nextSession.error ?? null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to execute step");
    } finally {
      setActionStepId(null);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Guided Fix"
        subtitle={
          session
            ? `${session.control_id.replace(/_/g, " ")} for ${session.resource_id}`
            : "Step-by-step remediation workflow"
        }
        actions={
          <>
            <Button variant="ghost" size="sm" onClick={() => router.push("/risk-feed")}>
              <ArrowLeft size={12} /> Back to findings
            </Button>
            <Button variant="secondary" size="sm" onClick={loadSession} loading={loading}>
              <RefreshCw size={12} /> Refresh
            </Button>
          </>
        }
      />

      {loading ? (
        <Card className="p-5">
          <TableSkeleton rows={4} cols={1} />
        </Card>
      ) : error ? (
        <ErrorState message={error} />
      ) : !session ? (
        <EmptyState message="Guided fix session not found" />
      ) : (
        <>
          <Card className="p-5">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <p className="text-xs font-medium uppercase tracking-wider text-gray-500">Progress</p>
                <p className="mt-2 text-3xl font-bold text-gray-100">
                  {completedSteps}/{totalSteps}
                </p>
                <p className="mt-1 text-sm text-gray-400">completed steps</p>
              </div>
              <div className="sm:text-right">
                <p className="text-xs font-medium uppercase tracking-wider text-gray-500">Session Status</p>
                <div className="mt-2">
                  <StatusBadge value={session.status} />
                </div>
              </div>
            </div>
            <div className="mt-4 h-2 overflow-hidden rounded-full bg-gray-800">
              <div
                className="h-full rounded-full bg-cyan-500 transition-all"
                style={{ width: `${progress}%` }}
              />
            </div>
          </Card>

          <Card className="overflow-hidden">
            <div className="border-b border-gray-800 px-5 py-4">
              <div className="flex items-center gap-2">
                <WandSparkles size={14} className="text-cyan-400" />
                <p className="text-sm font-semibold text-gray-200">Workflow Steps</p>
              </div>
            </div>
            <div className="divide-y divide-gray-800/60">
              {session.steps.map((step, index) => (
                <div
                  key={step.id}
                  className="flex flex-col gap-4 px-5 py-4 lg:flex-row lg:items-center lg:justify-between"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-3">
                      <div
                        className={`flex h-8 w-8 items-center justify-center rounded-full border text-xs font-semibold ${
                          step.status === "completed"
                            ? "border-green-500/30 bg-green-500/10 text-green-400"
                            : step.status === "failed"
                              ? "border-red-500/30 bg-red-500/10 text-red-400"
                              : "border-gray-700 bg-gray-800 text-gray-300"
                        }`}
                      >
                        {step.status === "completed" ? <CheckCircle2 size={14} /> : index + 1}
                      </div>
                      <div>
                        <p className="text-sm font-semibold text-gray-100">{step.title}</p>
                        <div className="mt-1 flex flex-wrap items-center gap-2">
                          <span
                            className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
                              step.type === "automated"
                                ? "border-cyan-500/30 bg-cyan-500/10 text-cyan-300"
                                : "border-yellow-500/30 bg-yellow-500/10 text-yellow-300"
                            }`}
                          >
                            {stepTypeLabel(step)}
                          </span>
                          <p className="text-xs text-gray-400">
                            {step.type === "automated"
                              ? "Executed directly against the tenant when confirmed."
                              : "User confirms this action has been completed manually."}
                          </p>
                        </div>
                        {step.error ? <p className="mt-1 text-xs text-red-400">{step.error}</p> : null}
                        {!step.error && step.blocked_reason ? (
                          <p className="mt-1 text-xs text-yellow-400">{step.blocked_reason}</p>
                        ) : null}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <StatusBadge value={step.status} />
                    <Button
                      variant={step.type === "automated" ? "primary" : "secondary"}
                      size="sm"
                      loading={actionStepId === step.id}
                      disabled={step.status === "completed" || step.disabled}
                      onClick={() => handleStepExecute(step.id)}
                    >
                      {stepActionLabel(step)}
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
