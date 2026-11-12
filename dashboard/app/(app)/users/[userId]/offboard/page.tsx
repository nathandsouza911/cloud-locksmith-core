"use client";

import { useEffect, useMemo, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { ArrowLeft, CheckCircle2, RefreshCw, ShieldAlert, UserX, WandSparkles } from "lucide-react";

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
import * as ep from "@/lib/api/endpoints";
import type { DirectoryUser, OffboardingSession, OffboardingStep } from "@/types";

function relTime(iso: string | null) {
  if (!iso) return "No recent activity";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${Math.max(mins, 0)}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function stepActionLabel(step: OffboardingStep) {
  if (step.status === "completed") return "Completed";
  return step.type === "automated" ? "Execute" : "Mark Complete";
}

function stepTypeLabel(step: OffboardingStep) {
  return step.type === "automated" ? "Automated Step" : "Manual Step";
}

export default function UserOffboardingPage() {
  const params = useParams<{ userId: string }>();
  const router = useRouter();
  const userId = Array.isArray(params?.userId) ? params.userId[0] : params?.userId;

  const [user, setUser] = useState<DirectoryUser | null>(null);
  const [session, setSession] = useState<OffboardingSession | null>(null);
  const [loading, setLoading] = useState(true);
  const [sessionLoading, setSessionLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [actionStepId, setActionStepId] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [rollbackLoading, setRollbackLoading] = useState(false);
  const [restartLoading, setRestartLoading] = useState(false);

  async function loadPage() {
    if (!userId) return;
    setLoading(true);
    setError(null);
    try {
      const [nextUser, nextSession] = await Promise.all([
        ep.getUser(userId),
        ep.getUserOffboardingSession(userId).catch((err) => {
          if (err instanceof Error && err.message.toLowerCase().includes("not found")) return null;
          throw err;
        }),
      ]);
      setUser(nextUser);
      setSession(nextSession);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load user offboarding");
      setUser(null);
      setSession(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadPage();
  }, [userId]);

  const completedSteps = useMemo(
    () => (session?.steps ?? []).filter((step) => step.status === "completed").length,
    [session?.steps],
  );
  const totalSteps = session?.steps.length ?? 0;
  const progress = totalSteps > 0 ? Math.round((completedSteps / totalSteps) * 100) : 0;
  const hasFailedStep = (session?.steps ?? []).some((step) => step.status === "failed");
  const isIncomplete = Boolean(session && session.status !== "COMPLETED" && session.status !== "REVERSED");
  const canRestart = Boolean(session && (hasFailedStep || isIncomplete));

  async function handleStart() {
    if (!userId) return;
    setStarting(true);
    setError(null);
    setNotice(null);
    try {
      const nextSession = await ep.startUserOffboarding(userId);
      setSession(nextSession);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to start user offboarding");
    } finally {
      setStarting(false);
    }
  }

  async function refreshSession() {
    if (!userId) return;
    setSessionLoading(true);
    setError(null);
    try {
      const nextSession = session?.session_id
        ? await ep.getOffboardingSession(session.session_id)
        : await ep.getUserOffboardingSession(userId);
      setSession(nextSession);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to refresh offboarding session");
    } finally {
      setSessionLoading(false);
    }
  }

  async function handleStepExecute(stepId: string) {
    if (!userId) return;
    setActionStepId(stepId);
    setError(null);
    setNotice(null);
    try {
      const nextSession = await ep.executeUserOffboardingStep(userId, stepId);
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

  async function handleRollback() {
    if (!userId) return;
    setRollbackLoading(true);
    setError(null);
    setNotice(null);
    try {
      const result = await ep.rollbackUserOffboarding(userId);
      setNotice(
        [result.message, result.roles_restored.length > 0 ? result.roles_message : null]
          .filter(Boolean)
          .join(" "),
      );
      await loadPage();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to restore roles");
    } finally {
      setRollbackLoading(false);
    }
  }

  async function handleRestart() {
    if (!userId) return;
    setRestartLoading(true);
    setError(null);
    setNotice(null);
    try {
      const nextSession = await ep.restartUserOffboarding(userId);
      setSession((current) =>
        current
          ? {
              ...current,
              status: nextSession.status,
              steps: nextSession.steps,
              current_step: nextSession.current_step,
              step_states: nextSession.step_states,
              error: nextSession.error ?? null,
              retryable: nextSession.retryable ?? false,
            }
          : null,
      );
      setNotice("Offboarding workflow restarted from current tenant state");
      await loadPage();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to restart offboarding");
    } finally {
      setRestartLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="User Offboarding"
        subtitle={
          user
            ? `Lifecycle workflow for ${user.email ?? user.display_name ?? user.id}`
            : "Guided lifecycle workflow for identity offboarding"
        }
        actions={
          <>
            <Button variant="ghost" size="sm" onClick={() => router.push("/users")}>
              <ArrowLeft size={12} /> Back to users
            </Button>
            <Button variant="secondary" size="sm" onClick={loadPage} loading={loading || sessionLoading}>
              <RefreshCw size={12} /> Refresh
            </Button>
          </>
        }
      />

      {notice ? (
        <Card className="border-emerald-500/20 bg-emerald-500/5 px-4 py-3 text-sm text-emerald-200">
          {notice}
        </Card>
      ) : null}

      {loading ? (
        <Card className="p-5">
          <TableSkeleton rows={4} cols={2} />
        </Card>
      ) : error && !user ? (
        <ErrorState message={error} />
      ) : !user ? (
        <EmptyState message="User not found for the current tenant" />
      ) : (
        <>
          <div className="grid gap-4 lg:grid-cols-4">
            <Card className="p-5 lg:col-span-2">
              <div className="flex items-center gap-3">
                <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-red-500/10 text-red-300">
                  <UserX size={20} />
                </div>
                <div>
                  <p className="text-lg font-semibold text-gray-100">
                    {user.email ?? user.display_name ?? user.id}
                  </p>
                  <p className="text-sm text-gray-500">{user.display_name ?? user.id}</p>
                </div>
              </div>
              <div className="mt-4 grid gap-3 sm:grid-cols-2">
                <div>
                  <p className="text-xs font-medium uppercase tracking-wider text-gray-500">Role</p>
                  <p className="mt-1 text-sm text-gray-200">{user.role}</p>
                </div>
                <div>
                  <p className="text-xs font-medium uppercase tracking-wider text-gray-500">Status</p>
                  <p className="mt-1 text-sm text-gray-200">{user.enabled ? "Enabled" : "Disabled"}</p>
                </div>
                <div>
                  <p className="text-xs font-medium uppercase tracking-wider text-gray-500">Last Activity</p>
                  <p className="mt-1 text-sm text-gray-200">{relTime(user.last_activity)}</p>
                </div>
                <div>
                  <p className="text-xs font-medium uppercase tracking-wider text-gray-500">Risk Level</p>
                  <div className="mt-1">
                    {user.risk_level === "NONE" ? (
                      <span className="inline-flex rounded-md border border-gray-700 bg-gray-800 px-2 py-0.5 text-[11px] font-semibold text-gray-300">
                        NONE
                      </span>
                    ) : (
                      <SeverityBadge value={user.risk_level} />
                    )}
                  </div>
                </div>
                <div>
                  <p className="text-xs font-medium uppercase tracking-wider text-gray-500">Open Findings</p>
                  <p className="mt-1 text-sm text-gray-200">{user.open_findings}</p>
                </div>
              </div>
              {user.roles.length > 0 ? (
                <div className="mt-4 flex flex-wrap gap-2">
                  {user.roles.map((role) => (
                    <span
                      key={role}
                      className="inline-flex rounded-full border border-cyan-500/20 bg-cyan-500/10 px-2 py-0.5 text-[11px] font-medium text-cyan-200"
                    >
                      {role}
                    </span>
                  ))}
                </div>
              ) : null}
              {user.roles.some((role) => role.toLowerCase() === "global administrator") ? (
                <div className="mt-4 rounded-lg border border-red-500/20 bg-red-500/5 px-3 py-3 text-sm text-red-200">
                  <ShieldAlert size={14} className="mr-2 inline-block text-red-300" />
                  You are offboarding a privileged account
                </div>
              ) : null}
              {user.risk_indicators.length > 0 ? (
                <div className="mt-4 rounded-lg border border-yellow-500/20 bg-yellow-500/5 px-3 py-3 text-sm text-yellow-100">
                  <ShieldAlert size={14} className="mr-2 inline-block text-yellow-300" />
                  {user.risk_indicators.join(", ")}
                </div>
              ) : null}
            </Card>

            <Card className="p-5 lg:col-span-2">
              <p className="text-xs font-medium uppercase tracking-wider text-gray-500">Workflow</p>
              <p className="mt-3 text-2xl font-bold text-gray-100">Secure User Exit</p>
              <p className="mt-2 text-sm text-gray-400">
                Remove elevated access, revoke active sessions, disable the account, and track any handoff
                work that still needs a human confirmation.
              </p>
              {!session ? (
                <div className="mt-5">
                  <Button variant="primary" size="md" loading={starting} onClick={handleStart}>
                    <WandSparkles size={14} /> Start Offboarding
                  </Button>
                </div>
              ) : (
                <div className="mt-5 flex flex-wrap items-center gap-3">
                  <StatusBadge value={session.status} />
                  <p className="text-sm text-gray-400">
                    {completedSteps}/{totalSteps} steps completed
                  </p>
                  {session.status === "COMPLETED" ? (
                    <Button variant="secondary" size="sm" loading={rollbackLoading} onClick={handleRollback}>
                      Rollback Offboarding
                    </Button>
                  ) : null}
                  {canRestart ? (
                    <Button variant="secondary" size="sm" loading={restartLoading} onClick={handleRestart}>
                      Restart Offboarding
                    </Button>
                  ) : null}
                </div>
              )}
            </Card>
          </div>

          {error && session ? (
            <Card className="border-red-500/20 bg-red-500/5 px-4 py-3 text-sm text-red-200">{error}</Card>
          ) : null}

          {session ? (
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
                    <p className="text-xs font-medium uppercase tracking-wider text-gray-500">
                      Session Status
                    </p>
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
                    <p className="text-sm font-semibold text-gray-200">Offboarding Steps</p>
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
                                  ? "Execute directly against the tenant."
                                  : "User confirms the handoff work is complete."}
                              </p>
                            </div>
                            {step.error ? <p className="mt-1 text-xs text-red-400">{step.error}</p> : null}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <StatusBadge value={step.status} />
                        <Button
                          variant={step.type === "automated" ? "primary" : "secondary"}
                          size="sm"
                          loading={actionStepId === step.id}
                          disabled={step.status === "completed"}
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
          ) : null}
        </>
      )}
    </div>
  );
}
