"use client";

import { useCallback, useEffect, useReducer, useRef } from "react";
import { useRealtimeEvents } from "@/lib/hooks/useRealtimeEvents";
import type { RealtimeEvent } from "@/types/realtime";

// ── State ────────────────────────────────────────────────────────────────────

interface OperationsState {
  liveCampaigns: Record<string, unknown>[];
  recentTasks: Record<string, unknown>[];
  criticalFailures: Record<string, unknown>[];
  scheduledJobs: Record<string, unknown>[];
  driftFeed: Record<string, unknown>[];
}

const initialState: OperationsState = {
  liveCampaigns: [],
  recentTasks: [],
  criticalFailures: [],
  scheduledJobs: [],
  driftFeed: [],
};

type OperationsAction =
  | { type: "REST_REFRESH"; data: Partial<OperationsState> }
  | { type: "APPEND_TASK"; payload: Record<string, unknown> }
  | { type: "APPEND_FAILURE"; payload: Record<string, unknown> }
  | { type: "APPEND_JOB"; payload: Record<string, unknown> }
  | { type: "TRIGGER_REFETCH" };

function operationsReducer(state: OperationsState, action: OperationsAction): OperationsState {
  switch (action.type) {
    case "REST_REFRESH":
      return { ...state, ...action.data };
    case "APPEND_TASK":
      return {
        ...state,
        recentTasks: [action.payload, ...state.recentTasks].slice(0, 50),
      };
    case "APPEND_FAILURE":
      return {
        ...state,
        criticalFailures: [action.payload, ...state.criticalFailures].slice(0, 50),
      };
    case "APPEND_JOB":
      return {
        ...state,
        scheduledJobs: [action.payload, ...state.scheduledJobs].slice(0, 50),
      };
    case "TRIGGER_REFETCH":
      return state;
    default:
      return state;
  }
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function OperationsLivePage() {
  const [state, dispatch] = useReducer(operationsReducer, initialState);
  const refetchRef = useRef<() => void>(() => {});

  const restRefetch = useCallback(async () => {
    try {
      const [campaignsRes, driftRes] = await Promise.all([
        fetch("/api/v1/campaigns?status=EXECUTING", { credentials: "include" }),
        fetch("/api/v1/drift-notifications?limit=20", { credentials: "include" }),
      ]);
      const campaigns: Record<string, unknown>[] = campaignsRes.ok
        ? ((await campaignsRes.json()) as Record<string, unknown>[])
        : [];
      const drift: Record<string, unknown>[] = driftRes.ok
        ? ((await driftRes.json()) as Record<string, unknown>[])
        : [];
      dispatch({ type: "REST_REFRESH", data: { liveCampaigns: campaigns, driftFeed: drift } });
    } catch {
      // fail-open: leave previous state intact
    }
  }, []);

  useEffect(() => {
    refetchRef.current = restRefetch;
    void restRefetch();
  }, [restRefetch]);

  const handleEvent = useCallback((event: RealtimeEvent) => {
    switch (event.event_type) {
      case "CampaignExecuting":
      case "CampaignCompleted":
      case "CampaignRolledBack":
        refetchRef.current();
        break;
      case "TaskExecuted":
      case "TaskFailed":
      case "TaskLockDeferred":
        dispatch({ type: "APPEND_TASK", payload: event.payload });
        break;
      case "RemediationFailure":
        dispatch({ type: "APPEND_FAILURE", payload: event.payload });
        break;
      case "ScheduledJobCreated":
      case "ScheduledJobClaimed":
      case "ScheduledJobExecuted":
      case "ScheduledJobFailed":
      case "ScheduledJobRecovered":
        dispatch({ type: "APPEND_JOB", payload: event.payload });
        break;
      default:
        break;
    }
  }, []);

  const handleReconnect = useCallback(() => {
    refetchRef.current();
  }, []);

  useRealtimeEvents({ onEvent: handleEvent, onReconnect: handleReconnect });

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Operations Center</h1>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Panel 1: Live Campaigns */}
        <section className="rounded-lg border bg-card p-4">
          <h2 className="text-lg font-semibold mb-3">Live Campaigns</h2>
          {state.liveCampaigns.length === 0 ? (
            <p className="text-muted-foreground text-sm">No campaigns executing</p>
          ) : (
            <ul className="space-y-2">
              {state.liveCampaigns.map((c, i) => (
                <li key={(c.campaign_id as string | undefined) ?? i} className="text-sm">
                  <span className="font-mono">{String(c.campaign_id ?? "")}</span>
                  {" — "}
                  {String(c.status ?? "")}
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* Panel 2: Task Progress */}
        <section className="rounded-lg border bg-card p-4">
          <h2 className="text-lg font-semibold mb-3">Task Progress</h2>
          {state.recentTasks.length === 0 ? (
            <p className="text-muted-foreground text-sm">No recent task activity</p>
          ) : (
            <ul className="space-y-1">
              {state.recentTasks.slice(0, 10).map((t, i) => (
                <li key={(t.task_id as string | undefined) ?? i} className="text-sm">
                  {String(t.tenant_id ?? "")} / {String(t.control_id ?? "")}
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* Panel 3: Critical Failures */}
        <section className="rounded-lg border border-destructive/30 bg-card p-4">
          <h2 className="text-lg font-semibold mb-3 text-destructive">Critical Failures</h2>
          {state.criticalFailures.length === 0 ? (
            <p className="text-muted-foreground text-sm">No failures</p>
          ) : (
            <ul className="space-y-1">
              {state.criticalFailures.slice(0, 10).map((f, i) => (
                <li key={(f.task_id as string | undefined) ?? i} className="text-sm text-destructive">
                  {String(f.control_id ?? "")}: {String(f.error ?? "unknown error")}
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* Panel 4: Scheduled Jobs */}
        <section className="rounded-lg border bg-card p-4">
          <h2 className="text-lg font-semibold mb-3">Scheduled Jobs</h2>
          {state.scheduledJobs.length === 0 ? (
            <p className="text-muted-foreground text-sm">No recent job activity</p>
          ) : (
            <ul className="space-y-1">
              {state.scheduledJobs.slice(0, 10).map((j, i) => (
                <li key={(j.job_id as string | undefined) ?? i} className="text-sm font-mono">
                  {String(j.job_id ?? "")} — {String(j.campaign_id ?? "")}
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      {/* Panel 5: Drift Feed */}
      <section className="rounded-lg border bg-card p-4">
        <h2 className="text-lg font-semibold mb-3">Drift Feed</h2>
        {state.driftFeed.length === 0 ? (
          <p className="text-muted-foreground text-sm">No drift notifications</p>
        ) : (
          <ul className="space-y-2">
            {state.driftFeed.map((d, i) => (
              <li key={(d.id as string | undefined) ?? i} className="text-sm">
                {String(d.tenant_name ?? d.tenant_id ?? "")}: {String(d.control_id ?? "")}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
