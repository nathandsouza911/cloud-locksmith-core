"use client";

import { useCallback, useEffect, useState } from "react";

import { useAuth } from "@/lib/auth-context";
import * as ep from "./endpoints";
import * as campaignApi from "./campaigns";
import type { TimelineQueryParams } from "@/types/timeline";

interface QueryState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  refetch: () => void;
}

export function useQuery<T>(
  fetcher: () => Promise<T>,
  deps: unknown[] = [],
  options?: { requireTenant?: boolean },
): QueryState<T> {
  const { loading: authLoading, authed, tenantId } = useAuth();
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const requireTenant = options?.requireTenant ?? true;

  const run = useCallback(async () => {
    if (authLoading || !authed) return;
    if (requireTenant && !tenantId) {
      setData(null);
      setError("Select a tenant to continue");
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const result = await fetcher();
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [authLoading, authed, tenantId, requireTenant, ...deps]);

  useEffect(() => {
    if (authLoading) return;
    if (!authed) {
      setData(null);
      setError(null);
      setLoading(false);
      return;
    }
    if (requireTenant && !tenantId) {
      setData(null);
      setError("Select a tenant to continue");
      setLoading(false);
      return;
    }
    run();
  }, [authLoading, authed, tenantId, requireTenant, run]);

  return { data, loading, error, refetch: run };
}

export const useFleetPosture = () => useQuery(() => ep.getFleetPosture(), [], { requireTenant: false });

export const useFleetOverview = () => useQuery(() => ep.getFleetOverview(), [], { requireTenant: false });

export const useRiskFeed = (_tenantId?: string | null) =>
  useQuery(() => ep.getRiskFeed(), [], { requireTenant: true });

export const useAttackPaths = (tenantId?: string | null) =>
  useQuery(
    () => {
      if (!tenantId) return Promise.reject(new Error("No tenant selected"));
      return ep.getAttackPaths(tenantId);
    },
    [tenantId],
    { requireTenant: true },
  );

export const useAttackPathRemediationPlan = (pathId?: string | null) =>
  useQuery(
    () => {
      if (!pathId) return Promise.reject(new Error("No attack path selected"));
      return ep.getAttackPathRemediationPlan(pathId);
    },
    [pathId],
    { requireTenant: true },
  );

export const useUsers = (tenantId?: string | null) =>
  useQuery(() => ep.getUsers(), [tenantId], { requireTenant: true });

export const useUser = (userId?: string | null) =>
  useQuery(
    () => {
      if (!userId) return Promise.reject(new Error("No user selected"));
      return ep.getUser(userId);
    },
    [userId],
    { requireTenant: true },
  );

export const useBreakGlassEvents = (tenantId?: string | null) =>
  useQuery(() => ep.getBreakGlassEvents(), [tenantId], { requireTenant: true });

export const useSupportTickets = (_tenantId?: string | null) =>
  useQuery(() => ep.getMySupportTickets(), [], { requireTenant: true });

export const useSupportTicket = (ticketId?: string | null, _tenantId?: string | null) =>
  useQuery(
    () => {
      if (!ticketId) return Promise.reject(new Error("No ticket selected"));
      return ep.getSupportTicket(ticketId);
    },
    [ticketId],
    { requireTenant: true },
  );

export const useLicenseSummary = (_tenantId?: string | null) =>
  useQuery(() => ep.getLicenseSummary(), [], { requireTenant: true });

export const useLicenseFindings = (_tenantId?: string | null) =>
  useQuery(() => ep.getLicenseFindings(), [], { requireTenant: true });

export const useBaselineTemplates = () =>
  useQuery(() => ep.getBaselineTemplates(), [], { requireTenant: true });

export const useRemediationTimeline = (limit = 100, _tenantId?: string | null) =>
  useQuery(() => ep.getRemediationTimeline(limit), [limit], { requireTenant: true });

export const useRemediationHistory = () =>
  useQuery(() => ep.getRemediationHistory(), [], { requireTenant: true });

export const usePostureTrend = (tenantId?: string | null) =>
  useQuery(
    () => {
      if (!tenantId) return Promise.reject(new Error("No tenant selected"));
      return ep.getPostureTrend();
    },
    [tenantId],
    { requireTenant: true },
  );

export const usePostureTimeline = (tenantId?: string | null) =>
  useQuery(
    () => {
      if (!tenantId) return Promise.reject(new Error("No tenant selected"));
      return ep.getPostureTimeline();
    },
    [tenantId],
    { requireTenant: true },
  );

export const useComplianceResults = (tenantId?: string | null) =>
  useQuery(
    () => {
      if (!tenantId) return Promise.reject(new Error("No tenant selected"));
      return ep.getComplianceResults();
    },
    [tenantId],
    { requireTenant: true },
  );

export const useControlCapabilities = (tenantId?: string | null) =>
  useQuery(
    () => {
      if (!tenantId) return Promise.reject(new Error("No tenant selected"));
      return ep.getControlCapabilities();
    },
    [tenantId],
    { requireTenant: true },
  );

export const useRemediationStats = (_tenantId?: string | null) =>
  useQuery(() => ep.getRemediationStats(), [], { requireTenant: true });

export const useRemediationStatsWindow = (window: "24h" | "7d" | "30d" | "custom") =>
  useQuery(() => ep.getRemediationStatsWindow(window), [window], { requireTenant: true });

export const useRemediationDecisions = (_tenantId?: string | null) =>
  useQuery(() => ep.getRemediationDecisions(), [], { requireTenant: true });

export const usePriorityQueue = (_tenantId?: string | null) =>
  useQuery(() => ep.getPriorityQueue(), [], { requireTenant: true });

export const useExecutiveSummary = () =>
  useQuery(() => ep.getExecutiveSummary(), [], { requireTenant: true });

export const useEvidenceReports = () => useQuery(() => ep.getEvidenceReports(), [], { requireTenant: true });

export const useReportAttestation = (reportId: number | null) =>
  useQuery(
    () => {
      if (!reportId || isNaN(reportId)) return Promise.reject(new Error("Invalid report ID"));
      return ep.getReportAttestation(reportId);
    },
    [reportId],
    { requireTenant: true },
  );

export const useArchivedReport = () =>
  useQuery(() => ep.getArchivedReportJson(), [], { requireTenant: true });

export const useAuditLogs = () => useQuery(() => ep.getAuditLogs(), [], { requireTenant: true });

export function useComplianceDashboard(params?: { framework_id?: string; status?: string; search?: string }) {
  return useQuery(
    () => ep.getComplianceDashboard(params),
    [params?.framework_id, params?.status, params?.search],
  );
}

export function useSimulation() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ep.SimulationRunResponse | null>(null);

  const runSimulation = useCallback(
    async (payload: {
      tenant_snapshot: Record<string, unknown>;
      proposed_change: Record<string, unknown>;
      role_mapping: Record<string, string[]>;
    }) => {
      setLoading(true);
      try {
        const response = await ep.runSimulation(payload);
        setResult(response);
        return response;
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  return {
    runSimulation,
    loading,
    result,
  };
}

// ── Fleet campaigns ───────────────────────────────────────────────────────────

export const useCampaigns = () => useQuery(() => campaignApi.listCampaigns(), [], { requireTenant: false });

export const useCampaign = (campaignId: string | null) =>
  useQuery(
    () => {
      if (!campaignId) return Promise.reject(new Error("No campaign ID"));
      return campaignApi.getCampaign(campaignId);
    },
    [campaignId],
    { requireTenant: false },
  );

export const useCampaignPreview = (controlIds: string[], tenantIds: string[]) =>
  useQuery(
    () => {
      if (controlIds.length === 0 || tenantIds.length === 0) {
        return Promise.resolve({ items: [] });
      }
      return campaignApi.getCampaignPreview(controlIds, tenantIds);
    },
    [controlIds.join(","), tenantIds.join(",")],
    { requireTenant: false },
  );

// ─── Work queue (Sprint 1) ───────────────────────────────────────────────────

export const useWorkQueue = () => useQuery(() => ep.getWorkQueue(), [], { requireTenant: true });

export const useWorkflowDelta = (workflowId?: string | null) =>
  useQuery(
    () => {
      if (!workflowId) return Promise.reject(new Error("No workflow selected"));
      return ep.getWorkflowDelta(workflowId);
    },
    [workflowId],
    { requireTenant: true },
  );

// ─── Workflow library (Sprint 3) ─────────────────────────────────────────────
// Tenant-neutral: the catalogue of workflow types is the same regardless of
// which tenant is selected, so it does not require a tenant to be resolved.

export const useWorkflowLibrary = () => useQuery(() => ep.getWorkflowLibrary(), [], { requireTenant: false });

export const useWorkflowDefinition = (workflowId?: string | null) =>
  useQuery(
    () => {
      if (!workflowId) return Promise.reject(new Error("No workflow selected"));
      return ep.getWorkflowDefinition(workflowId);
    },
    [workflowId],
    { requireTenant: false },
  );

// ─── Workflow runtime (Sprint 4) ─────────────────────────────────────────────

export const useActiveRuns = () => useQuery(() => ep.getActiveRuns(), [], { requireTenant: true });

export const useWorkflowRun = (runId?: string | null) =>
  useQuery(
    () => {
      if (!runId) return Promise.reject(new Error("No run selected"));
      return ep.getWorkflowRun(runId);
    },
    [runId],
    { requireTenant: true },
  );

// ─── Client timeline (Sprint 3) ──────────────────────────────────────────────

export const useClientTimeline = (tenantId?: string | null, params?: TimelineQueryParams) =>
  useQuery(
    () => {
      if (!tenantId) return Promise.reject(new Error("No tenant selected"));
      return ep.getClientTimeline(tenantId, params);
    },
    [
      tenantId,
      params?.limit,
      params?.cursor,
      params?.workflow_id,
      params?.since,
      params?.until,
      (params?.event_types ?? []).join(","),
    ],
    { requireTenant: true },
  );

// ─── Generic workflow review (Wave 2) ────────────────────────────────────────

export const useWorkflowReview = (workflowKey?: string | null) =>
  useQuery(
    () => {
      if (!workflowKey) return Promise.reject(new Error("No workflow selected"));
      return ep.getWorkflowReview(workflowKey);
    },
    [workflowKey],
    { requireTenant: true },
  );
