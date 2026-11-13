import { getApiBaseUrl, getSelectedTenantId, getToken } from "@/lib/auth";
import { ApiError, api } from "./client";
import { fetchFleetOverview } from "./msp";
import type {
  ArchivedReportResponse,
  AttestationResponse,
  AuditLog,
  ComplianceResult,
  ComplianceDashboardResponse,
  EligibilityResponse,
  EvidenceReport,
  ExecutiveSummary,
  FleetPostureResponse,
  RemediationAuditEvent,
  RemediationDecision,
  RemediationDecisionStats,
  RemediationPriorityItem,
  RemediationTimelineItem,
  RemediationHistoryItem,
  RiskFeedItem,
  AttackPathExecuteAllResponse,
  AttackPathRemediationPlan,
  AttackPathSummary,
  AttackPathStepExecutionResponse,
  PostureTrend,
  PostureTimelinePoint,
  OffboardingSession,
  ScanStatusResponse,
  DirectoryUser,
  UserTenantAccessItem,
  VerifyResponse,
  ExecuteRemediationResponse,
  BreakGlassCreateResponse,
  BreakGlassUsageEvent,
  LicenseFindingsResponse,
  LicenseScanResponse,
  LicenseSummary,
  ControlCapabilityMap,
  ControlStateResponse,
  SupportTicket,
  SupportTicketCreatePayload,
} from "@/types";
import type { ReviewSubmitPayload, ReviewSubmitResponse, WorkQueue, WorkflowDelta } from "@/types/work";
import type {
  RunStateChangePayload,
  WorkflowDefinition,
  WorkflowLibraryResponse,
  WorkflowRemediationSimulation,
  WorkflowReviewResponse,
  WorkflowRun,
} from "@/types/workflow";
import type { TimelineQueryParams, TimelineResponse } from "@/types/timeline";

export const login = (email: string, password: string) =>
  api.post<{ access_token: string }>("/api/auth/login", { email, password });

// Verified signup: creates an unverified account and emails a verification
// link. No session is issued until the email is verified (see /auth/verify-email).
// The legacy unverified /auth/signup endpoint has been removed (returns 410).
export const signup = (email: string, password: string, name: string) =>
  api.post<{ ok: boolean; verification_required: boolean }>("/auth/signup-password", {
    email,
    password,
    name,
  });

export const getMyTenants = () => api.get<UserTenantAccessItem[]>("/api/v1/tenants/my");

export interface SessionContext {
  mode: "SMB" | "MSP";
  tenant_id: string | null;
  role: string;
  is_preview: boolean;
}

export const getSessionContext = () =>
  api.get<SessionContext>("/api/v1/session/context", { omitTenantHeader: true });

export const deleteTenant = (tenantId: string) =>
  api.delete<{ success: boolean; message: string }>(`/api/v1/tenants/${encodeURIComponent(tenantId)}`, {
    confirmation: "DELETE",
  });

export const getFleetPosture = () => api.get<FleetPostureResponse>("/api/v1/fleet/posture");

export const getFleetOverview = () => fetchFleetOverview();

export const getRiskFeed = () => api.get<RiskFeedItem[]>("/api/v1/risk-feed");

export const getAttackPaths = (_tenantId?: string | null) =>
  api.get<AttackPathSummary>("/api/v1/attack-paths");

export const getAttackPathRemediationPlan = (pathId: string) =>
  api.get<AttackPathRemediationPlan>(`/api/v1/attack-paths/${encodeURIComponent(pathId)}/remediation`);

export const executeAttackPathStep = (pathId: string, controlId: string) =>
  api.post<AttackPathStepExecutionResponse>(
    `/api/v1/attack-paths/${encodeURIComponent(pathId)}/execute-step`,
    { control_id: controlId },
  );

export const executeAttackPathAll = (pathId: string) =>
  api.post<AttackPathExecuteAllResponse>(
    `/api/v1/attack-paths/${encodeURIComponent(pathId)}/execute-all`,
    {},
  );

export const getUsers = () => api.get<DirectoryUser[]>("/api/v1/users");

export const getUser = (userId: string) => api.get<DirectoryUser>(`/api/v1/users/${userId}`);

export const getBreakGlassEvents = () => api.get<BreakGlassUsageEvent[]>("/api/v1/break-glass/events");

export const createSupportTicket = (payload: SupportTicketCreatePayload) =>
  api.post<SupportTicket>("/api/v1/support/tickets", payload);

export const getMySupportTickets = () => api.get<SupportTicket[]>("/api/v1/support/tickets/me");

export const getSupportTicket = (ticketId: string) =>
  api.get<SupportTicket>(`/api/v1/support/tickets/${encodeURIComponent(ticketId)}`);

export const runLicenseScan = () => api.get<LicenseScanResponse>("/api/v1/license/scan");

export const getLicenseSummary = () => api.get<LicenseSummary>("/api/v1/license/summary");

export const getLicenseFindings = () => api.get<LicenseFindingsResponse>("/api/v1/license/findings");

export const downloadLicenseReport = () => downloadReportBlob("/api/v1/license/report");

export const getPostureTrend = () => api.get<PostureTrend>("/api/v1/posture/trend");

export const getPostureTimeline = () => api.get<PostureTimelinePoint[]>("/api/v1/posture/timeline");

export const getComplianceResults = () => api.get<ComplianceResult[]>("/api/v1/compliance/results");

export const getComplianceDashboard = (params?: {
  framework_id?: string;
  status?: string;
  search?: string;
}) => {
  const searchParams = new URLSearchParams();
  if (params?.framework_id) searchParams.append("framework_id", params.framework_id);
  if (params?.status) searchParams.append("status", params.status);
  if (params?.search) searchParams.append("search", params.search);
  const queryString = searchParams.toString();
  const path = queryString ? `/api/v1/compliance/dashboard?${queryString}` : "/api/v1/compliance/dashboard";
  return api.get<ComplianceDashboardResponse>(path);
};

export const getExecutiveSummary = () => api.get<ExecutiveSummary>("/api/v1/reports/executive-summary");

export const getReportAttestation = (reportId: number) =>
  api.get<AttestationResponse>(`/insurance/reports/${reportId}/attestation`);

export const getArchivedReportJson = () =>
  api.get<ArchivedReportResponse>("/insurance/evidence-report/pdf?archived=true");

export const getEvidenceReports = () =>
  api.get<Array<EvidenceReport & { id?: string | number }>>("/insurance/evidence-reports").then((reports) =>
    (Array.isArray(reports) ? reports : []).map((report) => ({
      ...report,
      report_id: String(report.report_id ?? report.id ?? ""),
    })),
  );

export const downloadEvidenceReportPdf = () => downloadReportBlob("/insurance/evidence-report/pdf");

export const downloadArchivedReportPdf = (reportPayloadId: number) =>
  downloadReportBlob(`/insurance/reports/${reportPayloadId}/pdf`);

export const getCyberInsurancePdf = () => downloadReportBlob("/api/v1/reports/cyber-insurance");

async function downloadReportBlob(path: string): Promise<Blob> {
  const token = getToken();
  const tenantId = getSelectedTenantId();

  const headers = new Headers();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  if (tenantId) {
    headers.set("X-Tenant-ID", tenantId);
  }

  const response = await fetch(`${getApiBaseUrl()}${path}`, {
    method: "GET",
    credentials: "include",
    headers,
  });

  if (!response.ok) {
    const text = await response.text().catch(() => response.statusText);
    let message = text || response.statusText;
    let errorCode: string | undefined;

    try {
      const parsed = JSON.parse(text) as {
        detail?: string | { message?: string; error?: string };
        message?: string;
        error?: string;
      };
      if (typeof parsed.detail === "string") {
        message = parsed.detail;
      } else if (parsed.detail?.message) {
        message = parsed.detail.message;
      } else if (typeof parsed.message === "string") {
        message = parsed.message;
      } else if (typeof parsed.error === "string") {
        message = parsed.error;
      }
      errorCode = typeof parsed.error === "string" ? parsed.error : undefined;
    } catch {
      // fall back to plain text
    }

    throw new ApiError(response.status, message || "Report request failed", errorCode);
  }

  return response.blob();
}

export const getRemediationStats = () =>
  api.get<RemediationDecisionStats>("/api/v1/remediation/decisions/stats");

export const getControlState = (controlId: string) =>
  api.get<ControlStateResponse>(`/api/v1/control/state?control_id=${encodeURIComponent(controlId)}`);

export const getControlCapabilities = async (): Promise<ControlCapabilityMap> => {
  const response = await api.get<unknown>("/api/v1/controls/capabilities");
  const nested = (response as { capabilities?: ControlCapabilityMap } | null)?.capabilities;

  if (nested && typeof nested === "object" && !Array.isArray(nested)) {
    return nested;
  }

  return response && typeof response === "object" && !Array.isArray(response)
    ? (response as ControlCapabilityMap)
    : {};
};

export const getRemediationStatsWindow = (window: "24h" | "7d" | "30d" | "custom", start?: string) => {
  const qs = start ? `?window=${window}&start=${start}` : `?window=${window}`;
  return api.get<RemediationDecisionStats>(`/api/v1/remediation/decisions/stats/window${qs}`);
};

export const getRemediationDecisions = () => api.get<RemediationDecision[]>("/api/v1/remediation/decisions");

export const getRemediationDecision = (decisionId: string | number) =>
  api.get<RemediationDecision>(`/api/v1/remediation/decisions/${decisionId}`);

export const getPriorityQueue = () =>
  api.get<RemediationPriorityItem[]>("/api/v1/remediation/priority-queue");

export const getRemediationTimeline = (limit = 100) =>
  api.get<RemediationTimelineItem[]>(`/api/v1/remediation-timeline?limit=${limit}`);

export const getRemediationHistory = () => api.get<RemediationHistoryItem[]>("/api/v1/remediation/history");

export const getDecisionByResult = (complianceResultId: string) =>
  api.get<RemediationDecision>(`/api/v1/remediation/decisions/by-result/${complianceResultId}`);

export const approveByResult = (complianceResultId: string, _tenantId?: string | null, approvedBy?: string) =>
  api.post<{ status: string; compliance_result_id: string; decision_id: string }>(
    `/api/v1/remediation/decisions/by-result/${complianceResultId}/approve`,
    approvedBy ? { approved_by: approvedBy } : undefined,
  );

export const acknowledgeComplianceResult = (complianceResultId: string) =>
  api.post<ComplianceResult>(`/api/v1/compliance/results/${complianceResultId}/acknowledge`);

export const getExecuteEligibility = (complianceResultId: string) =>
  api.get<EligibilityResponse>(`/remediation/${complianceResultId}/execute/eligibility`);

export const getRemediationPreview = (complianceResultId: string) =>
  api.get<{ changes: unknown[] }>(`/api/v1/remediation/${complianceResultId}/preview`);

export const executeRemediation = async (
  complianceResultId: string,
  selectedRolesOrTenantId?: string[] | string | null,
  tenantIdOrPayload?: string | null | Record<string, unknown>,
) => {
  const selectedRoles = Array.isArray(selectedRolesOrTenantId) ? selectedRolesOrTenantId : undefined;
  const explicitTenantId =
    typeof selectedRolesOrTenantId === "string"
      ? selectedRolesOrTenantId
      : typeof tenantIdOrPayload === "string"
        ? tenantIdOrPayload
        : null;
  const extraPayload =
    tenantIdOrPayload && typeof tenantIdOrPayload === "object" && !Array.isArray(tenantIdOrPayload)
      ? tenantIdOrPayload
      : {};
  const payload =
    selectedRoles !== undefined ? { ...extraPayload, selected_roles: selectedRoles } : extraPayload;

  console.log("Sending selected_roles:", selectedRoles ?? []);

  const headers = new Headers({
    "Content-Type": "application/json",
  });
  const token = getToken();
  const effectiveTenantId = explicitTenantId ?? getSelectedTenantId();

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  if (effectiveTenantId) {
    headers.set("X-Tenant-ID", effectiveTenantId);
  }

  const response = await fetch(
    `${getApiBaseUrl()}/api/v1/remediation/${complianceResultId}/execute?dry_run=false`,
    {
      method: "POST",
      credentials: "include",
      headers,
      body: JSON.stringify(payload),
    },
  );

  if (!response.ok) {
    const text = await response.text().catch(() => response.statusText);
    let message = text || response.statusText;
    let errorCode: string | undefined;
    try {
      const parsed = JSON.parse(text) as { detail?: string; message?: string; error?: string };
      if (typeof parsed.detail === "string") {
        message = parsed.detail;
      } else if (typeof parsed.message === "string") {
        message = parsed.message;
      }
      if (typeof parsed.error === "string") {
        errorCode = parsed.error;
      }
    } catch {
      // fall back to plain text
    }
    throw new ApiError(response.status, message, errorCode);
  }

  return response.json() as Promise<ExecuteRemediationResponse>;
};

export const createBreakGlassAccounts = (payload?: {
  dry_run?: boolean;
  approve?: boolean;
  approved_by?: string | null;
}) =>
  api.post<BreakGlassCreateResponse>(
    `/api/v1/remediation/break-glass/create${payload?.dry_run ? "?dry_run=true" : ""}`,
    payload?.dry_run
      ? { dry_run: true }
      : {
          approve: payload?.approve ?? true,
          approved_by: payload?.approved_by ?? undefined,
        },
  );

export const verifyRemediation = (complianceResultId: string) =>
  api.get<VerifyResponse>(`/remediation/${complianceResultId}/verify`);

export const getRollbackEligibility = (complianceResultId: string) =>
  api.get<EligibilityResponse>(`/remediation/${complianceResultId}/rollback/eligibility`);

export const rollbackRemediation = (
  complianceResultId: string,
  _tenantId?: string | null,
  reason?: string,
  requestedBy?: string,
) =>
  api.post<{ status: string; compliance_result_id: string }>(
    `/api/v1/remediation/${complianceResultId}/rollback`,
    { reason, requested_by: requestedBy },
  );

export const getRemediationAudit = (decisionId: string | number) =>
  api.get<RemediationAuditEvent[]>(`/api/v1/remediation/audit/${decisionId}`);

export const getAuditLogs = () => api.get<AuditLog[]>("/audit/logs");

export const runIdentityScan = (_tenantId?: string | null) =>
  api.post<{ status: string; message: string; tenant_id: string }>("/api/v1/scan/identity");

export const startTenantScan = (tenantId: string) =>
  api.post<{ status: string; message: string; tenant_id: string }>(`/api/v1/scan/${tenantId}`);

export const startAllTenantScans = () =>
  api.post<{
    status: string;
    message: string;
    started_tenant_ids: string[];
    skipped: { tenant_id: string; reason: string }[];
  }>("/api/v1/scan/all");

export const getScanStatus = () => api.get<ScanStatusResponse>("/api/v1/scan/status");

// organization_id is intentionally NOT sent: the backend derives it from the
// authenticated tenant to prevent cross-organization baseline writes (IDOR).
export const applyBaseline = (payload: { baseline_name: string; controls: string[] }) =>
  api.post<{
    status: string;
    organization_id: string;
    baseline_name: string;
    controls: string[];
    tenant_count: number;
    tenant_ids: string[];
    message: string;
  }>("/api/v1/baseline/apply", payload);

export type BaselineTemplate = {
  id: string;
  baseline_name: string;
  controls: string[];
};

export const getBaselineTemplates = () => api.get<BaselineTemplate[]>("/api/v1/baseline/templates");

export const createBaselineTemplate = (baselineName: string, controls: string[]) =>
  api.post<BaselineTemplate>("/api/v1/baseline/templates", {
    baseline_name: baselineName,
    controls,
  });

export const createMspBaseline = (_organizationId: string, baselineName: string, controls: string[]) =>
  createBaselineTemplate(baselineName, controls);

export const startGuidedOffboarding = (controlId: string, resourceId: string) =>
  api.post<Pick<OffboardingSession, "session_id" | "steps" | "status">>("/api/v1/offboarding/start", {
    control_id: controlId,
    resource_id: resourceId,
  });

export const getOffboardingSession = (sessionId: string) =>
  api.get<OffboardingSession>(`/api/v1/offboarding/${sessionId}`);

export const executeOffboardingStep = (sessionId: string, stepId: string) =>
  api.post<Pick<OffboardingSession, "session_id" | "steps" | "status" | "error" | "retryable">>(
    `/api/v1/offboarding/${sessionId}/step`,
    {
      step_id: stepId,
    },
  );

export const startUserOffboarding = (userId: string) =>
  api.post<OffboardingSession>(`/api/v1/users/${userId}/offboard/start`);

export const getUserOffboardingSession = (userId: string) =>
  api.get<OffboardingSession>(`/api/v1/users/${userId}/offboard/session`);

export const executeUserOffboardingStep = (userId: string, stepId: string) =>
  api.post<Pick<OffboardingSession, "session_id" | "steps" | "status" | "error" | "retryable">>(
    `/api/v1/users/${userId}/offboard/step`,
    {
      step_id: stepId,
    },
  );

export const restartUserOffboarding = (userId: string) =>
  api.post<
    Pick<
      OffboardingSession,
      "session_id" | "steps" | "status" | "current_step" | "step_states" | "error" | "retryable"
    >
  >(`/api/v1/users/${userId}/offboard/restart`);

export const rollbackUserOffboarding = (userId: string) =>
  api.post<{
    status: string;
    session_id: string;
    resource_id: string;
    user_enabled: boolean;
    roles_restored: string[];
    message?: string;
    roles_message?: string;
  }>(`/api/v1/users/${userId}/offboarding/rollback`);

export const refreshOverprivilegedRoles = (complianceResultId: string) =>
  api.post<ComplianceResult>(`/api/v1/compliance/results/${complianceResultId}/refresh-roles`);

export type SimulationRunResponse = {
  status: string;
  risk_level: string;
  blocked_users: number;
  mfa_required_users: number;
  unaffected_users: number;
  impacted_users: number;
  impacted_admins: number;
  conflicts: Array<{
    type: string;
    policy_ids?: Array<string | null>;
    users?: string[];
    grant_controls?: Array<{ left: string; right: string }>;
  }>;
  impact: {
    total_users: number;
    admin_users: number;
    global_admins: number;
    user_ids?: string[];
    admin_user_ids?: string[];
    global_admin_user_ids?: string[];
  };
};

export const runSimulation = (payload: {
  tenant_snapshot: Record<string, unknown>;
  proposed_change: Record<string, unknown>;
  role_mapping: Record<string, string[]>;
}) => api.post<SimulationRunResponse>("/api/v1/simulations/run", payload);

// ─── Work queue (Sprint 1) ───────────────────────────────────────────────────
// Read-only. The tenant is resolved server-side from the session; the
// X-Tenant-ID header added by the client is only a selector.

export const getWorkQueue = () => api.get<WorkQueue>("/api/v1/work");

// ─── Review memory (Sprint 2) ────────────────────────────────────────────────
// Writes the technician's decision for a compliance result. The tenant is
// resolved server-side from the session, not from this payload.

export const submitReview = (payload: ReviewSubmitPayload) =>
  api.post<ReviewSubmitResponse>("/api/v1/work/review", payload);

export const getWorkflowDelta = (workflowId: string) =>
  api.get<WorkflowDelta>(`/api/v1/work/${encodeURIComponent(workflowId)}/delta`);

// ─── Workflow library (Sprint 3) ─────────────────────────────────────────────
// Informational catalogue of workflow types. Tenant-neutral: describes what
// the platform can run, not any tenant's outstanding work.

export const getWorkflowLibrary = () => api.get<WorkflowLibraryResponse>("/api/v1/workflows");

export const getWorkflowDefinition = (id: string) =>
  api.get<WorkflowDefinition>(`/api/v1/workflows/${encodeURIComponent(id)}`);

// ─── Workflow runtime (Sprint 4) ─────────────────────────────────────────────
// Idempotent: creating a run for a definition that already has an active run
// returns the existing one instead of a second run.

export const createWorkflowRun = (definitionKey: string) =>
  api.post<WorkflowRun>(`/api/v1/workflows/${encodeURIComponent(definitionKey)}/runs`);

export const getWorkflowRun = (runId: string) =>
  api.get<WorkflowRun>(`/api/v1/workflows/runs/${encodeURIComponent(runId)}`);

export const getActiveRuns = () => api.get<{ runs: WorkflowRun[] }>("/api/v1/workflows/runs/active");

export const patchRunState = (runId: string, payload: RunStateChangePayload) =>
  api.patch<WorkflowRun>(`/api/v1/workflows/runs/${encodeURIComponent(runId)}/state`, payload);

// ─── Client timeline (Sprint 3) ──────────────────────────────────────────────
// Read-only, merged, chronological history for a tenant. `since`/`until` are
// ISO datetimes and MUST be URL-encoded — an unencoded "+00:00" offset decodes
// as a space server-side and 422s. URLSearchParams handles this correctly.

// OAuth Review's dedicated endpoints were retired in Wave 2. It is served by
// the generic workflow review surface above, under the key "oauth-review".

export const getClientTimeline = (tenantId: string, params?: TimelineQueryParams) => {
  const searchParams = new URLSearchParams();
  if (params?.limit != null) searchParams.append("limit", String(params.limit));
  if (params?.cursor) searchParams.append("cursor", params.cursor);
  if (params?.workflow_id) searchParams.append("workflow_id", params.workflow_id);
  if (params?.event_types) {
    for (const eventType of params.event_types) {
      searchParams.append("event_types", eventType);
    }
  }
  if (params?.since) searchParams.append("since", params.since);
  if (params?.until) searchParams.append("until", params.until);

  const queryString = searchParams.toString();
  const path = `/api/v1/clients/${encodeURIComponent(tenantId)}/timeline${
    queryString ? `?${queryString}` : ""
  }`;
  return api.get<TimelineResponse>(path);
};

// ─── Generic workflow review (Wave 2) ────────────────────────────────────────
// One surface for every workflow. The tenant is resolved server-side from the
// session; resource_id is never trusted for tenant scoping — the backend
// re-projects and re-verifies ownership on every call.

export const getWorkflowReview = (workflowKey: string) =>
  api.get<WorkflowReviewResponse>(`/api/v1/workflows/${encodeURIComponent(workflowKey)}/review`);

export const submitWorkflowDecision = (
  workflowKey: string,
  payload: {
    control_id: string;
    resource_id: string;
    decision: string;
    reason?: string;
  },
) =>
  api.post<WorkflowReviewResponse>(
    `/api/v1/workflows/${encodeURIComponent(workflowKey)}/review/decisions`,
    payload,
  );

export const simulateWorkflowRemediation = (
  workflowKey: string,
  payload: { control_id: string; resource_ids: string[] },
) =>
  api.post<WorkflowRemediationSimulation>(
    `/api/v1/workflows/${encodeURIComponent(workflowKey)}/review/remediate/simulate`,
    payload,
  );

export const executeWorkflowRemediation = (
  workflowKey: string,
  payload: {
    control_id: string;
    resource_ids: string[];
    confirmed: boolean;
    reason?: string;
  },
) =>
  api.post<{ selected_resource_ids: string[]; review: WorkflowReviewResponse }>(
    `/api/v1/workflows/${encodeURIComponent(workflowKey)}/review/remediate`,
    payload,
  );

export const completeWorkflowReview = (workflowKey: string) =>
  api.post<WorkflowReviewResponse>(`/api/v1/workflows/${encodeURIComponent(workflowKey)}/review/complete`);

export const getWorkflowReviewReport = (workflowKey: string) =>
  api.get<Record<string, unknown>>(`/api/v1/workflows/${encodeURIComponent(workflowKey)}/review/report`);
