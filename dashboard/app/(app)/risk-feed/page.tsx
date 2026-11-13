"use client";

import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { AlertTriangle, CheckCircle, Flame, Play, RefreshCw, X, Zap } from "lucide-react";

import {
  Button,
  Card,
  ConfirmModal,
  EmptyState,
  ErrorState,
  FilterSelect,
  PageHeader,
  SeverityBadge,
  SimulationPanel,
  StatusBadge,
  TableSkeleton,
} from "@/components/ui";
import * as ep from "@/lib/api/endpoints";
import { ApiError } from "@/lib/api/client";
import {
  useAttackPaths,
  useComplianceResults,
  useControlCapabilities,
  useFleetPosture,
  useRiskFeed,
  useSimulation,
  useUsers,
} from "@/lib/api/hooks";
import { useAuth } from "@/lib/auth-context";
import { startMicrosoftOAuth } from "@/lib/auth";
import {
  capabilityModeClasses,
  capabilityModeLabel,
  capabilityTooltip,
  resolveControlCapabilityWithFallback,
} from "@/lib/control-capabilities";
import { requireTenantIdentitySnapshot } from "@/lib/simulation";
import { FloatingNotice } from "@/components/ui/FloatingNotice";
import { canSimulateFix } from "@/lib/simulate-fix-controls";
import type {
  ComplianceResult,
  ControlCapabilityDecision,
  DirectoryUser,
  RiskFeedItem,
  Severity,
} from "@/types";

const SEV_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEV_COLOR: Record<string, string> = {
  CRITICAL: "#f87171",
  HIGH: "#fb923c",
  MEDIUM: "#facc15",
  LOW: "#60a5fa",
  INFO: "#9ca3af",
};

const DIRECT_REMEDIATION_CONTROLS = new Set([
  "IDENTITY_MFA_NOT_ENFORCED",
  "IDENTITY_LEGACY_AUTH_ALLOWED",
  "IDENTITY_USER_CONSENT_ALLOWED",
  "IDENTITY_PASSWORD_PROTECTION_WEAK",
  "IDENTITY_BREAK_GLASS_ACCOUNT",
]);
const OVERPRIVILEGED_ROLE_CONTROL_IDS = new Set([
  "IDENTITY_OVERPRIVILEGED_ADMIN",
  "IDENTITY_OVERPRIVILEGED_USER",
]);
const MANUAL_REVIEW_ONLY_CONTROLS = new Set(["IDENTITY_ADMIN_COUNT_EXCESS"]);

// Keep in sync with CA_CONTROL_TYPES in cloud-locksmith-backend/app/services/license_check_service.py
const CA_CONTROL_IDS = new Set([
  "CA_MFA_ALL_USERS",
  "CA_MFA_ADMINS",
  "CA_GUEST_MFA",
  "CA_LEGACY_AUTH_BLOCK",
  "CA_DEVICE_CODE_FLOW_BLOCK",
  "CA_AUTHENTICATION_TRANSFER_BLOCK",
  "CA_BREAK_GLASS_EXCLUSION",
]);

function isCaControl(controlId: string): boolean {
  return CA_CONTROL_IDS.has(controlId);
}

type RoleRecord = Record<string, unknown>;
type RoleOption = { value: string; label: string };
type BreakGlassCredential = {
  username: string;
  user_principal_name?: string;
  display_name?: string;
  password: string;
  password_revealed?: boolean;
};

function getRoles(
  source?: {
    available_roles?: Array<Record<string, unknown>>;
    current_roles?: Array<Record<string, unknown>>;
    evidence?: Record<string, unknown> | string;
  } | null,
): RoleRecord[] {
  const evidence = source?.evidence;
  const evidenceRecord =
    evidence && typeof evidence === "object" && !Array.isArray(evidence)
      ? (evidence as Record<string, unknown>)
      : {};

  const availableRoles = Array.isArray(source?.available_roles)
    ? source.available_roles
    : Array.isArray(evidenceRecord.available_roles)
      ? evidenceRecord.available_roles
      : [];
  const currentRoles = Array.isArray(source?.current_roles)
    ? source.current_roles
    : Array.isArray(evidenceRecord.current_roles)
      ? evidenceRecord.current_roles
      : Array.isArray(evidenceRecord.roles)
        ? evidenceRecord.roles
        : [];

  return availableRoles.length ? availableRoles : currentRoles;
}

function mapRoleOptions(roleSource: Array<unknown>): RoleOption[] {
  return roleSource
    .map((role) => {
      if (typeof role === "string") return { value: role, label: role };
      if (!role || typeof role !== "object") return null;

      const roleRecord = role as Record<string, unknown>;
      const value = typeof roleRecord.id === "string" ? roleRecord.id : null;
      if (!value) return null;

      const label =
        typeof roleRecord.role_name === "string"
          ? roleRecord.role_name
          : typeof roleRecord.displayName === "string"
            ? roleRecord.displayName
            : value;

      return { value, label };
    })
    .filter((role): role is RoleOption => Boolean(role));
}

function normalizeExecuteFailureMessage(status?: string, reason?: string, message?: string): string {
  if (reason === "NO_ROLES_SELECTED") return "Execution failed: no roles selected";
  if (message) return message;
  if (reason) return `Execution failed: ${reason}`;
  if (status) return `Execution failed: ${status}`;
  return "Execution failed";
}

function relTime(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function getEvidenceRecord(result?: ComplianceResult | null): Record<string, unknown> {
  const evidence = result?.evidence;
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) return {};
  return evidence as Record<string, unknown>;
}

function formatBlockReason(reason?: string | null): string | null {
  if (!reason) return null;

  const labels: Record<string, string> = {
    PRIVILEGED_USER: "Privileged User",
    POLICY_RESTRICTION: "Policy Restriction",
    BREAK_GLASS_PROTECTION: "Break-Glass Protection",
    INSUFFICIENT_PERMISSIONS: "Permission Required",
    INSUFFICIENT_SCOPE: "Permission Required",
    INVALID_PAYLOAD: "Configuration Error",
    RESOURCE_NOT_FOUND: "Resource Not Found",
    UNKNOWN: "Unknown",
  };

  return labels[reason] ?? reason.replaceAll("_", " ");
}

function formatImpactScore(impactScore?: number): string | null {
  if (typeof impactScore !== "number" || !Number.isFinite(impactScore) || impactScore <= 0) return null;
  const rounded = impactScore % 1 === 0 ? impactScore.toFixed(0) : impactScore.toFixed(2);
  return `+${rounded}`;
}

function formatResourceTypeLabel(resourceType?: string | null): string {
  if (!resourceType) return "Resource";
  return resourceType
    .toLowerCase()
    .split("_")
    .filter(Boolean)
    .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
    .join(" ");
}

function formatControlLabel(controlId: string): string {
  return controlId
    .replace(/^IDENTITY_/, "")
    .split("_")
    .filter(Boolean)
    .map((segment) => segment.charAt(0) + segment.slice(1).toLowerCase())
    .join(" ");
}

interface CapabilityActionState {
  buttonLabel: string;
  buttonDisabled: boolean;
  buttonTooltip?: string;
  note?: string;
  requiresConfirmation: boolean;
}

function withImpactLabel(label: string, impactLabel?: string | null): string {
  return impactLabel ? `${label} (${impactLabel})` : label;
}

function buildCapabilityActionState(
  controlId: string,
  capability: ControlCapabilityDecision,
  impactLabel?: string | null,
): CapabilityActionState {
  if (controlId === "IDENTITY_USER_NO_MFA" && capability.mode !== "auto") {
    return {
      buttonLabel: "Manual Action Required",
      buttonDisabled: true,
      buttonTooltip: capabilityTooltip(capability.mode, capability.notes),
      note: capability.notes || "This action requires manual follow-up.",
      requiresConfirmation: false,
    };
  }

  if (capability.mode === "auto") {
    return {
      buttonLabel: withImpactLabel("Fix Now", impactLabel),
      buttonDisabled: false,
      requiresConfirmation: false,
    };
  }

  if (capability.mode === "manual") {
    if (isCaControl(controlId) && capability.ca_license_available === false) {
      return {
        buttonLabel: "License Required",
        buttonDisabled: true,
        buttonTooltip:
          capability.license_note ??
          "Conditional Access requires Microsoft Entra ID P1/P2 or equivalent licensing.",
        note: "Microsoft Entra ID P1/P2 required.",
        requiresConfirmation: false,
      };
    }

    const baseLabel = controlId === "IDENTITY_ADMIN_NO_MFA" ? "Fix: Remove Admin Access" : "Review & Fix";
    return {
      buttonLabel: withImpactLabel(baseLabel, impactLabel),
      buttonDisabled: false,
      buttonTooltip: capabilityTooltip(capability.mode, capability.notes),
      note: capability.notes || "Review this action before applying it.",
      requiresConfirmation: true,
    };
  }

  return {
    buttonLabel:
      controlId === "TENANT_CONDITIONAL_ACCESS_POLICY"
        ? "Not supported on Google Workspace"
        : "Not Available",
    buttonDisabled: true,
    buttonTooltip: capabilityTooltip(capability.mode, capability.notes),
    note: capability.notes || "This action is not supported for your provider.",
    requiresConfirmation: false,
  };
}

async function buildSimulationPayload(
  risk: RiskFeedItem,
  complianceResult: ComplianceResult | null | undefined,
  tenantUsers: DirectoryUser[] | null,
  usersError: string | null,
) {
  const tenantSnapshot = requireTenantIdentitySnapshot(tenantUsers, usersError);

  const evidenceRecord = getEvidenceRecord(complianceResult ?? null);
  const roleSource = getRoles({
    available_roles: complianceResult?.available_roles ?? risk.available_roles,
    current_roles: complianceResult?.current_roles ?? risk.current_roles,
    evidence: complianceResult?.evidence,
  });
  const mappedRoles = mapRoleOptions(roleSource);

  return {
    tenant_snapshot: {
      ...tenantSnapshot,
    },
    proposed_change: {
      id: `sim-${risk.compliance_result_id}`,
      conditions: {
        users: {
          includeUsers: risk.resource_type === "USER" ? [risk.resource_id] : [],
          includeRoles: mappedRoles.map((role) => role.label),
        },
      },
      grantControls: {
        builtInControls: ["mfa"],
      },
      state: "enabled",
      control_id: risk.control_id,
      resource_id: risk.resource_id,
      resource_name: risk.resource_name,
      evidence: evidenceRecord,
    },
    role_mapping: tenantSnapshot.roles,
  };
}

export default function RiskFeedPage() {
  const [severityFilter, setSeverityFilter] = useState("");
  const [loadingId, setLoadingId] = useState<string | null>(null);
  const [activeSimulationId, setActiveSimulationId] = useState<string | null>(null);
  const [simulationError, setSimulationError] = useState<string | null>(null);
  const [selectedRolesByResultId, setSelectedRolesByResultId] = useState<Record<string, string[]>>({});
  const [statusOverrides, setStatusOverrides] = useState<
    Record<string, { approval_status: "pending" | "approved"; execution_status: "pending" | "executed" }>
  >({});
  const [toast, setToast] = useState<string | null>(null);
  const [breakGlassCredentials, setBreakGlassCredentials] = useState<BreakGlassCredential[] | null>(null);
  const [pendingAction, setPendingAction] = useState<{
    kind: "approve" | "execute";
    complianceResultId: string;
    controlId: string;
    isTenantLevel: boolean;
    title: string;
    message: string;
    confirmLabel: string;
    variant: "danger" | "warning";
    requireTypedConfirm: boolean;
    approveBeforeExecute?: boolean;
  } | null>(null);

  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const { tenantId: activeTenantId, setActiveTenantId, isPreviewMode } = useAuth();
  const simulation = useSimulation();
  const selectedRolesByResultIdRef = useRef<Record<string, string[]>>({});

  const selectedTenantId = searchParams.get("tenant_id");
  const effectiveTenantId = selectedTenantId ?? activeTenantId;

  const riskQuery = useRiskFeed(effectiveTenantId);
  const fleetQuery = useFleetPosture();
  const complianceQuery = useComplianceResults(effectiveTenantId);
  const capabilitiesQuery = useControlCapabilities(effectiveTenantId);
  const attackPathsQuery = useAttackPaths(effectiveTenantId);
  const usersQuery = useUsers(effectiveTenantId);

  const feed = riskQuery.data ?? [];
  const isLoading = riskQuery.loading || capabilitiesQuery.loading;

  useEffect(() => {
    selectedRolesByResultIdRef.current = selectedRolesByResultId;
  }, [selectedRolesByResultId]);

  useEffect(() => {
    if (!toast) return undefined;
    const timeout = window.setTimeout(() => setToast(null), 2500);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  useEffect(() => {
    if (!capabilitiesQuery.error) return;
    console.error("Failed to load control capabilities", capabilitiesQuery.error);
  }, [capabilitiesQuery.error]);

  const rows = useMemo(
    () =>
      feed.map((item) => ({
        ...item,
        ...(statusOverrides[item.compliance_result_id] ?? {}),
      })),
    [feed, statusOverrides],
  );

  const tenantOptions = useMemo(
    () =>
      (fleetQuery.data?.tenants ?? []).map((tenant) => ({
        label: tenant.tenant_name,
        value: tenant.tenant_id,
      })),
    [fleetQuery.data],
  );

  const attackPathControlFilter = useMemo(() => {
    const raw = searchParams.get("controls") ?? "";
    return raw
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
  }, [searchParams]);

  const attackPathControlSet = useMemo(() => new Set(attackPathControlFilter), [attackPathControlFilter]);

  const criticalAttackPathControls = useMemo(() => {
    const direct = attackPathsQuery.data?.critical_controls ?? [];
    if (direct.length > 0) return new Set(direct);

    return new Set(
      (attackPathsQuery.data?.paths ?? [])
        .filter((path) => path.severity === "CRITICAL")
        .flatMap((path) => path.controls_triggered),
    );
  }, [attackPathsQuery.data]);

  const filtered = useMemo(
    () =>
      rows.filter((row) => {
        if (severityFilter && row.severity !== severityFilter) return false;
        if (attackPathControlSet.size > 0 && !attackPathControlSet.has(row.control_id)) return false;
        return true;
      }),
    [rows, severityFilter, attackPathControlSet],
  );

  async function handleSimulateFix(risk: RiskFeedItem, complianceResult?: ComplianceResult | null) {
    setSimulationError(null);
    setActiveSimulationId(risk.compliance_result_id);

    try {
      const payload = await buildSimulationPayload(risk, complianceResult, usersQuery.data, usersQuery.error);
      await simulation.runSimulation(payload);
    } catch (error) {
      setSimulationError(error instanceof Error ? error.message : "Simulation failed");
    }
  }

  const complianceById = useMemo(
    () => new Map((complianceQuery.data ?? []).map((result) => [String(result.id), result])),
    [complianceQuery.data],
  );

  useEffect(() => {
    const complianceResults = complianceQuery.data;
    if (!complianceResults?.length) return;

    setSelectedRolesByResultId((current) => {
      const next = { ...current };

      for (const result of complianceResults) {
        if (!OVERPRIVILEGED_ROLE_CONTROL_IDS.has(result.control_id)) continue;
        const resultId = String(result.id);
        if (!next[resultId]) {
          next[resultId] = [];
        }
      }

      return next;
    });
  }, [complianceQuery.data]);

  function setSelectedRole(complianceResultId: string, roleId: string) {
    setSelectedRolesByResultId((current) => {
      const next = {
        ...current,
        [complianceResultId]: roleId ? [roleId] : [],
      };

      selectedRolesByResultIdRef.current = next;
      return next;
    });
  }

  const sevCounts = SEV_ORDER.map((severity) => ({
    severity,
    count: rows.filter((row) => row.severity === severity).length,
  })).filter((item) => item.count > 0);

  const critical = rows.filter((row) => row.severity === "CRITICAL").length;
  const high = rows.filter((row) => row.severity === "HIGH").length;

  function handleTenantSwitch(nextTenantId: string) {
    const params = new URLSearchParams(searchParams.toString());
    if (nextTenantId) {
      params.set("tenant_id", nextTenantId);
      setActiveTenantId(nextTenantId);
    } else {
      params.delete("tenant_id");
    }
    router.replace(params.toString() ? `${pathname}?${params.toString()}` : pathname);
  }

  function clearAttackPathFilter() {
    const params = new URLSearchParams(searchParams.toString());
    params.delete("controls");
    router.replace(params.toString() ? `${pathname}?${params.toString()}` : pathname);
  }

  function requestAction(
    kind: "approve" | "execute",
    complianceResultId: string,
    controlId: string,
    isTenantLevel: boolean,
  ) {
    if (isPreviewMode) {
      startMicrosoftOAuth("smb_onboarding");
      return;
    }
    const isExecute = kind === "execute";
    setPendingAction({
      kind,
      complianceResultId,
      controlId,
      isTenantLevel,
      title: isExecute ? "Execute Remediation" : "Approve Finding",
      message: isExecute
        ? isTenantLevel
          ? `This will change tenant-wide security settings for control: ${controlId}. This action modifies live tenant configuration and cannot be undone automatically.`
          : `This will apply remediation for control: ${controlId}. This action modifies live identity settings.`
        : "You are approving this finding for remediation. The finding will be queued for execution. Approvals expire after 48 hours.",
      confirmLabel: isExecute ? "Execute Remediation" : "Approve",
      variant: isExecute ? "danger" : "warning",
      requireTypedConfirm: isExecute,
    });
  }

  function requestCapabilityAction(
    complianceResultId: string,
    controlId: string,
    capability: ControlCapabilityDecision,
    actionState: CapabilityActionState,
    isTenantLevel: boolean,
  ) {
    if (isPreviewMode) {
      startMicrosoftOAuth("smb_onboarding");
      return;
    }
    if (capability.mode === "blocked" || actionState.buttonDisabled) {
      return;
    }
    if (actionState.requiresConfirmation) {
      setPendingAction({
        kind: "execute",
        complianceResultId,
        controlId,
        isTenantLevel,
        title: "Review Remediation",
        message:
          capability.notes || `Review this action before applying remediation for control: ${controlId}.`,
        confirmLabel: actionState.buttonLabel,
        variant: "warning",
        requireTypedConfirm: false,
        approveBeforeExecute: true,
      });
      return;
    }
    void executeRemediationAction(complianceResultId, false);
  }

  function handleConfirm() {
    if (!pendingAction) return;
    const { kind, complianceResultId, approveBeforeExecute } = pendingAction;
    setPendingAction(null);
    if (kind === "approve") {
      void approveAction(complianceResultId);
      return;
    }
    void executeRemediationAction(complianceResultId, approveBeforeExecute === true);
  }

  async function approveAction(complianceResultId: string) {
    const key = `approve-${complianceResultId}`;
    setLoadingId(key);

    try {
      await ep.approveByResult(complianceResultId, effectiveTenantId);
      setStatusOverrides((current) => ({
        ...current,
        [complianceResultId]: {
          approval_status: "approved",
          execution_status: current[complianceResultId]?.execution_status ?? "pending",
        },
      }));
      setToast("Risk approved");

      riskQuery.refetch();
      complianceQuery.refetch();
      attackPathsQuery.refetch();
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        setToast("Action endpoint not found. Please refresh or contact support.");
      } else {
        setToast(error instanceof Error ? error.message : "Action failed");
      }
    } finally {
      setLoadingId(null);
    }
  }

  async function executeRemediationAction(complianceResultId: string, approveBeforeExecute: boolean) {
    const key = `execute-${complianceResultId}`;
    setLoadingId(key);

    try {
      const complianceResult = complianceById.get(String(complianceResultId));
      const risk = rows.find((item) => String(item.compliance_result_id) === String(complianceResultId));
      let selectedRolesForExecution: string[] | undefined;

      if (OVERPRIVILEGED_ROLE_CONTROL_IDS.has(complianceResult?.control_id ?? risk?.control_id ?? "")) {
        const effectiveSelectedRoles = selectedRolesByResultIdRef.current[complianceResultId] ?? [];
        if (!effectiveSelectedRoles.length) {
          setToast("No roles selected");
          return;
        }
        selectedRolesForExecution = effectiveSelectedRoles;
      }

      if (approveBeforeExecute) {
        await ep.approveByResult(complianceResultId, effectiveTenantId);
      }

      const response =
        (complianceResult?.control_id ?? risk?.control_id) === "IDENTITY_BREAK_GLASS_ACCOUNT"
          ? await ep.createBreakGlassAccounts({ approve: true })
          : await ep.executeRemediation(complianceResultId, selectedRolesForExecution, effectiveTenantId);
      if (
        (complianceResult?.control_id ?? risk?.control_id) === "IDENTITY_BREAK_GLASS_ACCOUNT" &&
        "created_accounts" in response &&
        Array.isArray(response.created_accounts) &&
        response.created_accounts.length > 0
      ) {
        setBreakGlassCredentials(response.created_accounts);
      }
      const executionSucceeded =
        response.status?.toLowerCase() === "success" ||
        response.status?.toLowerCase() === "executed" ||
        ("remediation_status" in response && response.remediation_status === "SUCCESS");

      if (!executionSucceeded) {
        setToast(normalizeExecuteFailureMessage(response.status, response.reason, response.message));
        return;
      }

      setStatusOverrides((current) => ({
        ...current,
        [complianceResultId]: {
          approval_status: "approved",
          execution_status: "executed",
        },
      }));
      setToast("Remediation executed successfully");

      riskQuery.refetch();
      complianceQuery.refetch();
      attackPathsQuery.refetch();
    } catch (error) {
      setToast(error instanceof Error ? error.message : "Action failed");
    } finally {
      setLoadingId(null);
    }
  }

  async function acknowledgeFinding(complianceResultId: string) {
    const key = `acknowledge-${complianceResultId}`;
    setLoadingId(key);

    try {
      await ep.acknowledgeComplianceResult(complianceResultId);
      setStatusOverrides((current) => ({
        ...current,
        [complianceResultId]: {
          approval_status: "approved",
          execution_status: "executed",
        },
      }));
      setToast("Break-glass usage marked as authorized");
      riskQuery.refetch();
      complianceQuery.refetch();
      attackPathsQuery.refetch();
    } catch (error) {
      setToast(error instanceof Error ? error.message : "Acknowledgment failed");
    } finally {
      setLoadingId(null);
    }
  }

  async function retryFetchRoles(complianceResultId: string) {
    const key = `roles-${complianceResultId}`;
    setLoadingId(key);
    try {
      await ep.refreshOverprivilegedRoles(complianceResultId);
      await Promise.all([riskQuery.refetch(), complianceQuery.refetch(), attackPathsQuery.refetch()]);
      setToast("Role fetch retried");
    } catch (error) {
      setToast(error instanceof Error ? error.message : "No roles detected for this user");
    } finally {
      setLoadingId(null);
    }
  }

  async function handleReviewAccount(complianceResultId: string, userId: string) {
    setLoadingId(`review-${complianceResultId}`);
    try {
      const session = await ep.startUserOffboarding(userId);
      router.push(`/offboarding/${session.session_id}`);
    } catch (error) {
      setToast(error instanceof Error ? error.message : "Failed to start account review");
    } finally {
      setLoadingId(null);
    }
  }

  return (
    <div className="space-y-6">
      <ConfirmModal
        open={pendingAction !== null}
        title={pendingAction?.title ?? "Confirm Action"}
        message={pendingAction?.message ?? "Review this action before continuing."}
        confirmLabel={pendingAction?.confirmLabel ?? "Confirm"}
        variant={pendingAction?.variant ?? "warning"}
        requireTypedConfirm={pendingAction?.requireTypedConfirm ?? false}
        onConfirm={handleConfirm}
        onCancel={() => setPendingAction(null)}
      />
      <PageHeader
        title="Risk Feed"
        subtitle="Cross-tenant security misconfigurations ordered by severity"
        actions={
          <Button
            variant="primary"
            size="sm"
            onClick={() => {
              riskQuery.refetch();
              complianceQuery.refetch();
              attackPathsQuery.refetch();
            }}
          >
            <RefreshCw size={13} className={isLoading ? "animate-spin" : ""} /> Refresh
          </Button>
        }
      />

      <FloatingNotice message={toast} />

      {breakGlassCredentials ? (
        <div className="fixed inset-0 z-[130] flex items-center justify-center bg-gray-950/85 px-4 backdrop-blur-sm">
          <div className="w-full max-w-2xl rounded-3xl border border-red-400/30 bg-gray-950 p-6 shadow-2xl shadow-red-950/40">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.35em] text-red-300">
                  Break-glass credentials
                </p>
                <h2 className="mt-2 text-2xl font-semibold text-white">Save this password now</h2>
                <p className="mt-2 text-sm text-red-100/85">
                  ⚠ Save this password now. It will not be shown again.
                </p>
              </div>
              <button
                type="button"
                aria-label="Close break-glass credentials modal"
                onClick={() => setBreakGlassCredentials(null)}
                className="rounded-full border border-white/10 p-2 text-gray-300 transition hover:border-white/30 hover:text-white"
              >
                <X size={16} />
              </button>
            </div>

            <div className="mt-5 space-y-3">
              {breakGlassCredentials.map((account) => (
                <div
                  key={account.username}
                  className="rounded-2xl border border-white/10 bg-white/[0.03] p-4"
                >
                  <p className="text-xs uppercase tracking-[0.25em] text-gray-500">
                    {account.display_name ?? "Break-glass account"}
                  </p>
                  <p className="mt-2 font-mono text-sm text-cyan-100">{account.username}</p>
                  <div className="mt-3 rounded-xl border border-red-400/20 bg-red-500/10 px-3 py-2">
                    <p className="text-xs font-medium text-red-200">One-time password</p>
                    <p className="mt-1 break-all font-mono text-sm text-white">{account.password}</p>
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-5 flex justify-end">
              <Button variant="primary" size="sm" onClick={() => setBreakGlassCredentials(null)}>
                I saved these passwords
              </Button>
            </div>
          </div>
        </div>
      ) : null}

      {attackPathControlFilter.length > 0 ? (
        <Card className="border-red-500/20 bg-red-500/5 px-4 py-3">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-sm font-semibold text-red-100">Attack path filter active</p>
              <p className="mt-1 text-xs text-red-200/80">
                Showing findings linked to: {attackPathControlFilter.map(formatControlLabel).join(", ")}
              </p>
            </div>
            <Button variant="ghost" size="sm" onClick={clearAttackPathFilter}>
              <X size={12} /> Clear filter
            </Button>
          </div>
        </Card>
      ) : null}

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Card className="p-5">
          <p className="text-xs font-medium uppercase tracking-wider text-gray-400">Total Issues</p>
          <p className="mt-3 text-3xl font-bold text-gray-200">{isLoading ? "-" : rows.length}</p>
          <p className="mt-1 text-xs text-gray-500">all severities</p>
        </Card>
        <Card className="p-5">
          <p className="text-xs font-medium uppercase tracking-wider text-gray-400">Critical</p>
          <p className="mt-3 text-3xl font-bold text-red-400">{isLoading ? "-" : critical}</p>
          <p className="mt-1 text-xs text-gray-500">immediate action</p>
        </Card>
        <Card className="p-5">
          <p className="text-xs font-medium uppercase tracking-wider text-gray-400">High</p>
          <p className="mt-3 text-3xl font-bold text-orange-400">{isLoading ? "-" : high}</p>
          <p className="mt-1 text-xs text-gray-500">resolve soon</p>
        </Card>
        <Card className="p-5">
          <p className="text-xs font-medium uppercase tracking-wider text-gray-400">Tenants Affected</p>
          <p className="mt-3 text-3xl font-bold text-yellow-400">
            {isLoading ? "-" : new Set(rows.map((row) => row.tenant_id)).size}
          </p>
          <p className="mt-1 text-xs text-gray-500">unique tenants</p>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="p-5 lg:col-span-1">
          <p className="mb-4 text-sm font-semibold text-gray-200">Risk Distribution</p>
          {isLoading ? (
            <TableSkeleton rows={3} cols={1} />
          ) : riskQuery.error ? (
            <ErrorState message={riskQuery.error} />
          ) : sevCounts.length === 0 ? (
            <EmptyState message="No risks found" />
          ) : (
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={sevCounts} barSize={32}>
                <XAxis
                  dataKey="severity"
                  tick={{ fill: "#6b7280", fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: "#6b7280", fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                  width={24}
                />
                <Tooltip
                  contentStyle={{
                    background: "#111827",
                    border: "1px solid #374151",
                    borderRadius: 8,
                    color: "#e5e7eb",
                    fontSize: 12,
                  }}
                  cursor={{ fill: "rgba(255,255,255,0.04)" }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {sevCounts.map((entry, index) => (
                    <Cell key={index} fill={SEV_COLOR[entry.severity]} opacity={0.85} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </Card>

        <Card className="overflow-hidden lg:col-span-2">
          <div className="flex flex-col justify-between gap-3 border-b border-gray-800 px-5 py-4 sm:flex-row sm:items-center">
            <div className="flex items-center gap-2">
              <Zap size={14} className="text-yellow-400" />
              <p className="text-sm font-semibold text-gray-200">Live Risk Feed</p>
              {!isLoading ? (
                <span className="rounded-full bg-gray-800 px-2 py-0.5 text-xs text-gray-500">
                  {filtered.length}
                </span>
              ) : null}
            </div>
            <div className="flex gap-2">
              <FilterSelect
                value={severityFilter}
                onChange={setSeverityFilter}
                options={SEV_ORDER.map((severity) => ({ label: severity, value: severity }))}
                placeholder="All severities"
              />
              <FilterSelect
                value={effectiveTenantId ?? ""}
                onChange={handleTenantSwitch}
                options={tenantOptions}
                placeholder="Current tenant"
              />
            </div>
          </div>
          {isLoading ? (
            <div className="p-5">
              <TableSkeleton rows={7} cols={6} />
            </div>
          ) : riskQuery.error ? (
            <ErrorState message={riskQuery.error} />
          ) : filtered.length === 0 ? (
            <EmptyState message="No risks match the current filter" />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-800">
                    {["Severity", "Tenant", "Identity", "Control ID", "Status", "Detected", "Actions"].map(
                      (heading) => (
                        <th
                          key={heading}
                          className="whitespace-nowrap px-5 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-400"
                        >
                          {heading}
                        </th>
                      ),
                    )}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/50">
                  {[...filtered]
                    .sort(
                      (a, b) =>
                        SEV_ORDER.indexOf(a.severity as Severity) - SEV_ORDER.indexOf(b.severity as Severity),
                    )
                    .map((risk) => {
                      const complianceResult = complianceById.get(String(risk.compliance_result_id));
                      const availableRoles = getRoles(complianceResult ?? risk);
                      const roleOptions = mapRoleOptions(availableRoles);
                      const resolvedControlId = complianceResult?.control_id ?? risk.control_id;
                      const capability = resolveControlCapabilityWithFallback(
                        capabilitiesQuery.data ?? undefined,
                        resolvedControlId,
                      );
                      const isOverprivilegedAdmin = OVERPRIVILEGED_ROLE_CONTROL_IDS.has(resolvedControlId);
                      const isManualReviewOnly = MANUAL_REVIEW_ONLY_CONTROLS.has(resolvedControlId);
                      const evidence = getEvidenceRecord(complianceResult);
                      const decisionStatus =
                        typeof complianceResult?.decision_status === "string"
                          ? complianceResult.decision_status
                          : undefined;
                      const blockReason = formatBlockReason(
                        typeof complianceResult?.block_reason === "string"
                          ? complianceResult.block_reason
                          : null,
                      );
                      const errorLabel =
                        typeof complianceResult?.error_label === "string"
                          ? complianceResult.error_label
                          : typeof complianceResult?.error_type === "string"
                            ? formatBlockReason(complianceResult.error_type)
                            : null;
                      const status =
                        decisionStatus === "ACKNOWLEDGED" ||
                        risk.acknowledged ||
                        complianceResult?.acknowledged
                          ? "ACKNOWLEDGED"
                          : decisionStatus === "BLOCKED"
                            ? "BLOCKED"
                            : decisionStatus === "FAILED" || decisionStatus === "FAILED_SAFE"
                              ? "FAILED"
                              : risk.execution_status === "executed"
                                ? "EXECUTED"
                                : risk.approval_status === "approved"
                                  ? "APPROVED"
                                  : "PENDING";
                      const approveLoading = loadingId === `approve-${risk.compliance_result_id}`;
                      const executeLoading = loadingId === `execute-${risk.compliance_result_id}`;
                      const acknowledgeLoading = loadingId === `acknowledge-${risk.compliance_result_id}`;
                      const requiresAcknowledgment =
                        risk.requires_acknowledgment === true ||
                        complianceResult?.requires_acknowledgment === true ||
                        risk.control_id === "IDENTITY_BREAK_GLASS_USAGE";
                      const canApprove =
                        risk.approval_status === "pending" &&
                        decisionStatus !== "FAILED" &&
                        decisionStatus !== "BLOCKED";
                      const licenseRequired =
                        risk.requires_license ?? complianceResult?.requires_license === true;
                      const licenseAvailable =
                        risk.license_available ?? complianceResult?.license_available !== false;
                      const rowSelectedRoles =
                        selectedRolesByResultId[String(risk.compliance_result_id)] ?? [];
                      const hasRoles = roleOptions.length > 0;
                      const roleRetryLoading = loadingId === `roles-${risk.compliance_result_id}`;
                      const canExecuteBase =
                        (risk.execution_status === "pending" || decisionStatus === "FAILED") &&
                        decisionStatus !== "BLOCKED" &&
                        (!licenseRequired || licenseAvailable);
                      const canExecute = isManualReviewOnly
                        ? false
                        : isOverprivilegedAdmin
                          ? canExecuteBase && rowSelectedRoles.length > 0
                          : canExecuteBase;
                      const isDirectRemediationControl = DIRECT_REMEDIATION_CONTROLS.has(risk.control_id);
                      const isTenantLevelIdentityControl =
                        risk.resource_type === "TENANT" || complianceResult?.resource_type === "TENANT";
                      const licenseMessage =
                        licenseRequired && !licenseAvailable ? "Requires Azure AD Premium P1" : undefined;
                      const executeMessage =
                        isOverprivilegedAdmin && !hasRoles
                          ? "No roles available for this user"
                          : licenseMessage;
                      const lastExecutionError =
                        typeof evidence.last_execution_error === "string"
                          ? evidence.last_execution_error
                          : null;
                      const impactLabel = formatImpactScore(risk.impact_score);
                      const capabilityAction = capability
                        ? buildCapabilityActionState(resolvedControlId, capability, impactLabel)
                        : null;
                      const capabilityDisabled = (capabilityAction?.buttonDisabled ?? false) || !canExecute;
                      const capabilityTooltipText = capabilityDisabled
                        ? (executeMessage ?? capabilityAction?.buttonTooltip)
                        : capabilityAction?.buttonTooltip;
                      const isUserResource = risk.resource_type === "USER";
                      const resourceName = isUserResource
                        ? risk.resource_name && risk.resource_name !== risk.resource_id
                          ? risk.resource_name
                          : "Unknown User"
                        : formatResourceTypeLabel(risk.resource_type);
                      const resourceSubtext = isUserResource
                        ? (risk.resource_email ?? risk.resource_id)
                        : risk.resource_id;
                      const showAdminBadge = isUserResource && risk.is_admin === true;
                      const isAdminUnusedAccount =
                        resolvedControlId === "IDENTITY_UNUSED_ACCOUNT" && risk.is_admin === true;
                      const reviewLoading = loadingId === `review-${risk.compliance_result_id}`;
                      const isCriticalAttackPath = criticalAttackPathControls.has(risk.control_id);
                      const rowHighlightClass = isCriticalAttackPath
                        ? "border-l-2 border-red-500/60 bg-red-500/5"
                        : risk.is_attack_path
                          ? "bg-orange-500/5"
                          : "hover:bg-gray-800/40";

                      const isSimulationRowOpen = activeSimulationId === risk.compliance_result_id;
                      const simulationResult =
                        isSimulationRowOpen && !simulation.loading ? simulation.result : null;
                      const applySimulationLoading = loadingId === `execute-${risk.compliance_result_id}`;

                      return (
                        <Fragment key={risk.compliance_result_id}>
                          <tr className={`${rowHighlightClass} transition-colors`}>
                            <td className="px-5 py-3.5">
                              <div className="flex flex-col gap-2">
                                <SeverityBadge value={risk.severity as Severity} />
                                {isCriticalAttackPath ? (
                                  <span className="inline-flex items-center gap-1 rounded-full border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-red-200">
                                    <AlertTriangle size={10} /> Critical path
                                  </span>
                                ) : risk.is_attack_path ? (
                                  <span className="inline-flex items-center gap-1 rounded-full border border-orange-500/30 bg-orange-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-orange-200">
                                    <Flame size={10} /> Part of attack path
                                  </span>
                                ) : null}
                              </div>
                            </td>
                            <td className="px-5 py-3.5 font-medium text-gray-200">{risk.tenant_name}</td>
                            <td className="px-5 py-3.5">
                              <div className="min-w-[12rem]">
                                <div className="flex flex-wrap items-center gap-2">
                                  <p className="font-semibold text-gray-100">{resourceName}</p>
                                  {showAdminBadge ? (
                                    <span className="inline-flex rounded-full border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-red-300">
                                      ADMIN
                                    </span>
                                  ) : null}
                                </div>
                                <p className="text-xs text-gray-400">{resourceSubtext}</p>
                              </div>
                            </td>
                            <td className="px-5 py-3.5 font-mono text-xs text-gray-300">
                              <div className="flex flex-col gap-2">
                                <div className="flex flex-wrap items-center gap-2">
                                  <span>{risk.control_id.replace(/_/g, " ")}</span>
                                  {licenseRequired ? (
                                    <span className="inline-flex rounded-full border border-fuchsia-500/30 bg-fuchsia-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-fuchsia-200">
                                      Premium Feature
                                    </span>
                                  ) : null}
                                </div>
                                {risk.is_attack_path ? (
                                  <span className="text-[11px] text-gray-400">
                                    Active in attack path chain: {formatControlLabel(risk.control_id)}
                                  </span>
                                ) : null}
                              </div>
                            </td>
                            <td className="px-5 py-3.5">
                              <div className="flex flex-col gap-1">
                                <StatusBadge value={status} />
                                {decisionStatus === "BLOCKED" && blockReason ? (
                                  <span className="text-[11px] text-red-300">BLOCKED ({blockReason})</span>
                                ) : null}
                                {decisionStatus === "FAILED" && errorLabel ? (
                                  <span className="text-[11px] text-amber-200">FAILED ({errorLabel})</span>
                                ) : null}
                              </div>
                            </td>
                            <td className="px-5 py-3.5 text-xs text-gray-500">
                              {relTime(risk.evaluated_at)}
                            </td>
                            <td className="px-5 py-3.5">
                              <div
                                className={
                                  isOverprivilegedAdmin
                                    ? "flex max-w-[14rem] flex-col gap-2"
                                    : "flex items-center gap-2"
                                }
                              >
                                {isOverprivilegedAdmin ? (
                                  <>
                                    <select
                                      multiple
                                      value={rowSelectedRoles}
                                      onChange={(event) => {
                                        const selected = Array.from(
                                          event.target.selectedOptions,
                                          (o) => o.value,
                                        );
                                        setSelectedRolesByResultId((current) => {
                                          const next = {
                                            ...current,
                                            [String(risk.compliance_result_id)]: selected,
                                          };
                                          selectedRolesByResultIdRef.current = next;
                                          return next;
                                        });
                                      }}
                                      disabled={!hasRoles}
                                      className="w-full max-w-[18rem] rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-200 outline-none transition-colors focus:border-cyan-500 disabled:cursor-not-allowed disabled:opacity-60"
                                    >
                                      {!hasRoles ? <option value="">No roles available</option> : null}
                                      {roleOptions.map((role) => (
                                        <option key={role.value} value={role.value}>
                                          {role.label}
                                        </option>
                                      ))}
                                    </select>
                                    {!hasRoles ? (
                                      <p className="text-[11px] text-amber-200">
                                        No roles available for this user
                                      </p>
                                    ) : null}
                                    {hasRoles && rowSelectedRoles.length === 0 ? (
                                      <p className="text-[11px] text-amber-200">Please select a role</p>
                                    ) : null}
                                  </>
                                ) : null}
                                <div className="flex flex-wrap items-center gap-2">
                                  {requiresAcknowledgment ? (
                                    <Button
                                      variant="primary"
                                      size="sm"
                                      loading={acknowledgeLoading}
                                      disabled={risk.acknowledged || complianceResult?.acknowledged}
                                      onClick={() => acknowledgeFinding(risk.compliance_result_id)}
                                    >
                                      <CheckCircle size={11} />{" "}
                                      {risk.action?.label ??
                                        complianceResult?.action?.label ??
                                        "Mark as Authorized"}
                                    </Button>
                                  ) : isAdminUnusedAccount ? (
                                    <Button
                                      variant="primary"
                                      size="sm"
                                      loading={reviewLoading}
                                      onClick={() =>
                                        handleReviewAccount(
                                          String(risk.compliance_result_id),
                                          risk.resource_id,
                                        )
                                      }
                                    >
                                      Review Account
                                    </Button>
                                  ) : capability ? (
                                    <>
                                      <span
                                        className={`inline-flex items-center rounded-md px-2 py-1 text-[11px] font-semibold tracking-wide ${capabilityModeClasses(
                                          capability.mode,
                                        )}`}
                                      >
                                        {capabilityModeLabel(capability.mode)}
                                      </span>
                                      <span title={capabilityTooltipText}>
                                        <Button
                                          variant={capability.mode === "blocked" ? "secondary" : "primary"}
                                          size="sm"
                                          loading={executeLoading}
                                          disabled={capabilityDisabled}
                                          onClick={() => {
                                            if (!capabilityAction) return;
                                            requestCapabilityAction(
                                              risk.compliance_result_id,
                                              resolvedControlId,
                                              capability,
                                              capabilityAction,
                                              isTenantLevelIdentityControl,
                                            );
                                          }}
                                        >
                                          {capability.mode !== "blocked" ? <Play size={11} /> : null}
                                          {capabilityAction?.buttonLabel ?? "Review & Fix"}
                                        </Button>
                                      </span>
                                    </>
                                  ) : isOverprivilegedAdmin ? (
                                    <Button
                                      variant="primary"
                                      size="sm"
                                      loading={approveLoading}
                                      disabled={!canApprove}
                                      onClick={() =>
                                        requestAction(
                                          "approve",
                                          risk.compliance_result_id,
                                          resolvedControlId,
                                          isTenantLevelIdentityControl,
                                        )
                                      }
                                    >
                                      <CheckCircle size={11} /> Approve
                                    </Button>
                                  ) : !isTenantLevelIdentityControl && !isDirectRemediationControl ? (
                                    <Button
                                      variant="primary"
                                      size="sm"
                                      loading={approveLoading}
                                      disabled={!canApprove}
                                      onClick={() =>
                                        requestAction(
                                          "approve",
                                          risk.compliance_result_id,
                                          resolvedControlId,
                                          isTenantLevelIdentityControl,
                                        )
                                      }
                                    >
                                      <CheckCircle size={11} /> Approve
                                    </Button>
                                  ) : null}
                                  {!capability && !requiresAcknowledgment && !isManualReviewOnly ? (
                                    <span title={executeMessage}>
                                      <Button
                                        variant={
                                          isTenantLevelIdentityControl || isDirectRemediationControl
                                            ? "primary"
                                            : "secondary"
                                        }
                                        size="sm"
                                        loading={executeLoading}
                                        disabled={!canExecute}
                                        onClick={() =>
                                          requestAction(
                                            "execute",
                                            risk.compliance_result_id,
                                            resolvedControlId,
                                            isTenantLevelIdentityControl,
                                          )
                                        }
                                      >
                                        <Play size={11} />
                                        {decisionStatus === "FAILED"
                                          ? `Retry${impactLabel ? ` (${impactLabel})` : ""}`
                                          : risk.control_id === "IDENTITY_BREAK_GLASS_ACCOUNT" &&
                                              complianceResult?.remediation_cta?.label
                                            ? `${complianceResult.remediation_cta.label}${impactLabel ? ` (${impactLabel})` : ""}`
                                            : isOverprivilegedAdmin
                                              ? `Fix${impactLabel ? ` (${impactLabel})` : ""}`
                                              : isTenantLevelIdentityControl || isDirectRemediationControl
                                                ? `Fix Now${impactLabel ? ` (${impactLabel})` : ""}`
                                                : `Execute${impactLabel ? ` (${impactLabel})` : ""}`}
                                      </Button>
                                    </span>
                                  ) : null}
                                  {isManualReviewOnly ? (
                                    <span className="text-[11px] text-gray-400">Manual review required</span>
                                  ) : null}
                                  {capabilityAction?.note ? (
                                    <span
                                      className={`text-[11px] ${
                                        capability?.mode === "blocked" ? "text-gray-400" : "text-yellow-200"
                                      }`}
                                    >
                                      <AlertTriangle
                                        size={11}
                                        className="mr-1 inline-block align-text-bottom"
                                      />
                                      {capabilityAction.note}
                                    </span>
                                  ) : null}
                                  {impactLabel ? (
                                    <span className="text-[11px] text-cyan-200">
                                      Fixing this improves score by {impactLabel}
                                    </span>
                                  ) : null}
                                  {executeMessage ? (
                                    <span
                                      className={`text-[11px] ${hasRoles ? "text-fuchsia-200" : "text-amber-200"}`}
                                    >
                                      {executeMessage}
                                    </span>
                                  ) : null}
                                  {decisionStatus === "FAILED" && lastExecutionError ? (
                                    <span className="text-[11px] text-red-300">{lastExecutionError}</span>
                                  ) : null}
                                  {decisionStatus === "BLOCKED" && blockReason ? (
                                    <span className="text-[11px] text-red-300">{blockReason}</span>
                                  ) : null}
                                  {!requiresAcknowledgment &&
                                  !isManualReviewOnly &&
                                  capability?.mode !== "blocked" &&
                                  !capabilityAction?.buttonDisabled &&
                                  canSimulateFix(risk.control_id) ? (
                                    <div className="flex flex-col items-end gap-0.5">
                                      <Button
                                        variant="ghost"
                                        size="sm"
                                        loading={simulation.loading && isSimulationRowOpen}
                                        disabled={usersQuery.loading}
                                        onClick={() => {
                                          void handleSimulateFix(risk, complianceResult);
                                        }}
                                      >
                                        Simulate Fix
                                      </Button>
                                      <span className="text-[10px] text-gray-500 pr-1">
                                        Preview the impact of an MFA Conditional Access policy before
                                        enforcement.
                                      </span>
                                    </div>
                                  ) : null}
                                </div>
                                {isOverprivilegedAdmin && !hasRoles ? (
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    loading={roleRetryLoading}
                                    onClick={() => retryFetchRoles(risk.compliance_result_id)}
                                  >
                                    Retry Fetch Roles
                                  </Button>
                                ) : null}
                              </div>
                            </td>
                          </tr>
                          {isSimulationRowOpen ? (
                            <tr className="bg-gray-950/40">
                              <td colSpan={7} className="px-5 pb-4">
                                {simulationError ? (
                                  <p className="pt-2 text-sm text-red-400">{simulationError}</p>
                                ) : null}
                                <div className="pt-3">
                                  <SimulationPanel
                                    simulation={simulationResult}
                                    loading={simulation.loading}
                                    applyLoading={applySimulationLoading}
                                    onApply={() => {
                                      if (capability && capabilityAction) {
                                        requestCapabilityAction(
                                          risk.compliance_result_id,
                                          resolvedControlId,
                                          capability,
                                          capabilityAction,
                                          isTenantLevelIdentityControl,
                                        );
                                        return;
                                      }
                                      requestAction(
                                        "execute",
                                        risk.compliance_result_id,
                                        resolvedControlId,
                                        isTenantLevelIdentityControl,
                                      );
                                    }}
                                    onCancel={() => {
                                      setSimulationError(null);
                                      setActiveSimulationId(null);
                                    }}
                                  />
                                </div>
                              </td>
                            </tr>
                          ) : null}
                        </Fragment>
                      );
                    })}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
