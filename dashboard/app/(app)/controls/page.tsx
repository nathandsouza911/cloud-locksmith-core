"use client";

import { useEffect, useMemo, useState } from "react";
import { Shield, ShieldCheck, ShieldX } from "lucide-react";

import ControlCard from "@/components/controls/ControlCard";
import {
  Card,
  ConfirmModal,
  EmptyState,
  ErrorState,
  PageHeader,
  StatCard,
  TableSkeleton,
} from "@/components/ui";
import * as ep from "@/lib/api/endpoints";
import { resolveControlCapabilityWithFallback } from "@/lib/control-capabilities";
import {
  buildControlButtonState,
  deriveNonCaStatus,
  type ControlButtonState,
  type ControlDisplayStatus,
} from "@/lib/control-status";
import { useComplianceResults, useControlCapabilities } from "@/lib/api/hooks";
import { useAuth } from "@/lib/auth-context";
import type { ComplianceResult, ControlCapabilityDecision, ControlStateResponse, Severity } from "@/types";

interface ControlDefinition {
  controlId: string;
  title: string;
  severity: Severity;
  description: string;
}

interface ControlActionState {
  loading: boolean;
  label: string | null;
}

interface PendingControlAction {
  controlId: string;
  finding?: ComplianceResult;
  capability?: ControlCapabilityDecision;
  confirmLabel: string;
}

const CONTROL_DEFINITIONS: ControlDefinition[] = [
  {
    controlId: "CA_MFA_ALL_USERS",
    title: "Require MFA for All Users",
    severity: "CRITICAL",
    description:
      "Protects every interactive sign-in with MFA and reduces the blast radius of password compromise.",
  },
  {
    controlId: "CA_MFA_ADMINS",
    title: "Require MFA for Admins",
    severity: "CRITICAL",
    description:
      "Adds stronger sign-in controls to privileged roles so administrative access is harder to abuse.",
  },
  {
    controlId: "CA_LEGACY_AUTH_BLOCK",
    title: "Block Legacy Authentication",
    severity: "HIGH",
    description:
      "Shuts down older authentication paths that bypass modern access protections and MFA enforcement.",
  },
  {
    controlId: "CA_DEVICE_CODE_FLOW_BLOCK",
    title: "Block Device Code Flow",
    severity: "HIGH",
    description:
      "Prevents device code phishing paths that attackers can use to obtain valid sessions from users.",
  },
  {
    controlId: "CA_AUTHENTICATION_TRANSFER_BLOCK",
    title: "Block Authentication Transfer",
    severity: "HIGH",
    description:
      "Stops authentication transfer flows that can be abused for token handoff and phishing-assisted session theft.",
  },
  {
    controlId: "CA_GUEST_MFA",
    title: "Require MFA for Guest Users",
    severity: "HIGH",
    description:
      "Requires guest and external collaborators to use MFA before they can access Microsoft 365 resources.",
  },
  {
    controlId: "CA_BREAK_GLASS_EXCLUSION",
    title: "Protect Break-Glass Exclusions",
    severity: "HIGH",
    description:
      "Ensures emergency access accounts stay excluded from Conditional Access policies to avoid tenant lockout.",
  },
  {
    controlId: "IDENTITY_USER_CONSENT_POLICY",
    title: "User App Consent Lockdown",
    severity: "HIGH",
    description: "Users can currently grant apps access without admin approval.",
  },
  {
    controlId: "IDENTITY_ILLICIT_CONSENT_GRANTS",
    title: "Suspicious App Permissions",
    severity: "CRITICAL",
    description: "Apps currently have access to sensitive data like email or files.",
  },
];

const NON_CA_CONTROL_IDS = new Set<string>([
  "IDENTITY_USER_CONSENT_POLICY",
  "IDENTITY_ILLICIT_CONSENT_GRANTS",
]);

function isCaControl(controlId: string): boolean {
  return !NON_CA_CONTROL_IDS.has(controlId);
}

function parseEvidence(evidence: ComplianceResult["evidence"]): Record<string, unknown> {
  if (!evidence) return {};
  if (typeof evidence === "string") {
    try {
      const parsed = JSON.parse(evidence);
      return typeof parsed === "object" && parsed !== null ? parsed : {};
    } catch {
      return {};
    }
  }
  return evidence;
}

function illicitGrantCount(result: ComplianceResult | undefined): number {
  if (!result) return 0;
  const evidence = parseEvidence(result.evidence);
  const grants = evidence.illicit_grants;
  return Array.isArray(grants) ? grants.length : 0;
}

function deriveControlStatus(
  controlId: string,
  stateResponse: ControlStateResponse | null | undefined,
  complianceResults: ComplianceResult[],
): ControlDisplayStatus {
  const controlFindings = complianceResults.filter(
    (result) => result.control_id === controlId && result.passed === false,
  );

  const state = stateResponse?.state;
  if (state?.status === "error" || state?.rollout_phase === "partial") {
    return "PARTIAL";
  }
  if (controlFindings.length > 0) {
    return "NOT_CONFIGURED";
  }
  if (
    state &&
    state.status === "active" &&
    (state.mode === "enforced" || controlId === "CA_BREAK_GLASS_EXCLUSION")
  ) {
    return "ENFORCED";
  }
  if (stateResponse?.latest_snapshot) {
    return "PARTIAL";
  }
  return "NOT_CONFIGURED";
}

function actionLabelForResult(result: { status: string; reason?: string } | null | undefined): string | null {
  if (!result) return null;
  if (result.status === "success" || result.status === "no-op") return "Applied and Verified";
  if (result.status === "partial") return "Partial - needs review";
  if (result.status === "blocked") {
    if (result.reason === "NO_CA_LICENSE") {
      return "License required: Entra P1/P2 needed";
    }
    return "Blocked (license or config)";
  }
  return null;
}

export default function ControlsPage() {
  const { tenantId } = useAuth();
  const complianceQuery = useComplianceResults(tenantId);
  const capabilitiesQuery = useControlCapabilities(tenantId);
  const [controlStates, setControlStates] = useState<Record<string, ControlStateResponse>>({});
  const [statesLoading, setStatesLoading] = useState(true);
  const [statesError, setStatesError] = useState<string | null>(null);
  const [actionStateByControl, setActionStateByControl] = useState<Record<string, ControlActionState>>({});
  const [pendingAction, setPendingAction] = useState<PendingControlAction | null>(null);

  useEffect(() => {
    if (!capabilitiesQuery.error) return;
    console.error("Failed to load control capabilities", capabilitiesQuery.error);
  }, [capabilitiesQuery.error]);

  useEffect(() => {
    let cancelled = false;

    async function loadControlStates() {
      if (!tenantId) {
        setControlStates({});
        setStatesLoading(false);
        setStatesError("Select a tenant to continue");
        return;
      }

      setStatesLoading(true);
      setStatesError(null);
      try {
        const responses = await Promise.all(
          CONTROL_DEFINITIONS.filter(({ controlId }) => isCaControl(controlId)).map(
            async ({ controlId }) => [controlId, await ep.getControlState(controlId)] as const,
          ),
        );

        if (cancelled) return;
        setControlStates(Object.fromEntries(responses));
      } catch (error) {
        if (cancelled) return;
        setStatesError(error instanceof Error ? error.message : "Failed to load controls");
        setControlStates({});
      } finally {
        if (!cancelled) {
          setStatesLoading(false);
        }
      }
    }

    void loadControlStates();

    return () => {
      cancelled = true;
    };
  }, [tenantId]);

  const complianceResults = complianceQuery.data ?? [];

  const controlCards = useMemo(
    () =>
      CONTROL_DEFINITIONS.map((definition) => {
        const actionState = actionStateByControl[definition.controlId];
        const capability = resolveControlCapabilityWithFallback(
          capabilitiesQuery.data ?? undefined,
          definition.controlId,
        );
        if (isCaControl(definition.controlId)) {
          const status = deriveControlStatus(
            definition.controlId,
            controlStates[definition.controlId],
            complianceResults,
          );
          const buttonState = buildControlButtonState(definition.controlId, capability, status);
          return {
            ...definition,
            status,
            // The CA fix runs through the approval workflow on this finding.
            finding: deriveNonCaStatus(definition.controlId, complianceResults).finding,
            actionState,
            capability,
            buttonState,
          };
        }

        const { status, finding } = deriveNonCaStatus(definition.controlId, complianceResults);
        const buttonState = buildControlButtonState(definition.controlId, capability, status);
        return {
          ...definition,
          status,
          finding,
          actionState,
          capability,
          buttonState,
        };
      }),
    [actionStateByControl, capabilitiesQuery.data, complianceResults, controlStates],
  );

  const enforcedCount = controlCards.filter(
    (control) => control.status === "ENFORCED" || control.status === "COMPLIANT",
  ).length;
  const partialCount = controlCards.filter((control) => control.status === "PARTIAL").length;
  const notConfiguredCount = controlCards.filter((control) => control.status === "NOT_CONFIGURED").length;

  async function refreshControl(controlId: string) {
    const nextState = await ep.getControlState(controlId);
    setControlStates((current) => ({
      ...current,
      [controlId]: nextState,
    }));
  }

  async function handleFixNow(
    controlId: string,
    finding?: ComplianceResult,
    capability?: ControlCapabilityDecision,
  ) {
    setActionStateByControl((current) => ({
      ...current,
      [controlId]: {
        loading: true,
        label: capability?.mode === "manual" ? "Reviewing..." : "Applying...",
      },
    }));

    try {
      if (capability?.mode === "blocked") {
        throw new Error(capability.notes || "This action is not available for this tenant.");
      }

      if (!finding || finding.passed === true) {
        setActionStateByControl((current) => ({
          ...current,
          [controlId]: {
            loading: false,
            label: finding?.passed ? "Already compliant" : "No active finding to remediate",
          },
        }));
        return;
      }

      const grantsBefore = controlId === "IDENTITY_ILLICIT_CONSENT_GRANTS" ? illicitGrantCount(finding) : 0;

      // Conditional Access fixes always need an approval record: the backend refuses to
      // execute them otherwise, and the approval starts the 48 h expiry.
      if (capability?.mode === "manual" || isCaControl(controlId)) {
        await ep.approveByResult(finding.id, tenantId);
      }

      const result = await ep.executeRemediation(finding.id);

      if (isCaControl(controlId)) {
        await refreshControl(controlId);
      }

      const successLabel =
        controlId === "IDENTITY_ILLICIT_CONSENT_GRANTS"
          ? `Removed ${grantsBefore} risky app permission${grantsBefore === 1 ? "" : "s"}`
          : isCaControl(controlId)
            ? (actionLabelForResult(result) ?? "Applied and Verified")
            : "Applied and Verified";

      setActionStateByControl((current) => ({
        ...current,
        [controlId]: { loading: false, label: successLabel },
      }));

      complianceQuery.refetch();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Blocked (license or config)";
      setActionStateByControl((current) => ({
        ...current,
        [controlId]: { loading: false, label: message || "Blocked (license or config)" },
      }));
    }
  }

  function requestControlAction(
    controlId: string,
    finding?: ComplianceResult,
    capability?: ControlCapabilityDecision,
  ) {
    if (capability?.mode === "blocked") return;

    const buttonState = buildControlButtonState(controlId, capability, undefined);
    if (capability?.mode === "manual") {
      setPendingAction({
        controlId,
        finding,
        capability,
        confirmLabel: buttonState.buttonLabel,
      });
      return;
    }

    void handleFixNow(controlId, finding, capability);
  }

  function confirmPendingAction() {
    if (!pendingAction) return;
    const { controlId, finding, capability } = pendingAction;
    setPendingAction(null);
    void handleFixNow(controlId, finding, capability);
  }

  return (
    <div className="space-y-6">
      <ConfirmModal
        open={pendingAction !== null}
        title="Review Remediation"
        message={
          pendingAction?.capability?.notes ||
          `Review this action before applying remediation for ${pendingAction?.controlId ?? "this control"}.`
        }
        confirmLabel={pendingAction?.confirmLabel ?? "Review & Fix"}
        variant="warning"
        onConfirm={confirmPendingAction}
        onCancel={() => setPendingAction(null)}
      />

      <PageHeader
        title="Security Controls"
        subtitle="Review tenant-wide identity controls and apply supported fixes without leaving the dashboard."
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Controls"
          value={CONTROL_DEFINITIONS.length}
          sub="available in this workspace"
          accent="text-cyan-400"
          icon={<Shield size={18} />}
        />
        <StatCard
          label="Enforced"
          value={enforcedCount}
          sub="verified or active"
          accent="text-emerald-400"
          icon={<ShieldCheck size={18} />}
        />
        <StatCard label="Partial" value={partialCount} sub="needs follow-up" accent="text-yellow-400" />
        <StatCard
          label="Not Configured"
          value={notConfiguredCount}
          sub="ready to fix"
          accent="text-red-400"
          icon={<ShieldX size={18} />}
        />
      </div>

      {statesError ? <ErrorState message={statesError} /> : null}
      {complianceQuery.error ? <ErrorState message={complianceQuery.error} /> : null}

      <Card className="overflow-hidden">
        <div className="border-b border-gray-800 px-5 py-4">
          <p className="text-sm font-semibold text-gray-200">Tenant Controls</p>
          <p className="mt-0.5 text-xs text-gray-500">
            These actions call the backend control engine directly. Rollback stays in Remediation History.
          </p>
        </div>

        {statesLoading || complianceQuery.loading || capabilitiesQuery.loading ? (
          <div className="p-5">
            <TableSkeleton rows={5} cols={1} />
          </div>
        ) : controlCards.length === 0 ? (
          <EmptyState message="No controls available" />
        ) : (
          <div className="grid grid-cols-1 gap-4 p-5 xl:grid-cols-2">
            {controlCards.map((control) => {
              let detail: string | null = null;
              let warning: string | null = null;
              if (control.controlId === "IDENTITY_ILLICIT_CONSENT_GRANTS") {
                const count = illicitGrantCount(control.finding);
                if (count > 0) {
                  detail = `${count} risky app${count === 1 ? "" : "s"} detected`;
                }
                if (control.finding) {
                  const evidence = parseEvidence(control.finding.evidence);
                  const stateAfter = evidence.state_after as Record<string, unknown> | undefined;
                  const result =
                    (stateAfter?.result as Record<string, unknown> | undefined) ??
                    (evidence.result as Record<string, unknown> | undefined);
                  const failed = result?.failed;
                  if (Array.isArray(failed) && failed.length > 0) {
                    warning = "Some apps could not be removed - manual review needed";
                  }
                }
              }

              return (
                <ControlCard
                  key={control.controlId}
                  controlId={control.controlId}
                  title={control.title}
                  description={control.description}
                  severity={control.severity}
                  status={control.status}
                  actionLabel={control.actionState?.label ?? null}
                  detail={detail}
                  warning={warning}
                  loading={control.actionState?.loading ?? false}
                  buttonLabel={control.buttonState.buttonLabel}
                  buttonDisabled={control.buttonState.buttonDisabled}
                  buttonTooltip={control.buttonState.buttonTooltip}
                  capabilityMode={control.capability?.mode ?? null}
                  capabilityNotes={
                    control.status === "NOT_CONFIGURED" ? control.buttonState.capabilityNotes : null
                  }
                  onFixNow={() =>
                    requestControlAction(control.controlId, control.finding, control.capability)
                  }
                />
              );
            })}
          </div>
        )}
      </Card>
    </div>
  );
}
