/**
 * Pure decision logic for control status and button state.
 *
 * Extracted from controls/page.tsx so the rules can be unit-tested without a
 * React render tree.  page.tsx imports and delegates to these functions.
 */

import { capabilityTooltip } from "@/lib/control-capabilities";
import type { ComplianceResult, ControlCapabilityDecision } from "@/types";

// ---------------------------------------------------------------------------
// Display-status type
// ---------------------------------------------------------------------------

export type ControlDisplayStatus = "NOT_CONFIGURED" | "PARTIAL" | "ENFORCED" | "COMPLIANT";

// ---------------------------------------------------------------------------
// Non-CA controls (IDENTITY_*): status derived from compliance results only.
//
// COMPLIANT  -- latest scan passed; no action required.
// PARTIAL    -- latest scan passed but a prior remediation failed/blocked.
// NOT_CONFIGURED -- latest scan failed, or no results exist.
//
// ENFORCED is intentionally absent from the non-CA path: it is reserved for
// CA controls where a policy was actively applied via the CA enforcement engine.
// ---------------------------------------------------------------------------

export function deriveNonCaStatus(
  controlId: string,
  complianceResults: ComplianceResult[],
): { status: ControlDisplayStatus; finding: ComplianceResult | undefined } {
  const findings = complianceResults
    .filter((r) => r.control_id === controlId)
    .sort((a, b) => (a.evaluated_at < b.evaluated_at ? 1 : -1));
  const latest = findings[0];

  if (!latest) {
    return { status: "NOT_CONFIGURED", finding: undefined };
  }
  if (latest.passed === false) {
    return { status: "NOT_CONFIGURED", finding: latest };
  }
  if (latest.remediation_status === "FAILED" || latest.remediation_status === "BLOCKED") {
    return { status: "PARTIAL", finding: latest };
  }
  return { status: "COMPLIANT", finding: latest };
}

// ---------------------------------------------------------------------------
// Button state
// ---------------------------------------------------------------------------

export interface ControlButtonState {
  buttonLabel: string;
  buttonDisabled: boolean;
  buttonTooltip?: string;
  capabilityNotes: string | null;
}

const NON_CA_CONTROL_IDS = new Set<string>([
  "IDENTITY_USER_CONSENT_POLICY",
  "IDENTITY_ILLICIT_CONSENT_GRANTS",
]);

function isCaControl(controlId: string): boolean {
  return !NON_CA_CONTROL_IDS.has(controlId);
}

/**
 * Derive the action-button state for a control card.
 *
 * @param controlId  Canonical control ID.
 * @param capability Resolved capability decision from the backend, if any.
 * @param status     Current display status of the control.
 */
export function buildControlButtonState(
  controlId: string,
  capability: ControlCapabilityDecision | undefined,
  status: ControlDisplayStatus = "NOT_CONFIGURED",
): ControlButtonState {
  // COMPLIANT: the finding already passed -- no action available.
  if (status === "COMPLIANT") {
    return {
      buttonLabel: "Compliant",
      buttonDisabled: true,
      buttonTooltip: "No action required — this control is already passing.",
      capabilityNotes: null,
    };
  }

  if (!capability) {
    return {
      buttonLabel: "Fix Now",
      buttonDisabled: false,
      capabilityNotes: null,
    };
  }

  if (controlId === "IDENTITY_USER_NO_MFA" && capability.mode !== "auto") {
    return {
      buttonLabel: "Manual Action Required",
      buttonDisabled: true,
      buttonTooltip: capabilityTooltip(capability.mode, capability.notes),
      capabilityNotes: capability.notes || "This action requires manual follow-up.",
    };
  }

  if (capability.mode === "auto") {
    return {
      buttonLabel: "Fix Now",
      buttonDisabled: false,
      capabilityNotes: null,
    };
  }

  if (capability.mode === "manual") {
    const isCA = isCaControl(controlId);

    if (isCA && capability.ca_license_available === false) {
      return {
        buttonLabel: "License Required",
        buttonDisabled: true,
        buttonTooltip:
          capability.license_note ??
          "Conditional Access requires Microsoft Entra ID P1/P2 or equivalent licensing.",
        capabilityNotes: null,
      };
    }

    return {
      buttonLabel: controlId === "IDENTITY_ADMIN_NO_MFA" ? "Fix: Remove Admin Access" : "Review & Fix",
      buttonDisabled: false,
      buttonTooltip: capabilityTooltip(capability.mode, capability.notes),
      capabilityNotes: isCA ? null : capability.notes || "Review this action before applying it.",
    };
  }

  // blocked
  return {
    buttonLabel:
      controlId === "TENANT_CONDITIONAL_ACCESS_POLICY"
        ? "Not supported on Google Workspace"
        : "Not Available",
    buttonDisabled: true,
    buttonTooltip: capabilityTooltip(capability.mode, capability.notes),
    capabilityNotes: capability.notes || "This action is not supported for your provider.",
  };
}
