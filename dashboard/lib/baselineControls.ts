import type { Severity } from "@/types";

// Customer-selectable baseline controls.
//
// MUST stay in sync with CUSTOMER_SELECTABLE_CONTROLS in
// cloud-locksmith-backend/app/services/baseline/baseline_definition.py
// (= MSP_SECURITY_BASELINE minus ALWAYS_MONITORED_CONTROLS).
//
// Always-monitored controls (IDENTITY_BREAK_GLASS_USAGE, CA_BREAK_GLASS_EXCLUSION)
// are intentionally absent — the backend enforces them regardless of baseline,
// so they are not customer-selectable here.
//
// TODO: replace with a /api/v1/baseline/control-definitions fetch so the UI can
// never drift from the backend registry.

export type BaselineControlBadge = "MANUAL_REVIEW" | "DANGEROUS" | "REQUIRES_P1";

export type BaselineControlDef = {
  id: string;
  label: string;
  description: string;
  severity: Severity;
  badges: BaselineControlBadge[];
};

export const BASELINE_CONTROLS: BaselineControlDef[] = [
  {
    id: "IDENTITY_USER_NO_MFA",
    label: "User MFA",
    description: "Ensure every standard user is protected with MFA",
    severity: "HIGH",
    badges: ["MANUAL_REVIEW"],
  },
  {
    id: "IDENTITY_ADMIN_NO_MFA",
    label: "Admin MFA",
    description: "Ensure no administrator remains without MFA",
    severity: "CRITICAL",
    badges: ["MANUAL_REVIEW"],
  },
  {
    id: "IDENTITY_UNUSED_ACCOUNT",
    label: "Unused Accounts",
    description: "Detect and remediate inactive identities",
    severity: "MEDIUM",
    badges: [],
  },
  {
    id: "IDENTITY_ADMIN_COUNT_EXCESS",
    label: "Admin Count",
    description: "Global administrator count should not exceed policy thresholds",
    severity: "HIGH",
    badges: ["MANUAL_REVIEW"],
  },
  {
    id: "IDENTITY_OVERPRIVILEGED_USER",
    label: "Overprivileged Users",
    description: "Users should have minimal admin role assignments",
    severity: "HIGH",
    badges: [],
  },
  {
    id: "IDENTITY_BREAK_GLASS_ACCOUNT",
    label: "Break-Glass Accounts",
    description: "Two valid break-glass accounts must be configured",
    severity: "HIGH",
    badges: ["DANGEROUS"],
  },
  {
    id: "IDENTITY_GUEST_INVITES_OPEN",
    label: "Guest Invites Restricted",
    description: "Limit guest invitations to approved roles",
    severity: "MEDIUM",
    badges: ["DANGEROUS"],
  },
  {
    id: "IDENTITY_USER_CONSENT_POLICY",
    label: "User Consent Restricted",
    description: "Restrict user consent to OAuth applications to owned resources",
    severity: "HIGH",
    badges: [],
  },
  {
    id: "IDENTITY_ILLICIT_CONSENT_GRANTS",
    label: "Illicit Consent Grants",
    description: "Detect risky OAuth grants already consented by users",
    severity: "CRITICAL",
    badges: [],
  },
  {
    id: "CA_MFA_ALL_USERS",
    label: "CA — MFA All Users",
    description: "MFA enforced for all users via Conditional Access policy",
    severity: "CRITICAL",
    badges: ["REQUIRES_P1"],
  },
  {
    id: "CA_MFA_ADMINS",
    label: "CA — MFA Admins",
    description: "MFA enforced for all privileged roles via Conditional Access policy",
    severity: "CRITICAL",
    badges: ["REQUIRES_P1"],
  },
  {
    id: "CA_LEGACY_AUTH_BLOCK",
    label: "CA — Block Legacy Auth",
    description: "Legacy authentication blocked via Conditional Access policy",
    severity: "HIGH",
    badges: ["REQUIRES_P1"],
  },
  {
    id: "CA_DEVICE_CODE_FLOW_BLOCK",
    label: "CA — Block Device Code Flow",
    description: "Device code flow blocked via Conditional Access policy",
    severity: "HIGH",
    badges: ["REQUIRES_P1"],
  },
  {
    id: "CA_AUTHENTICATION_TRANSFER_BLOCK",
    label: "CA — Block Auth Transfer",
    description: "Authentication transfer blocked via Conditional Access policy",
    severity: "HIGH",
    badges: ["REQUIRES_P1"],
  },
  {
    id: "CA_GUEST_MFA",
    label: "CA — Guest MFA",
    description: "MFA enforced for guest and external users via Conditional Access policy",
    severity: "HIGH",
    badges: ["REQUIRES_P1"],
  },
];

export const BASELINE_CONTROL_IDS: string[] = BASELINE_CONTROLS.map((c) => c.id);
const SELECTABLE_ID_SET = new Set(BASELINE_CONTROL_IDS);

/**
 * Restrict a list of control ids to the customer-selectable set. Always-monitored
 * controls (and any unknown/legacy ids) returned by the backend template are
 * dropped so selectedControls.length always matches the number of controls
 * rendered in the UI.
 */
export function toSelectableControls(controlIds: string[] | null | undefined): string[] {
  return (controlIds ?? []).filter((id) => SELECTABLE_ID_SET.has(id));
}

export const BADGE_LABELS: Record<BaselineControlBadge, string> = {
  MANUAL_REVIEW: "Manual Review Required",
  DANGEROUS: "Dangerous Remediation",
  REQUIRES_P1: "Requires Entra P1/P2",
};

export const BADGE_STYLES: Record<BaselineControlBadge, string> = {
  MANUAL_REVIEW: "border-amber-500/30 bg-amber-500/10 text-amber-300",
  DANGEROUS: "border-red-500/30 bg-red-500/10 text-red-300",
  REQUIRES_P1: "border-violet-500/30 bg-violet-500/10 text-violet-300",
};
