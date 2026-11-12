import type { ControlCapabilityDecision, ControlCapabilityMap, ControlCapabilityMode } from "@/types";

const CAPABILITY_ALIASES: Record<string, string> = {
  IDENTITY_ILLICIT_CONSENT_GRANTS: "IDENTITY_RISKY_OAUTH_APP",
  IDENTITY_OVERPRIVILEGED_USER: "IDENTITY_OVERPRIVILEGED_ADMIN",
  CA_MFA_ALL_USERS: "TENANT_CONDITIONAL_ACCESS_POLICY",
  CA_MFA_ADMINS: "TENANT_CONDITIONAL_ACCESS_POLICY",
  CA_LEGACY_AUTH_BLOCK: "TENANT_CONDITIONAL_ACCESS_POLICY",
  CA_DEVICE_CODE_FLOW_BLOCK: "TENANT_CONDITIONAL_ACCESS_POLICY",
  CA_AUTHENTICATION_TRANSFER_BLOCK: "TENANT_CONDITIONAL_ACCESS_POLICY",
  CA_GUEST_MFA: "TENANT_CONDITIONAL_ACCESS_POLICY",
};

const CAPABILITY_MANAGED_CONTROL_IDS = new Set<string>([
  "IDENTITY_USER_NO_MFA",
  "IDENTITY_ADMIN_NO_MFA",
  "IDENTITY_DORMANT_ACCOUNT",
  "IDENTITY_OVERPRIVILEGED_ADMIN",
  "IDENTITY_RISKY_OAUTH_APP",
  "TENANT_CONDITIONAL_ACCESS_POLICY",
  ...Object.keys(CAPABILITY_ALIASES),
]);

const FALLBACK_MANUAL_CAPABILITY: ControlCapabilityDecision = {
  allowed: false,
  mode: "blocked",
  reason: "capability_unavailable",
  notes: "Capability data is unavailable for this control. Review this action manually.",
};

export function normalizeCapabilityControlId(controlId: string): string {
  return CAPABILITY_ALIASES[controlId] ?? controlId;
}

export function isCapabilityManagedControl(controlId: string): boolean {
  return CAPABILITY_MANAGED_CONTROL_IDS.has(controlId);
}

export function resolveControlCapability(
  capabilities: ControlCapabilityMap | null | undefined,
  controlId: string,
): ControlCapabilityDecision | undefined {
  if (!capabilities) return undefined;
  const normalizedControlId = normalizeCapabilityControlId(controlId);
  return capabilities[controlId] ?? capabilities[normalizedControlId];
}

export function resolveControlCapabilityWithFallback(
  capabilities: ControlCapabilityMap | null | undefined,
  controlId: string,
): ControlCapabilityDecision | undefined {
  const capability = resolveControlCapability(capabilities, controlId);
  if (capability) return capability;
  if (!isCapabilityManagedControl(controlId)) return undefined;
  return FALLBACK_MANUAL_CAPABILITY;
}

export function capabilityModeLabel(mode: ControlCapabilityMode): string {
  if (mode === "auto") return "Auto";
  if (mode === "manual") return "Manual";
  return "Blocked";
}

export function capabilityModeClasses(mode: ControlCapabilityMode): string {
  if (mode === "auto") {
    return "border border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
  }
  if (mode === "manual") {
    return "border border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
  }
  return "border border-gray-700 bg-gray-800/80 text-gray-300";
}

export function capabilityTooltip(mode: ControlCapabilityMode, notes?: string | null): string | undefined {
  if (notes && notes.trim().length > 0) return notes;
  if (mode === "manual" || mode === "blocked") {
    return "This action is not supported for your provider";
  }
  return undefined;
}
