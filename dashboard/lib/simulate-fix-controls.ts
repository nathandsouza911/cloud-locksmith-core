import type { SimulationControlId } from "@/lib/api/endpoints";

export const SIMULATE_FIX_CONTROLS: ReadonlySet<string> = new Set<SimulationControlId>([
  "CA_MFA_ALL_USERS",
  "CA_MFA_ADMINS",
]);

export function canSimulateFix(controlId: string): controlId is SimulationControlId {
  return SIMULATE_FIX_CONTROLS.has(controlId);
}
