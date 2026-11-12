export const SIMULATE_FIX_CONTROLS: ReadonlySet<string> = new Set(["CA_MFA_ALL_USERS", "CA_MFA_ADMINS"]);

export function canSimulateFix(controlId: string): boolean {
  return SIMULATE_FIX_CONTROLS.has(controlId);
}
