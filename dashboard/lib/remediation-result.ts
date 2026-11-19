import type { ExecuteRemediationResponse } from "@/types";

/**
 * The execute endpoint returns HTTP 200 even when the fix did not apply, so a
 * resolved call is not proof of success: the body decides.
 */
export function executionSucceeded(
  response: Pick<ExecuteRemediationResponse, "status" | "remediation_status"> | null | undefined,
): boolean {
  if (!response) return false;
  return (
    response.status?.toLowerCase() === "success" ||
    response.status?.toLowerCase() === "executed" ||
    ("remediation_status" in response && response.remediation_status === "SUCCESS")
  );
}

/** Nothing to fix: the finding was already compliant or resolved. Not a failure. */
export function executionAlreadyDone(
  response: Pick<ExecuteRemediationResponse, "status"> | null | undefined,
): boolean {
  const status = response?.status?.toLowerCase();
  return status === "already_compliant" || status === "already_resolved";
}

export function normalizeExecuteFailureMessage(status?: string, reason?: string, message?: string): string {
  if (reason === "NO_ROLES_SELECTED") return "Execution failed: no roles selected";
  if (message) return message;
  if (reason) return `Execution failed: ${reason}`;
  if (status) return `Execution failed: ${status}`;
  return "Execution failed";
}
