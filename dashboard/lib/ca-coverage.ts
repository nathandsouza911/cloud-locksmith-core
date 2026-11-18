import type { CoverageStatus, CoverageUser } from "@/lib/api/endpoints";

export const COVERAGE_QUESTIONS = [
  { key: "mfa", label: "MFA" },
  { key: "legacy_auth", label: "Legacy auth blocked" },
  { key: "admin_mfa", label: "Admin MFA" },
] as const;

const LABELS: Record<CoverageStatus, string> = {
  covered: "Covered",
  report_only: "Report-only",
  gap: "Gap",
  not_applicable: "N/A",
};

export function coverageStatusLabel(status: CoverageStatus): string {
  return LABELS[status] ?? status;
}

function hasGap(user: CoverageUser): boolean {
  return COVERAGE_QUESTIONS.some(({ key }) => ["gap", "report_only"].includes(user[key].status));
}

export function filterCoverageUsers(
  users: CoverageUser[],
  { gapsOnly, search }: { gapsOnly: boolean; search: string },
): CoverageUser[] {
  const needle = search.trim().toLowerCase();
  return users.filter((user) => {
    if (gapsOnly && !hasGap(user)) return false;
    if (!needle) return true;
    return [user.display_name, user.user_principal_name].some((v) =>
      (v ?? "").toLowerCase().includes(needle),
    );
  });
}
