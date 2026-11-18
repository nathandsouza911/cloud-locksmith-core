import { coverageStatusLabel, filterCoverageUsers } from "@/lib/ca-coverage";
import type { CoverageUser } from "@/lib/api/endpoints";

const result = (status: CoverageUser["mfa"]["status"]) => ({ status, policies: [], reasons: [] });

function user(id: string, mfa: CoverageUser["mfa"]["status"], legacy = "covered" as const): CoverageUser {
  return {
    id,
    display_name: id,
    user_principal_name: `${id}@x`,
    enabled: true,
    is_guest: false,
    is_admin: false,
    mfa: result(mfa),
    legacy_auth: result(legacy),
    admin_mfa: result("not_applicable"),
  };
}

test("gaps-only keeps users with any gap or report-only result", () => {
  const users = [user("ok", "covered"), user("gap", "gap"), user("ro", "report_only")];
  expect(filterCoverageUsers(users, { gapsOnly: true, search: "" }).map((u) => u.id)).toEqual(["gap", "ro"]);
  expect(filterCoverageUsers(users, { gapsOnly: false, search: "" })).toHaveLength(3);
});

test("search matches name or UPN, case-insensitive", () => {
  const users = [user("Alice", "gap"), user("bob", "gap")];
  expect(filterCoverageUsers(users, { gapsOnly: false, search: "ALI" }).map((u) => u.id)).toEqual(["Alice"]);
  expect(filterCoverageUsers(users, { gapsOnly: false, search: "bob@" }).map((u) => u.id)).toEqual(["bob"]);
});

test("status labels are plain words", () => {
  expect(coverageStatusLabel("report_only")).toBe("Report-only");
  expect(coverageStatusLabel("not_applicable")).toBe("N/A");
});
