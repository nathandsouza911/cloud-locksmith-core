import type { DirectoryUser } from "@/types";

export type TenantIdentitySnapshot = {
  users: string[];
  groups: Record<string, string[]>;
  roles: Record<string, string[]>;
};

function dedupe(values: string[]) {
  return Array.from(new Set(values.map((value) => value.trim()).filter(Boolean)));
}

export function buildRoleMembershipMap(users: DirectoryUser[]): Record<string, string[]> {
  const roleMap: Record<string, string[]> = {};

  for (const user of users) {
    if (!user.id) continue;
    for (const roleName of user.roles ?? []) {
      const normalizedRole = roleName?.trim();
      if (!normalizedRole) continue;
      roleMap[normalizedRole] = dedupe([...(roleMap[normalizedRole] ?? []), user.id]);
    }
  }

  return roleMap;
}

export function buildTenantIdentitySnapshot(users: DirectoryUser[]): TenantIdentitySnapshot | null {
  const userIds = dedupe(users.map((user) => user.id).filter(Boolean));
  if (userIds.length === 0) {
    return null;
  }

  return {
    users: userIds,
    groups: {},
    roles: buildRoleMembershipMap(users),
  };
}
