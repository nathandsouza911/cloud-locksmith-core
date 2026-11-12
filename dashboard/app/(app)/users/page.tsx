"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowRight, Search, ShieldAlert, Users } from "lucide-react";

import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  PageHeader,
  SeverityBadge,
  TableSkeleton,
} from "@/components/ui";
import * as ep from "@/lib/api/endpoints";
import { useUsers } from "@/lib/api/hooks";
import { useAuth } from "@/lib/auth-context";
import { startMicrosoftOAuth } from "@/lib/auth";

function relTime(iso: string | null) {
  if (!iso) return "No recent activity";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${Math.max(mins, 0)}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default function UsersPage() {
  const router = useRouter();
  const { tenantId: selectedTenantId, isPreviewMode } = useAuth();
  const usersQuery = useUsers(selectedTenantId);
  const [search, setSearch] = useState("");
  const [visibleUsers, setVisibleUsers] = useState<typeof usersQuery.data>(null);
  const [actionUserId, setActionUserId] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const users = usersQuery.data ?? [];
  const filteredUsers = useMemo(() => {
    const term = search.trim().toLowerCase();
    if (!term) return visibleUsers ?? users;

    return (visibleUsers ?? users).filter((user) =>
      `${user.email ?? ""} ${user.display_name ?? ""}`.toLowerCase().includes(term),
    );
  }, [search, users, visibleUsers]);

  useEffect(() => {
    setVisibleUsers([]);
  }, [selectedTenantId]);

  useEffect(() => {
    setVisibleUsers(users);
  }, [users]);

  useEffect(() => {
    console.log("tenant:", selectedTenantId);
  }, [selectedTenantId]);

  useEffect(() => {
    console.log("users:", users);
  }, [users]);

  useEffect(() => {
    if (!toast) return undefined;
    const timeout = window.setTimeout(() => setToast(null), 2500);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  function handleOffboard(userId: string, roles: string[]) {
    if (isPreviewMode) {
      startMicrosoftOAuth("smb_onboarding");
      return;
    }
    const isGlobalAdmin = roles.some((role) => role.toLowerCase() === "global administrator");
    if (isGlobalAdmin) {
      const confirmed = window.confirm("You are offboarding a privileged account");
      if (!confirmed) return;
    }
    router.push(`/users/${userId}/offboard`);
  }

  function isOffboardingLocked(user: (typeof users)[number]) {
    return user.is_offboarded === true || user.offboarding_status === "COMPLETED";
  }

  async function handleRollbackOffboarding(userId: string) {
    if (isPreviewMode) {
      startMicrosoftOAuth("smb_onboarding");
      return;
    }
    setActionUserId(userId);
    try {
      await ep.rollbackUserOffboarding(userId);
      setToast("User restored successfully");
      usersQuery.refetch();
    } catch (_error) {
      setToast("Failed to rollback offboarding");
    } finally {
      setActionUserId(null);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Users"
        subtitle="Tenant-scoped identity inventory with risk context and offboarding entry points"
      />

      {toast ? (
        <Card className="px-4 py-3 border-cyan-500/30 bg-cyan-500/10 text-sm text-cyan-100">{toast}</Card>
      ) : null}

      <div className="grid gap-4 md:grid-cols-3">
        <Card className="p-5">
          <p className="text-xs font-medium uppercase tracking-wider text-gray-400">Users</p>
          <p className="mt-3 text-3xl font-bold text-gray-100">
            {usersQuery.loading ? "..." : filteredUsers.length}
          </p>
          <p className="mt-1 text-xs text-gray-500">directory accounts in the current tenant</p>
        </Card>
        <Card className="p-5">
          <p className="text-xs font-medium uppercase tracking-wider text-gray-400">At Risk</p>
          <p className="mt-3 text-3xl font-bold text-red-400">
            {usersQuery.loading ? "..." : filteredUsers.filter((user) => user.open_findings > 0).length}
          </p>
          <p className="mt-1 text-xs text-gray-500">users with active identity findings</p>
        </Card>
        <Card className="p-5">
          <p className="text-xs font-medium uppercase tracking-wider text-gray-400">Admins</p>
          <p className="mt-3 text-3xl font-bold text-cyan-300">
            {usersQuery.loading ? "..." : filteredUsers.filter((user) => user.role === "Admin").length}
          </p>
          <p className="mt-1 text-xs text-gray-500">accounts with elevated role exposure</p>
        </Card>
      </div>

      <Card className="overflow-hidden">
        <div className="flex flex-col gap-3 border-b border-gray-800 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <Users size={14} className="text-cyan-400" />
            <p className="text-sm font-semibold text-gray-200">Identity Roster</p>
          </div>
          <label className="flex items-center gap-2 rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-300">
            <Search size={14} className="text-gray-500" />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search users"
              className="w-56 bg-transparent outline-none placeholder:text-gray-500"
            />
          </label>
        </div>

        {usersQuery.loading ? (
          <div className="p-5">
            <TableSkeleton rows={6} cols={6} />
          </div>
        ) : usersQuery.error ? (
          <ErrorState message={usersQuery.error} />
        ) : filteredUsers.length === 0 ? (
          <EmptyState message="No users found for the current tenant" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  {["User", "Roles", "Status", "Risk", "Last Activity", "Actions"].map((heading) => (
                    <th
                      key={heading}
                      className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-400"
                    >
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/50">
                {filteredUsers.map((user) => (
                  <tr key={user.id} className="hover:bg-gray-800/40 transition-colors">
                    <td className="px-5 py-4">
                      <div>
                        <p className="font-semibold text-gray-100">
                          {user.email ?? user.display_name ?? user.id}
                        </p>
                        <p className="text-xs text-gray-500">{user.display_name ?? user.id}</p>
                      </div>
                    </td>
                    <td className="px-5 py-4">
                      <div className="flex flex-wrap gap-2">
                        <span
                          className={`inline-flex rounded-full border px-2 py-0.5 text-[11px] font-semibold ${
                            user.role === "Admin"
                              ? "border-red-500/30 bg-red-500/10 text-red-300"
                              : "border-gray-700 bg-gray-800 text-gray-300"
                          }`}
                        >
                          {user.role === "Admin" ? "Admin" : "User"}
                        </span>
                        {user.roles.map((role) => (
                          <span
                            key={role}
                            className="inline-flex rounded-full border border-cyan-500/20 bg-cyan-500/10 px-2 py-0.5 text-[11px] font-medium text-cyan-200"
                          >
                            {role}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-5 py-4">
                      <span
                        className={`inline-flex rounded-full border px-2 py-0.5 text-[11px] font-semibold ${
                          user.enabled
                            ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                            : "border-gray-700 bg-gray-800 text-gray-400"
                        }`}
                      >
                        {user.enabled ? "Enabled" : "Disabled"}
                      </span>
                    </td>
                    <td className="px-5 py-4">
                      <div className="space-y-1">
                        {user.risk_level === "NONE" ? (
                          <span className="inline-flex rounded-md border border-gray-700 bg-gray-800 px-2 py-0.5 text-[11px] font-semibold text-gray-300">
                            NONE
                          </span>
                        ) : (
                          <SeverityBadge value={user.risk_level} />
                        )}
                        <p className="text-xs text-gray-500">
                          {user.open_findings} open finding{user.open_findings === 1 ? "" : "s"}
                        </p>
                        {user.risk_indicators.length > 0 ? (
                          <p className="max-w-xs text-xs text-gray-400">
                            <ShieldAlert size={12} className="mr-1 inline-block text-yellow-300" />
                            {user.risk_indicators.join(", ")}
                          </p>
                        ) : null}
                      </div>
                    </td>
                    <td className="px-5 py-4 text-xs text-gray-400">{relTime(user.last_activity)}</td>
                    <td className="px-5 py-4">
                      <div className="flex flex-wrap items-center gap-2">
                        <Button
                          variant="primary"
                          size="sm"
                          disabled={isOffboardingLocked(user)}
                          onClick={() => handleOffboard(user.id, user.roles)}
                        >
                          {isOffboardingLocked(user) ? (
                            "Offboarding Completed"
                          ) : (
                            <>
                              Offboard User <ArrowRight size={12} />
                            </>
                          )}
                        </Button>
                        {user.offboarding_status === "COMPLETED" ? (
                          <Button
                            variant="secondary"
                            size="sm"
                            loading={actionUserId === user.id}
                            onClick={() => handleRollbackOffboarding(user.id)}
                          >
                            {actionUserId === user.id ? "Rolling back..." : "Rollback Offboarding"}
                          </Button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
