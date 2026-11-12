"use client";

import { useMemo } from "react";
import { useRouter } from "next/navigation";
import { AlertTriangle, ArrowRight, ShieldAlert, Siren } from "lucide-react";

import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  PageHeader,
  SeverityBadge,
  StatCard,
  TableSkeleton,
} from "@/components/ui";
import { useAttackPaths } from "@/lib/api/hooks";
import { useAuth } from "@/lib/auth-context";

function formatControlLabel(controlId: string): string {
  return controlId
    .replace(/^IDENTITY_/, "")
    .split("_")
    .filter(Boolean)
    .map((segment) => segment.charAt(0) + segment.slice(1).toLowerCase())
    .join(" ");
}

export default function AttackPathsPage() {
  const router = useRouter();
  const { tenantId, selectedTenant, requiresTenantSelection, setActiveTenantId } = useAuth();
  const attackPathsQuery = useAttackPaths(tenantId);
  const summary = attackPathsQuery.data;
  const paths = summary?.paths ?? [];

  const subtitle = useMemo(() => {
    if (!tenantId) return "Select a tenant to evaluate breach scenarios.";
    return `Active breach scenarios for ${selectedTenant?.tenant_name ?? tenantId}`;
  }, [selectedTenant?.tenant_name, tenantId]);

  function handleFixPath(pathId: string) {
    if (!tenantId) return;

    setActiveTenantId(tenantId);
    router.push(`/dashboard/attack-paths/${pathId}`);
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Attack Paths"
        subtitle={subtitle}
        actions={
          <Button variant="secondary" size="sm" onClick={() => attackPathsQuery.refetch()}>
            Refresh
          </Button>
        }
      />

      {requiresTenantSelection || !tenantId ? (
        <Card className="p-8">
          <EmptyState message="Select a tenant to view active attack paths" />
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            <StatCard
              label="Total Attack Paths"
              value={attackPathsQuery.loading ? "-" : (summary?.total_paths ?? 0)}
              sub="active breach scenarios"
              accent="text-cyan-400"
              icon={<ShieldAlert size={18} />}
            />
            <StatCard
              label="Critical Paths"
              value={attackPathsQuery.loading ? "-" : (summary?.critical_paths ?? 0)}
              sub="immediate escalation risks"
              accent="text-red-400"
              icon={<Siren size={18} />}
            />
            <StatCard
              label="High Paths"
              value={attackPathsQuery.loading ? "-" : (summary?.high_paths ?? 0)}
              sub="active high-risk chains"
              accent="text-orange-400"
              icon={<AlertTriangle size={18} />}
            />
          </div>

          <Card className="overflow-hidden">
            <div className="border-b border-gray-800 px-5 py-4">
              <p className="text-sm font-semibold text-gray-200">Triggered Attack Paths</p>
              <p className="mt-1 text-xs text-gray-500">
                Each path activates only when all required failed controls are present.
              </p>
            </div>

            {attackPathsQuery.loading ? (
              <div className="p-5">
                <TableSkeleton rows={4} cols={1} />
              </div>
            ) : attackPathsQuery.error ? (
              <ErrorState message={attackPathsQuery.error} />
            ) : paths.length === 0 ? (
              <EmptyState message="No active attack paths for this tenant" />
            ) : (
              <div className="divide-y divide-gray-800/60">
                {paths.map((path) => {
                  const isCritical = path.severity === "CRITICAL";

                  return (
                    <div key={path.id} className={`px-5 py-5 ${isCritical ? "bg-red-500/5" : ""}`}>
                      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                        <div className="min-w-0 space-y-3">
                          <div className="flex flex-wrap items-center gap-3">
                            <p className="text-lg font-semibold text-gray-100">{path.name}</p>
                            <SeverityBadge value={path.severity} />
                          </div>
                          <p className="max-w-3xl text-sm text-gray-300">{path.description}</p>
                          <div>
                            <p className="text-xs font-semibold uppercase tracking-wider text-gray-500">
                              Triggered by
                            </p>
                            <div className="mt-3 flex flex-wrap gap-2">
                              {path.controls_triggered.map((controlId) => (
                                <span
                                  key={controlId}
                                  className="inline-flex items-center rounded-full border border-red-500/20 bg-red-500/10 px-3 py-1 text-xs font-medium text-red-200"
                                >
                                  {formatControlLabel(controlId)}
                                  <span className="ml-2 text-red-400">X</span>
                                </span>
                              ))}
                            </div>
                          </div>
                        </div>

                        <div className="flex shrink-0 items-center">
                          <Button
                            variant={isCritical ? "danger" : "primary"}
                            size="sm"
                            onClick={() => handleFixPath(path.id)}
                          >
                            Fix this path
                            <ArrowRight size={12} />
                          </Button>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
