"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  AlertTriangle,
  Building2,
  RefreshCw,
  Shield,
  ShieldCheck,
  ShieldQuestion,
  WandSparkles,
} from "lucide-react";

import { Button, Card, EmptyState, ErrorState, PageHeader, StatCard, TableSkeleton } from "@/components/ui";
import { TenantCard } from "@/components/data/renderers";
import { useComplianceResults, useFleetOverview } from "@/lib/api/hooks";
import * as ep from "@/lib/api/endpoints";
import { startMicrosoftOAuth } from "@/lib/auth";
import { useAuth } from "@/lib/auth-context";
import type { ComplianceResult, FleetOverviewTopRisk, Severity } from "@/types";
import { scoreBandAccent } from "@/utils/posture";

const OFFBOARDING_CONTROLS = new Set([
  "IDENTITY_ADMIN_OVERPRIVILEGED",
  "IDENTITY_OVERPRIVILEGED_ADMIN",
  "IDENTITY_DORMANT_ACCOUNT",
]);

const severityOrder: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

function severityAccent(severity: Severity) {
  if (severity === "CRITICAL") return "text-red-400";
  if (severity === "HIGH") return "text-orange-400";
  if (severity === "MEDIUM") return "text-yellow-400";
  if (severity === "LOW") return "text-blue-400";
  return "text-gray-400";
}

function humanizeControlId(controlId: string) {
  return controlId
    .toLowerCase()
    .replace(/^identity_/, "")
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function findingTitle(finding: ComplianceResult) {
  if (
    finding.guidance &&
    typeof finding.guidance === "object" &&
    typeof finding.guidance.title === "string"
  ) {
    return finding.guidance.title;
  }
  return humanizeControlId(finding.control_id);
}

function findingTarget(finding: ComplianceResult) {
  const evidence =
    typeof finding.evidence === "object" && finding.evidence !== null
      ? (finding.evidence as Record<string, unknown>)
      : null;

  return (
    (typeof evidence?.display_name === "string" && evidence.display_name) ||
    (typeof evidence?.user_principal_name === "string" && evidence.user_principal_name) ||
    (typeof evidence?.tenant_name === "string" && evidence.tenant_name) ||
    finding.resource_id
  );
}

export default function DashboardPage() {
  const router = useRouter();
  const { tenants: linkedTenants, setActiveTenantId, tenantId, isSmb } = useAuth();
  const fleetQuery = useFleetOverview();
  const complianceQuery = useComplianceResults(tenantId);

  const [loadingRiskKey, setLoadingRiskKey] = useState<string | null>(null);

  const fleetData = fleetQuery.data;
  const tenants = useMemo(
    () => [...(fleetData?.tenants ?? [])].sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0)),
    [fleetData?.tenants],
  );
  const aggregate = fleetData?.aggregate;
  const topRisks = fleetData?.top_risks ?? [];
  const activeTenant = linkedTenants.find((tenant) => tenant.tenant_id === tenantId) ?? null;
  const activeTenantPosture = tenants.find((t) => t.tenant_id === tenantId) ?? null;
  const complianceRefetch = complianceQuery.refetch;
  const fleetRefetch = fleetQuery.refetch;
  const activeTenantIssues = useMemo(
    () =>
      (complianceQuery.data ?? [])
        .filter((item) => item.passed === false)
        .sort((a, b) => {
          const severityDelta = severityOrder[b.severity] - severityOrder[a.severity];
          if (severityDelta !== 0) return severityDelta;
          return new Date(b.evaluated_at).getTime() - new Date(a.evaluated_at).getTime();
        }),
    [complianceQuery.data],
  );
  const topTenantFindings = activeTenantIssues.slice(0, 5);
  const totalIssues = activeTenantIssues.length;
  const criticalIssueCount = activeTenantIssues.filter((item) => item.severity === "CRITICAL").length;
  const highIssueCount = activeTenantIssues.filter((item) => item.severity === "HIGH").length;
  const mediumIssueCount = activeTenantIssues.filter((item) => item.severity === "MEDIUM").length;
  const lowIssueCount = activeTenantIssues.filter((item) => item.severity === "LOW").length;
  const riskTypes = useMemo(
    () => Array.from(new Set(activeTenantIssues.map((item) => findingTitle(item)))).slice(0, 3),
    [activeTenantIssues],
  );

  function refetchFleet() {
    fleetRefetch();
    complianceRefetch();
  }

  async function handleFixNow(risk: FleetOverviewTopRisk) {
    const key = `${risk.tenant_id}:${risk.control_id}:${risk.resource_id}`;
    setLoadingRiskKey(key);
    try {
      setActiveTenantId(risk.tenant_id);
      if (OFFBOARDING_CONTROLS.has(risk.control_id)) {
        const session = await ep.startGuidedOffboarding(risk.control_id, risk.resource_id);
        router.push(`/offboarding/${session.session_id}`);
      } else {
        router.push(`/risk-feed?tenant_id=${risk.tenant_id}`);
      }
    } finally {
      setLoadingRiskKey(null);
    }
  }

  function handleTenantFindingAction(finding: ComplianceResult) {
    router.push(`/risk-feed?tenant_id=${tenantId ?? ""}`);
  }

  const addTenantButton = (
    <Button
      variant="primary"
      size="sm"
      onClick={() => {
        startMicrosoftOAuth("msp_connect");
      }}
    >
      Add Tenant
    </Button>
  );

  if (!fleetQuery.loading && !fleetQuery.error && tenants.length === 0) {
    return (
      <div className="space-y-6">
        <PageHeader title="Dashboard" subtitle="No tenants connected yet" actions={addTenantButton} />
        <Card className="p-10">
          <div className="flex flex-col items-center justify-center py-12 text-gray-500">
            <p className="text-lg text-gray-300">No tenants connected</p>
            <p className="mt-2 text-sm">
              Connect your first Microsoft tenant to start scanning posture data.
            </p>
            <div className="mt-5">{addTenantButton}</div>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        subtitle={
          activeTenant
            ? isSmb
              ? `${activeTenant.tenant_name} is ready for review`
              : `${activeTenant.tenant_name} is selected for review`
            : `${aggregate?.tenant_count ?? linkedTenants.length} tenants across your MSP fleet`
        }
        actions={
          <>
            <Button variant="secondary" size="sm" onClick={refetchFleet}>
              <RefreshCw size={13} className={fleetQuery.loading ? "animate-spin" : ""} />
              Refresh
            </Button>
            {!isSmb ? addTenantButton : null}
          </>
        }
      />

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1.15fr_0.85fr]">
        <Card className="overflow-hidden">
          <div className="border-b border-gray-800 px-5 py-4">
            <p className="text-sm font-semibold text-gray-200">Selected Tenant Snapshot</p>
            <p className="mt-1 text-xs text-gray-500">
              Issue volume, severity, and top findings for{" "}
              {activeTenant?.tenant_name ?? "the selected tenant"}.
            </p>
          </div>

          {/* Posture Score — always visible once fleet data loads */}
          {!fleetQuery.loading && activeTenantPosture ? (
            <div className="border-b border-gray-800 px-5 py-4">
              <div className="flex items-center gap-4">
                <div className="flex flex-col items-center justify-center rounded-2xl border border-gray-700 bg-gray-900/60 px-6 py-3 min-w-[96px]">
                  <span
                    className={`text-3xl font-bold tabular-nums ${scoreBandAccent(activeTenantPosture.risk_score_band ?? null)}`}
                  >
                    {activeTenantPosture.risk_score ?? "—"}
                  </span>
                  <span className="mt-0.5 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
                    Posture Score
                  </span>
                </div>
                <div className="min-w-0">
                  <p
                    className={`text-sm font-semibold ${scoreBandAccent(activeTenantPosture.risk_score_band ?? null)}`}
                  >
                    {activeTenantPosture.risk_score_band ?? "—"}
                  </p>
                  <p className="mt-0.5 text-xs text-gray-400">
                    {activeTenant?.tenant_name ?? "Selected tenant"}
                  </p>
                  {activeTenantPosture.last_scan ? (
                    <p className="mt-0.5 text-[11px] text-gray-600">
                      Last scan: {new Date(activeTenantPosture.last_scan).toLocaleDateString()}
                    </p>
                  ) : null}
                </div>
              </div>
            </div>
          ) : null}

          {complianceQuery.loading ? (
            <div className="p-5">
              <TableSkeleton rows={4} cols={1} />
            </div>
          ) : complianceQuery.error ? (
            <ErrorState message="Failed to load tenant findings" />
          ) : totalIssues === 0 ? (
            <div className="space-y-5 p-5">
              <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/5 px-5 py-5">
                <div className="flex items-start gap-3">
                  <div className="rounded-full bg-emerald-500/10 p-2 text-emerald-300">
                    <ShieldCheck size={18} />
                  </div>
                  <div>
                    <p className="text-base font-semibold text-white">Your tenant is secure</p>
                    <p className="mt-1 text-sm text-gray-300">
                      We didn&apos;t find any active issues in the latest scan. Keep monitoring enabled so new
                      drift or privilege changes surface quickly.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="space-y-5 p-5">
              <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
                <StatCard
                  label="Total Issues"
                  value={totalIssues}
                  sub="active findings"
                  accent="text-white"
                  icon={<ShieldQuestion size={18} />}
                />
                <StatCard
                  label="Critical"
                  value={criticalIssueCount}
                  sub="highest urgency"
                  accent="text-red-400"
                  icon={<AlertTriangle size={18} />}
                />
                <StatCard
                  label="High"
                  value={highIssueCount}
                  sub="needs action soon"
                  accent="text-orange-400"
                  icon={<AlertTriangle size={18} />}
                />
                <StatCard
                  label="Medium / Low"
                  value={mediumIssueCount + lowIssueCount}
                  sub="watchlist findings"
                  accent="text-yellow-400"
                  icon={<Shield size={18} />}
                />
              </div>

              <div className="rounded-2xl border border-gray-800 bg-gray-950/40">
                <div className="flex items-center justify-between border-b border-gray-800 px-4 py-3">
                  <div>
                    <p className="text-sm font-semibold text-gray-100">Top Findings</p>
                    <p className="mt-1 text-xs text-gray-500">
                      The most urgent findings for the selected tenant.
                    </p>
                  </div>
                </div>
                <div className="divide-y divide-gray-800/70">
                  {topTenantFindings.map((finding) => (
                    <div
                      key={finding.id}
                      className="flex flex-col gap-4 px-4 py-4 lg:flex-row lg:items-center lg:justify-between"
                    >
                      <div className="min-w-0">
                        <p className="text-sm font-semibold text-gray-100">{findingTitle(finding)}</p>
                        <p className="mt-1 text-xs text-gray-400">{findingTarget(finding)}</p>
                        <p className="mt-1 text-[11px] text-gray-500">
                          {humanizeControlId(finding.control_id)}
                        </p>
                      </div>
                      <div className="flex items-center gap-3">
                        <span
                          className={`text-xs font-semibold uppercase tracking-wider ${severityAccent(finding.severity)}`}
                        >
                          {finding.severity}
                        </span>
                        <Button
                          variant="primary"
                          size="sm"
                          onClick={() => handleTenantFindingAction(finding)}
                        >
                          <WandSparkles size={12} />
                          {finding.executable ? "Fix" : "Review"}
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </Card>

        {!isSmb ? (
          <div className="space-y-6">
            <div className="grid grid-cols-1 gap-4 md:grid-cols-3 xl:grid-cols-1">
              <StatCard
                label="Avg Risk Score"
                value={fleetQuery.loading ? "-" : (aggregate?.avg_risk ?? 0)}
                sub="across all tenants"
                accent={scoreBandAccent(aggregate?.avg_risk_band ?? null)}
                icon={<Shield size={18} />}
              />
              <StatCard
                label="Total Critical Findings"
                value={fleetQuery.loading ? "-" : (aggregate?.total_critical ?? 0)}
                sub="priority issues requiring attention"
                accent="text-red-400"
                icon={<AlertTriangle size={18} />}
              />
              <StatCard
                label="Total Tenants"
                value={fleetQuery.loading ? "-" : (aggregate?.tenant_count ?? linkedTenants.length)}
                sub="connected to this MSP account"
                accent="text-cyan-400"
                icon={<Building2 size={18} />}
              />
            </div>

            <Card className="overflow-hidden">
              <div className="flex items-center justify-between border-b border-gray-800 px-5 py-4">
                <div>
                  <p className="text-sm font-semibold text-gray-200">Top Risks Across All Tenants</p>
                  <p className="mt-1 text-xs text-gray-500">
                    Critical findings are prioritized first across your MSP fleet.
                  </p>
                </div>
              </div>

              {fleetQuery.loading ? (
                <div className="p-5">
                  <TableSkeleton rows={5} cols={1} />
                </div>
              ) : fleetQuery.error ? (
                <ErrorState message="Failed to load cross-tenant risks" />
              ) : topRisks.length === 0 ? (
                <EmptyState message="No open risks across connected tenants" />
              ) : (
                <div className="divide-y divide-gray-800/60">
                  {topRisks.map((risk) => {
                    const riskKey = `${risk.tenant_id}:${risk.control_id}:${risk.resource_id}`;
                    return (
                      <div
                        key={riskKey}
                        className="flex flex-col gap-4 px-5 py-4 lg:flex-row lg:items-center lg:justify-between"
                      >
                        <button
                          type="button"
                          className="min-w-0 text-left"
                          onClick={() => handleFixNow(risk)}
                        >
                          <p className="text-sm font-semibold text-gray-100">{risk.title}</p>
                          <p className="mt-1 text-xs text-gray-400">{risk.tenant_name}</p>
                          <p className="mt-1 text-[11px] font-mono text-gray-500">{risk.resource_id}</p>
                        </button>
                        <div className="flex items-center gap-3">
                          <span
                            className={`text-xs font-semibold uppercase tracking-wider ${severityAccent(risk.severity)}`}
                          >
                            {risk.severity}
                          </span>
                          <Button
                            variant="primary"
                            size="sm"
                            loading={loadingRiskKey === riskKey}
                            onClick={() => handleFixNow(risk)}
                          >
                            <WandSparkles size={12} />{" "}
                            {OFFBOARDING_CONTROLS.has(risk.control_id) ? "Offboard User" : "Fix in Findings"}
                          </Button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </Card>
          </div>
        ) : null}
      </div>

      {!isSmb ? (
        <Card className="p-5">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <p className="text-sm font-semibold text-gray-200">Tenant List</p>
              <p className="mt-1 text-xs text-gray-500">
                Click a tenant to drill into the detailed tenant dashboard.
              </p>
            </div>
          </div>

          {fleetQuery.loading ? (
            <TableSkeleton rows={6} cols={1} />
          ) : fleetQuery.error ? (
            <ErrorState message="Failed to load fleet data" />
          ) : tenants.length === 0 ? (
            <div className="space-y-4">
              <EmptyState message="No tenants connected" />
              <div className="flex justify-center">{addTenantButton}</div>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
              {tenants.map((tenant) => (
                <div key={tenant.tenant_id} className="space-y-3">
                  <TenantCard
                    tenant={tenant}
                    onClick={() => {
                      setActiveTenantId(tenant.tenant_id);
                      router.push(`/tenants/${tenant.tenant_id}`);
                    }}
                  />
                  <div className="flex items-center gap-2 text-sm text-cyan-300">
                    <ShieldCheck size={14} />
                    Open tenant dashboard
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      ) : null}
    </div>
  );
}
