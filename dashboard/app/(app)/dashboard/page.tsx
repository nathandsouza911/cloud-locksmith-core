"use client";

import { useMemo } from "react";
import { useRouter } from "next/navigation";
import { AlertTriangle, RefreshCw, Shield, ShieldCheck, ShieldQuestion, WandSparkles } from "lucide-react";

import { Button, Card, ErrorState, PageHeader, StatCard, TableSkeleton } from "@/components/ui";
import { useComplianceResults, useOverview } from "@/lib/api/hooks";
import { startMicrosoftOAuth } from "@/lib/auth";
import { useAuth } from "@/lib/auth-context";
import type { ComplianceResult, Severity } from "@/types";
import { scoreBandAccent } from "@/utils/posture";

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
  const { tenants: linkedTenants, tenantId } = useAuth();
  const overviewQuery = useOverview();
  const complianceQuery = useComplianceResults(tenantId);

  const activeTenant = linkedTenants.find((tenant) => tenant.tenant_id === tenantId) ?? null;
  // /api/v1/overview covers only the session tenant.
  const activeTenantPosture = overviewQuery.data?.tenants.find((t) => t.tenant_id === tenantId) ?? null;
  const complianceRefetch = complianceQuery.refetch;
  const overviewRefetch = overviewQuery.refetch;
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

  function refetchAll() {
    overviewRefetch();
    complianceRefetch();
  }

  function handleTenantFindingAction(finding: ComplianceResult) {
    router.push(`/risk-feed?tenant_id=${tenantId ?? ""}`);
  }

  const connectButton = (
    <Button
      variant="primary"
      size="sm"
      onClick={() => {
        startMicrosoftOAuth("smb_onboarding");
      }}
    >
      Connect Tenant
    </Button>
  );

  if (linkedTenants.length === 0) {
    return (
      <div className="space-y-6">
        <PageHeader title="Dashboard" subtitle="No tenant connected yet" actions={connectButton} />
        <Card className="p-10">
          <div className="flex flex-col items-center justify-center py-12 text-gray-500">
            <p className="text-lg text-gray-300">No tenant connected</p>
            <p className="mt-2 text-sm">Connect your Microsoft tenant to start scanning posture data.</p>
            <div className="mt-5">{connectButton}</div>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        subtitle={activeTenant ? `${activeTenant.tenant_name} is ready for review` : "Select a tenant"}
        actions={
          <Button variant="secondary" size="sm" onClick={refetchAll}>
            <RefreshCw size={13} className={overviewQuery.loading ? "animate-spin" : ""} />
            Refresh
          </Button>
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

          {/* Posture Score — visible once the overview loads */}
          {!overviewQuery.loading && activeTenantPosture ? (
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
      </div>
    </div>
  );
}
