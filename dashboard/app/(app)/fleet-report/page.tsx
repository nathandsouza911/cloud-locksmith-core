"use client";

import React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { TrendingUp, TrendingDown, Minus, AlertTriangle, ShieldCheck } from "lucide-react";
import { Card, ErrorState, PageHeader, TableSkeleton } from "@/components/ui";
import { useAuth } from "@/lib/auth-context";
import { useFleetPosture, useFleetOverview } from "@/lib/api/hooks";

// ── Insurance readiness proxy from score_band ─────────────────────────────────
// No fleet-level insurance endpoint exists; we derive readiness from posture band.
// This mirrors the per-tenant insurance_readiness service logic.

type ScoreBand = "GOOD" | "MODERATE" | "HIGH" | "CRITICAL" | null;

const INSURANCE_LABEL: Record<string, string> = {
  GOOD: "Insurable",
  MODERATE: "Conditional",
  HIGH: "High Risk",
  CRITICAL: "Not Insurable",
};

const INSURANCE_CLASS: Record<string, string> = {
  GOOD: "text-green-400",
  MODERATE: "text-yellow-400",
  HIGH: "text-orange-400",
  CRITICAL: "text-red-400",
};

const BAND_CLASS: Record<string, string> = {
  GOOD: "bg-green-900/50 text-green-300",
  MODERATE: "bg-yellow-900/50 text-yellow-300",
  HIGH: "bg-orange-900/50 text-orange-300",
  CRITICAL: "bg-red-900/60 text-red-300",
};

const SEVERITY_CLASS: Record<string, string> = {
  CRITICAL: "text-red-400",
  HIGH: "text-orange-400",
  MEDIUM: "text-yellow-400",
  LOW: "text-blue-400",
  INFO: "text-gray-400",
};

// ── Trend delta display ───────────────────────────────────────────────────────

function TrendDelta({ delta }: { delta: number | null }) {
  if (delta === null || delta === undefined) {
    return <span className="text-gray-500 text-xs">—</span>;
  }
  if (delta > 0) {
    return (
      <span className="flex items-center gap-1 text-green-400 text-xs font-semibold">
        <TrendingUp size={12} />
        {`+${delta}`}
      </span>
    );
  }
  if (delta < 0) {
    return (
      <span className="flex items-center gap-1 text-red-400 text-xs font-semibold">
        <TrendingDown size={12} />
        {`${delta}`}
      </span>
    );
  }
  return (
    <span className="flex items-center gap-1 text-gray-500 text-xs">
      <Minus size={12} />0
    </span>
  );
}

// ── Score band badge ──────────────────────────────────────────────────────────

function BandBadge({ band }: { band: ScoreBand }) {
  if (!band) return <span className="text-gray-500 text-xs">—</span>;
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded-full text-xs font-semibold ${BAND_CLASS[band] ?? "bg-gray-700 text-gray-300"}`}
    >
      {band.charAt(0) + band.slice(1).toLowerCase()}
    </span>
  );
}

// ── Stat card ─────────────────────────────────────────────────────────────────

function StatCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <Card className="p-5">
      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">{label}</p>
      <p className="text-2xl font-bold text-white">{value}</p>
      {sub && <p className="text-xs text-gray-500 mt-1">{sub}</p>}
    </Card>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function FleetReportPage() {
  const { isSmb } = useAuth();
  const router = useRouter();

  const postureQuery = useFleetPosture();
  const overviewQuery = useFleetOverview();

  if (isSmb) {
    router.replace("/dashboard");
    return null;
  }

  if (postureQuery.loading || overviewQuery.loading) {
    return <TableSkeleton rows={8} />;
  }

  if (postureQuery.error) {
    return <ErrorState message={postureQuery.error} />;
  }

  const posture = postureQuery.data;
  const overview = overviewQuery.data;

  // Build a map from tenant_id → overview data for joining
  const overviewByTenant = new Map((overview?.tenants ?? []).map((t: any) => [t.tenant_id, t]));

  const tenants = posture?.tenants ?? [];

  return (
    <div className="space-y-6">
      <PageHeader title="Fleet Report" subtitle={`${posture?.fleet_size ?? 0} tenants · as of today`} />

      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Tenants" value={posture?.fleet_size ?? 0} sub="scored tenants" />
        <StatCard
          label="Avg Posture Score"
          value={posture?.fleet_avg_score != null ? Math.round(posture.fleet_avg_score) : "—"}
          sub="fleet average"
        />
        <StatCard
          label="Critical Findings"
          value={overview?.aggregate?.total_critical ?? "—"}
          sub="across fleet"
        />
        <StatCard
          label="Avg Risk Band"
          value={overview?.aggregate?.avg_risk_band ?? "—"}
          sub="fleet risk level"
        />
      </div>

      {/* Risk ranking table */}
      <Card className="p-5 space-y-4">
        <h2 className="text-sm font-semibold text-gray-200 uppercase tracking-wider">Risk Ranking</h2>
        <p className="text-xs text-gray-500">Tenants ordered by posture score — lowest (worst) first.</p>

        {tenants.length === 0 ? (
          <p className="text-sm text-gray-500">
            No tenant data available. Connect tenants and run a scan first.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  {[
                    "Tenant",
                    "Score",
                    "Band",
                    "7d Trend",
                    "Insurance Readiness",
                    "Failed Controls",
                    "Critical Findings",
                    "MFA Coverage",
                  ].map((h) => (
                    <th
                      key={h}
                      className="px-4 py-2 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider whitespace-nowrap"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {tenants.map((tenant: any) => {
                  const ov = overviewByTenant.get(tenant.tenant_id) as any;
                  const insuranceLabel = tenant.score_band
                    ? (INSURANCE_LABEL[tenant.score_band] ?? "Unknown")
                    : "—";
                  const insuranceCls = tenant.score_band
                    ? (INSURANCE_CLASS[tenant.score_band] ?? "text-gray-400")
                    : "text-gray-500";

                  return (
                    <tr
                      key={tenant.tenant_id}
                      className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors"
                    >
                      <td className="px-4 py-3">
                        <Link
                          href="/tenants"
                          className="text-cyan-400 hover:text-cyan-300 font-medium text-sm transition-colors"
                        >
                          {tenant.tenant_name}
                        </Link>
                      </td>
                      <td className="px-4 py-3 text-sm font-mono text-gray-200">
                        {tenant.posture_score ?? "—"}
                      </td>
                      <td className="px-4 py-3">
                        <BandBadge band={tenant.score_band} />
                      </td>
                      <td className="px-4 py-3">
                        <TrendDelta delta={tenant.score_delta_7d} />
                      </td>
                      <td className={`px-4 py-3 text-xs font-semibold ${insuranceCls}`}>{insuranceLabel}</td>
                      <td className="px-4 py-3 text-sm tabular-nums text-gray-300">
                        {tenant.failed_controls ?? "—"}
                      </td>
                      <td className="px-4 py-3 text-sm tabular-nums text-gray-300">
                        {ov?.critical_findings ?? "—"}
                      </td>
                      <td className="px-4 py-3 text-sm tabular-nums text-gray-300">
                        {ov?.mfa_coverage != null ? `${ov.mfa_coverage}%` : "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Top fleet risks */}
      {overview?.top_risks && overview.top_risks.length > 0 && (
        <Card className="p-5 space-y-4">
          <div className="flex items-center gap-2">
            <AlertTriangle size={15} className="text-red-400" />
            <h2 className="text-sm font-semibold text-gray-200 uppercase tracking-wider">Top Fleet Risks</h2>
          </div>
          <p className="text-xs text-gray-500">Highest-severity unresolved findings across all tenants.</p>

          <div className="space-y-2">
            {overview.top_risks.map((risk: any, i: number) => (
              <div
                key={`${risk.tenant_id}-${risk.control_id}-${i}`}
                className="flex items-start gap-4 rounded-lg bg-gray-800/40 px-4 py-3"
              >
                <span
                  className={`text-xs font-bold uppercase tracking-wider mt-0.5 w-16 shrink-0 ${SEVERITY_CLASS[risk.severity] ?? "text-gray-400"}`}
                >
                  {risk.severity}
                </span>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-200 font-mono">{risk.control_id}</p>
                  <p className="text-xs text-gray-500 mt-0.5">
                    {risk.tenant_name} · {risk.resource_id}
                  </p>
                </div>
                <Link
                  href="/tenants"
                  className="text-xs text-cyan-500 hover:text-cyan-400 transition-colors shrink-0 mt-0.5"
                >
                  View tenant
                </Link>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
