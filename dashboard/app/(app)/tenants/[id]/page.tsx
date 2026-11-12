"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, ReferenceLine } from "recharts";
import {
  ArrowLeft,
  RefreshCw,
  FileText,
  ShieldCheck,
  ShieldAlert,
  TrendingUp,
  Play,
  CheckCircle,
} from "lucide-react";
import {
  Card,
  StatCard,
  PageHeader,
  SeverityBadge,
  StatusBadge,
  ScoreRing,
  Button,
  TableSkeleton,
  ErrorState,
  EmptyState,
  FilterSelect,
} from "@/components/ui";
import { FindingGuidanceCard } from "@/components/data/renderers";
import { useExecutiveSummary, usePostureTrend, useComplianceResults } from "@/lib/api/hooks";
import { useAuth } from "@/lib/auth-context";
import type { Severity, DecisionStatus } from "@/types";
import * as ep from "@/lib/api/endpoints";
import { scoreBandAccent } from "@/utils/posture";

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export default function TenantDetailPage({ params }: { params: { id: string } }) {
  const tenantId = params.id;
  const router = useRouter();
  const { tenants, tenantId: activeTenantId, setActiveTenantId } = useAuth();

  const [severityFilter, setSeverityFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [scanLoading, setScanLoading] = useState(false);
  const hasAccess = tenants.some((tenant) => tenant.tenant_id === tenantId);

  useEffect(() => {
    if (activeTenantId !== tenantId && hasAccess) {
      setActiveTenantId(tenantId);
    }
  }, [activeTenantId, hasAccess, setActiveTenantId, tenantId]);

  const scopedTenantId = hasAccess ? tenantId : null;
  const summaryQuery = useExecutiveSummary();
  const trendQuery = usePostureTrend(scopedTenantId);
  const complianceQuery = useComplianceResults(scopedTenantId);

  if (!hasAccess) {
    return (
      <div className="space-y-6">
        <ErrorState message="Access denied" />
      </div>
    );
  }

  const isLoading = summaryQuery.loading || complianceQuery.loading;

  const summary = summaryQuery.data;
  const trend = trendQuery.data?.trend ?? [];
  const results = complianceQuery.data ?? [];

  const filtered = results
    .filter((r) => {
      if (severityFilter && r.severity !== severityFilter) return false;
      if (statusFilter && r.decision_status !== statusFilter) return false;
      return true;
    })
    .sort(
      (a, b) =>
        SEVERITY_ORDER.indexOf(a.severity as Severity) - SEVERITY_ORDER.indexOf(b.severity as Severity),
    );

  async function handleScan() {
    setScanLoading(true);
    try {
      await ep.runIdentityScan(tenantId);
      summaryQuery.refetch();
      complianceQuery.refetch();
    } catch {
      /* ignore */
    } finally {
      setScanLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-1">
        <Button variant="ghost" size="sm" onClick={() => router.push("/tenants")}>
          <ArrowLeft size={13} /> Back
        </Button>
      </div>

      <PageHeader
        title={summary?.tenant_name ?? `Tenant ${tenantId}`}
        subtitle={`Tenant ID: ${tenantId}`}
        actions={
          <>
            <Button variant="secondary" size="sm" loading={scanLoading} onClick={handleScan}>
              <RefreshCw size={13} className={scanLoading ? "animate-spin" : ""} /> Run Scan
            </Button>
            <Button variant="primary" size="sm" onClick={() => router.push("/reports")}>
              <FileText size={13} /> Generate Report
            </Button>
          </>
        }
      />

      {summaryQuery.error ? (
        <ErrorState message={summaryQuery.error} />
      ) : (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
            <StatCard
              label="Posture Score"
              value={isLoading ? "—" : (summary?.posture_score ?? "—")}
              sub="identity posture"
              accent={scoreBandAccent(summary?.score_band ?? null)}
              icon={<ShieldCheck size={18} />}
            />
            <StatCard
              label="Total Findings"
              value={isLoading ? "—" : (summary?.total_findings ?? "—")}
              sub="all severities"
              accent="text-gray-200"
              icon={<ShieldAlert size={18} />}
            />
            <StatCard
              label="Critical Findings"
              value={isLoading ? "—" : (summary?.critical_findings ?? "—")}
              sub="immediate action"
              accent="text-red-400"
            />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <Card className="p-6 flex flex-col items-center gap-4 lg:col-span-1">
              {isLoading ? (
                <TableSkeleton rows={3} cols={1} />
              ) : !summary ? null : (
                <>
                  <ScoreRing score={summary.posture_score ?? 0} scoreBand={summary.score_band ?? null} />
                  <div className="text-center">
                    <p className="text-sm font-semibold text-gray-200">{summary.tenant_name}</p>
                    <p className="text-xs text-gray-500 mt-0.5">
                      {summary.remediations_last_30_days} remediations in 30 days
                    </p>
                  </div>
                  {(summary?.top_risks?.length ?? 0) > 0 && (
                    <div className="w-full space-y-1.5">
                      <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
                        Top Risks
                      </p>
                      {(summary?.top_risks ?? []).map((r) => (
                        <div
                          key={r.control_id}
                          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-gray-800/50 text-xs text-gray-300"
                        >
                          <span className="w-1.5 h-1.5 rounded-full bg-red-400 shrink-0" />
                          {r.name}
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </Card>

            <Card className="p-5 lg:col-span-2">
              <p className="text-sm font-semibold text-gray-200 mb-4">Posture Score Trend — 30 Days</p>
              {trendQuery.loading ? (
                <TableSkeleton rows={3} cols={1} />
              ) : trendQuery.error ? (
                <ErrorState message={trendQuery.error} />
              ) : trend.length === 0 ? (
                <EmptyState message="No trend data available" />
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <AreaChart data={trend}>
                    <defs>
                      <linearGradient id="tGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.2} />
                        <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis
                      dataKey="date"
                      tick={{ fill: "#6b7280", fontSize: 10 }}
                      axisLine={false}
                      tickLine={false}
                      tickFormatter={(v) =>
                        new Date(v).toLocaleDateString("en-US", { month: "short", day: "numeric" })
                      }
                      interval={6}
                    />
                    <YAxis
                      domain={[40, 100]}
                      tick={{ fill: "#6b7280", fontSize: 10 }}
                      axisLine={false}
                      tickLine={false}
                      width={30}
                    />
                    <Tooltip
                      contentStyle={{
                        background: "#111827",
                        border: "1px solid #374151",
                        borderRadius: 8,
                        color: "#e5e7eb",
                        fontSize: 12,
                      }}
                    />
                    <ReferenceLine y={80} stroke="#22d3ee" strokeDasharray="4 4" strokeOpacity={0.3} />
                    <ReferenceLine y={60} stroke="#f87171" strokeDasharray="4 4" strokeOpacity={0.3} />
                    <Area
                      type="monotone"
                      dataKey="score"
                      stroke="#22d3ee"
                      strokeWidth={2}
                      fill="url(#tGrad)"
                      dot={false}
                      activeDot={{ r: 4 }}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </Card>
          </div>

          {/* Compliance findings */}
          <Card className="overflow-hidden">
            <div className="px-5 py-4 border-b border-gray-800 flex flex-col sm:flex-row sm:items-center gap-3 justify-between">
              <p className="text-sm font-semibold text-gray-200">
                Compliance Findings
                {!complianceQuery.loading && (
                  <span className="ml-2 text-xs text-gray-500 bg-gray-800 px-2 py-0.5 rounded-full">
                    {filtered.length}
                  </span>
                )}
              </p>
              <div className="flex flex-wrap gap-2">
                <FilterSelect
                  value={severityFilter}
                  onChange={setSeverityFilter}
                  options={SEVERITY_ORDER.map((s) => ({ label: s, value: s }))}
                  placeholder="All severities"
                />
                <FilterSelect
                  value={statusFilter}
                  onChange={setStatusFilter}
                  options={["PENDING", "APPROVED", "EXECUTED", "VERIFIED", "RESOLVED", "BLOCKED"].map(
                    (s) => ({ label: s, value: s }),
                  )}
                  placeholder="All statuses"
                />
              </div>
            </div>
            {complianceQuery.loading ? (
              <div className="p-5">
                <TableSkeleton rows={6} cols={5} />
              </div>
            ) : complianceQuery.error ? (
              <ErrorState message={complianceQuery.error} />
            ) : results.length === 0 ? (
              <EmptyState message="No compliance findings" />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-800">
                      {["Control", "Severity", "Status", "Result", "Guidance", "Actions"].map((h) => (
                        <th
                          key={h}
                          className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider whitespace-nowrap"
                        >
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800/50">
                    {filtered.length === 0 ? (
                      <tr>
                        <td colSpan={6}>
                          <EmptyState message="No findings match the selected filters" />
                        </td>
                      </tr>
                    ) : (
                      filtered.map((r) => {
                        return (
                          <tr key={r.id} className="hover:bg-gray-800/40 transition-colors">
                            <td className="px-5 py-3.5 font-mono text-xs text-gray-200">
                              {r.control_id.replace(/_/g, " ")}
                            </td>
                            <td className="px-5 py-3.5">
                              <SeverityBadge value={r.severity as Severity} />
                            </td>
                            <td className="px-5 py-3.5">
                              <StatusBadge value={r.decision_status as DecisionStatus} />
                            </td>
                            <td className="px-5 py-3.5">
                              <span
                                className={`text-xs font-semibold ${r.passed ? "text-green-400" : "text-red-400"}`}
                              >
                                {r.passed ? "✓ Pass" : "✗ Fail"}
                              </span>
                            </td>
                            <td className="max-w-[360px] px-5 py-3.5 align-top">
                              <FindingGuidanceCard guidance={r?.guidance} />
                            </td>
                            <td className="px-5 py-3.5">
                              {!r.passed && r.decision_status === "PENDING" && (
                                <Button
                                  variant="primary"
                                  size="sm"
                                  onClick={() =>
                                    ep
                                      .approveByResult(String(r.id), tenantId)
                                      .then(() => complianceQuery.refetch())
                                      .catch(() => {})
                                  }
                                >
                                  <CheckCircle size={11} /> Approve
                                </Button>
                              )}
                              {!r.passed && r.decision_status === "APPROVED" && (
                                <Button
                                  variant="primary"
                                  size="sm"
                                  onClick={() =>
                                    ep
                                      .executeRemediation(String(r.id), tenantId)
                                      .then(() => complianceQuery.refetch())
                                      .catch(() => {})
                                  }
                                >
                                  <Play size={11} /> Execute
                                </Button>
                              )}
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
