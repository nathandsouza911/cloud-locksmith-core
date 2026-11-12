"use client";

import { Download, Receipt, RefreshCw, Wallet, Zap } from "lucide-react";

import { Button, Card, EmptyState, ErrorState, PageHeader, TableSkeleton } from "@/components/ui";
import type { LicenseFinding, LicenseSummary } from "@/types";

function formatCurrency(amount: number, currency = "USD") {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
    maximumFractionDigits: 0,
  }).format(amount);
}

function humanizeKey(value: string) {
  return value
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function issueLabel(type: LicenseFinding["type"]) {
  if (type === "inactive_user") return "Inactive User";
  if (type === "overlicensed_user") return "Overlicensed User";
  return "Unused License";
}

function recommendedAction(finding: LicenseFinding) {
  const explicit = finding.metadata?.recommended_action;
  if (typeof explicit === "string" && explicit.trim()) {
    return explicit;
  }
  if (finding.type === "inactive_user") return "Remove or reassign the license";
  if (finding.type === "overlicensed_user") return "Downgrade to a lower-cost plan";
  return "Reduce purchased seats or reassign them";
}

function findingUser(finding: LicenseFinding) {
  if (finding.type === "unused_license") return "Unassigned seat pool";
  const displayName = finding.metadata?.display_name;
  if (typeof displayName === "string" && displayName.trim()) return displayName;
  const email = finding.metadata?.email;
  if (typeof email === "string" && email.trim()) return email;
  return finding.user_id ?? "Unknown user";
}

function findingLicense(finding: LicenseFinding) {
  return humanizeKey(finding.license_type);
}

interface CostOptimizationViewProps {
  title: string;
  subtitle: string;
  summary: LicenseSummary | null;
  findings: LicenseFinding[];
  loading?: boolean;
  error?: string | null;
  onDownloadReport: () => Promise<void> | void;
  onRefreshScan?: () => Promise<void> | void;
  reportLoading?: boolean;
  scanLoading?: boolean;
  findingsLimit?: number;
  compactHeader?: boolean;
}

export function CostOptimizationView({
  title,
  subtitle,
  summary,
  findings,
  loading = false,
  error = null,
  onDownloadReport,
  onRefreshScan,
  reportLoading = false,
  scanLoading = false,
  findingsLimit,
  compactHeader = false,
}: CostOptimizationViewProps) {
  const currency = summary?.currency ?? "USD";
  const visibleFindings = findingsLimit ? findings.slice(0, findingsLimit) : findings;

  return (
    <div className="space-y-6">
      <PageHeader
        title={title}
        subtitle={subtitle}
        actions={
          <>
            {onRefreshScan ? (
              <Button variant="secondary" size="sm" loading={scanLoading} onClick={onRefreshScan}>
                <RefreshCw size={13} />
                Refresh Scan
              </Button>
            ) : null}
            <Button variant="primary" size="sm" loading={reportLoading} onClick={onDownloadReport}>
              <Download size={13} />
              Download Report
            </Button>
          </>
        }
      />

      {error ? <ErrorState message={error} /> : null}

      <Card
        className={`${compactHeader ? "p-6" : "p-8"} overflow-hidden border-emerald-500/20 bg-[radial-gradient(circle_at_top_left,rgba(22,163,74,0.18),transparent_32%),linear-gradient(160deg,rgba(17,24,39,0.98),rgba(3,7,18,0.94))]`}
      >
        {loading ? (
          <div className="space-y-4">
            <div className="h-5 w-40 animate-pulse rounded bg-gray-800" />
            <div className="h-12 w-64 animate-pulse rounded bg-gray-800" />
            <div className="h-4 w-48 animate-pulse rounded bg-gray-800" />
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.28em] text-emerald-300/80">
              <Wallet size={14} />
              License Waste
            </div>
            <div className="text-4xl font-semibold tracking-tight text-white sm:text-5xl">
              {formatCurrency(summary?.total_waste ?? 0, currency)}
              <span className="ml-2 text-lg font-normal text-gray-400">/month wasted</span>
            </div>
            <p className="max-w-2xl text-sm text-gray-400">
              Focus on inactive accounts, premium overspend, and licenses you paid for but never assigned.
            </p>
          </div>
        )}
      </Card>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card className="p-5">
          <div className="flex items-center justify-between">
            <p className="text-xs font-semibold uppercase tracking-[0.24em] text-gray-500">Inactive Users</p>
            <Receipt size={15} className="text-amber-400" />
          </div>
          <p className="mt-4 text-3xl font-semibold text-white">
            {loading ? "..." : formatCurrency(summary?.inactive_users_cost ?? 0, currency)}
          </p>
        </Card>
        <Card className="p-5">
          <div className="flex items-center justify-between">
            <p className="text-xs font-semibold uppercase tracking-[0.24em] text-gray-500">
              Overlicensed Users
            </p>
            <Zap size={15} className="text-cyan-400" />
          </div>
          <p className="mt-4 text-3xl font-semibold text-white">
            {loading ? "..." : formatCurrency(summary?.overlicensed_cost ?? 0, currency)}
          </p>
        </Card>
        <Card className="p-5">
          <div className="flex items-center justify-between">
            <p className="text-xs font-semibold uppercase tracking-[0.24em] text-gray-500">Unused Licenses</p>
            <Wallet size={15} className="text-emerald-400" />
          </div>
          <p className="mt-4 text-3xl font-semibold text-white">
            {loading ? "..." : formatCurrency(summary?.unused_license_cost ?? 0, currency)}
          </p>
        </Card>
      </div>

      <Card className="overflow-hidden">
        <div className="border-b border-gray-800 px-5 py-4">
          <p className="text-sm font-semibold text-gray-200">License Findings</p>
        </div>
        {loading ? (
          <div className="p-5">
            <TableSkeleton rows={5} cols={5} />
          </div>
        ) : visibleFindings.length === 0 ? (
          <EmptyState message="No license waste findings yet. Run a scan to populate this view." />
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead className="bg-gray-900/80 text-left">
                <tr className="text-xs uppercase tracking-[0.2em] text-gray-500">
                  <th className="px-5 py-3 font-medium">User</th>
                  <th className="px-5 py-3 font-medium">License</th>
                  <th className="px-5 py-3 font-medium">Issue Type</th>
                  <th className="px-5 py-3 font-medium">Estimated Cost</th>
                  <th className="px-5 py-3 font-medium">Recommended Action</th>
                </tr>
              </thead>
              <tbody>
                {visibleFindings.map((finding) => (
                  <tr key={finding.id} className="border-t border-gray-800 text-sm text-gray-200">
                    <td className="px-5 py-4">
                      <div className="font-medium text-white">{findingUser(finding)}</div>
                      {typeof finding.metadata?.email === "string" && finding.type !== "unused_license" ? (
                        <div className="mt-1 text-xs text-gray-500">{finding.metadata.email}</div>
                      ) : null}
                    </td>
                    <td className="px-5 py-4 text-gray-300">{findingLicense(finding)}</td>
                    <td className="px-5 py-4 text-gray-300">{issueLabel(finding.type)}</td>
                    <td className="px-5 py-4 font-semibold text-emerald-300">
                      {formatCurrency(finding.estimated_monthly_cost, finding.currency)}
                    </td>
                    <td className="px-5 py-4 text-gray-400">{recommendedAction(finding)}</td>
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
