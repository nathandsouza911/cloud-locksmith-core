"use client";

import { Fragment, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Download, Info, RefreshCw } from "lucide-react";

import { Button, Card, EmptyState, ErrorState, PageHeader, StatCard, TableSkeleton } from "@/components/ui";
import * as ep from "@/lib/api/endpoints";
import type { CoverageResult, CoverageStatus, CoverageUser } from "@/lib/api/endpoints";
import { useCaCoverage } from "@/lib/api/hooks";
import { COVERAGE_QUESTIONS, coverageStatusLabel, filterCoverageUsers } from "@/lib/ca-coverage";

const STATUS_CLASSES: Record<CoverageStatus, string> = {
  covered: "border-green-500/30 bg-green-500/10 text-green-300",
  report_only: "border-yellow-500/30 bg-yellow-500/10 text-yellow-300",
  gap: "border-red-500/30 bg-red-500/10 text-red-300",
  not_applicable: "border-gray-700 bg-gray-800/40 text-gray-500",
};

function StatusPill({ status }: { status: CoverageStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold ${STATUS_CLASSES[status]}`}
    >
      {coverageStatusLabel(status)}
    </span>
  );
}

function Tag({ children }: { children: React.ReactNode }) {
  return (
    <span className="rounded border border-gray-700 px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-gray-400">
      {children}
    </span>
  );
}

function ResultDetail({ label, result }: { label: string; result: CoverageResult }) {
  if (result.status === "not_applicable") return null;
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2">
        <p className="text-xs font-semibold text-gray-300">{label}</p>
        <StatusPill status={result.status} />
      </div>
      {result.policies.length > 0 ? (
        <p className="text-xs text-gray-400">
          {result.status === "report_only" ? "Would be covered if enforced: " : "Covered by: "}
          {result.policies.join(", ")}
        </p>
      ) : null}
      {result.reasons.length > 0 ? (
        <ul className="list-disc space-y-0.5 pl-5 text-xs text-gray-400">
          {result.reasons.map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

async function downloadCsv() {
  const text = await ep.getCaCoverageCsv();
  const url = URL.createObjectURL(new Blob([text], { type: "text/csv" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "ca-coverage.csv";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

export default function CaCoveragePage() {
  const coverage = useCaCoverage();
  const [gapsOnly, setGapsOnly] = useState(true);
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  const report = coverage.data;
  const users = useMemo(
    () => filterCoverageUsers(report?.users ?? [], { gapsOnly, search }),
    [report, gapsOnly, search],
  );

  async function handleExport() {
    setExporting(true);
    setExportError(null);
    try {
      await downloadCsv();
    } catch (error) {
      setExportError(error instanceof Error ? error.message : "Export failed");
    } finally {
      setExporting(false);
    }
  }

  function statSub(counts: ep.CoverageCounts, total: number) {
    return `${counts.report_only ?? 0} report-only · ${counts.covered ?? 0} covered of ${total}`;
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Conditional Access Coverage"
        subtitle="For every user: is MFA required, is legacy authentication blocked — and if not, which policy leaves them out"
        actions={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={handleExport}
              loading={exporting}
              disabled={!report}
            >
              <Download size={13} /> Export CSV
            </Button>
            <Button variant="secondary" size="sm" onClick={coverage.refetch} loading={coverage.loading}>
              <RefreshCw size={13} /> Refresh
            </Button>
          </>
        }
      />

      {exportError ? <ErrorState message={exportError} /> : null}

      {coverage.loading && !report ? (
        <Card className="p-5">
          <TableSkeleton rows={8} cols={4} />
        </Card>
      ) : coverage.error ? (
        <ErrorState message={coverage.error} />
      ) : report ? (
        <>
          {report.security_defaults_enabled ? (
            <Card className="border-cyan-500/30 bg-cyan-500/10 px-4 py-3 text-sm text-cyan-100">
              Security defaults are on: they require MFA and block legacy authentication for every user, and
              Conditional Access policies cannot be enforced while they stay on.
            </Card>
          ) : null}

          <div className="grid gap-4 sm:grid-cols-3">
            <StatCard
              label="MFA gaps"
              value={report.summary.mfa.gap ?? 0}
              sub={statSub(report.summary.mfa, report.summary.users)}
              accent="text-red-300"
            />
            <StatCard
              label="Legacy auth gaps"
              value={report.summary.legacy_auth.gap ?? 0}
              sub={statSub(report.summary.legacy_auth, report.summary.users)}
              accent="text-red-300"
            />
            <StatCard
              label="Admin MFA gaps"
              value={report.summary.admin_mfa.gap ?? 0}
              sub={statSub(
                report.summary.admin_mfa,
                report.summary.users - (report.summary.admin_mfa.not_applicable ?? 0),
              )}
              accent="text-red-300"
            />
          </div>

          <Card className="overflow-hidden">
            <div className="flex flex-col gap-3 border-b border-gray-800 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
              <label className="flex items-center gap-2 text-sm text-gray-300">
                <input
                  type="checkbox"
                  checked={gapsOnly}
                  onChange={(event) => setGapsOnly(event.target.checked)}
                  className="h-4 w-4 accent-cyan-500"
                />
                Only users with a gap or report-only result
              </label>
              <input
                type="search"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search name or UPN"
                aria-label="Search users"
                className="w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-1.5 text-sm text-gray-200 placeholder:text-gray-500 sm:w-64"
              />
            </div>

            {users.length === 0 ? (
              <EmptyState message={gapsOnly ? "No users with gaps match" : "No users match"} />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-800 text-left text-[11px] uppercase tracking-wider text-gray-500">
                      <th className="px-5 py-3 font-medium">User</th>
                      {COVERAGE_QUESTIONS.map(({ key, label }) => (
                        <th key={key} className="px-3 py-3 font-medium">
                          {label}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {users.map((user: CoverageUser) => {
                      const open = expanded === user.id;
                      return (
                        <Fragment key={user.id}>
                          <tr
                            className="cursor-pointer border-b border-gray-800/60 hover:bg-gray-900/60"
                            onClick={() => setExpanded(open ? null : user.id)}
                            aria-expanded={open}
                          >
                            <td className="px-5 py-3">
                              <div className="flex items-start gap-2">
                                {open ? (
                                  <ChevronDown size={14} className="mt-0.5 text-gray-500" />
                                ) : (
                                  <ChevronRight size={14} className="mt-0.5 text-gray-500" />
                                )}
                                <div>
                                  <p className="font-medium text-gray-100">{user.display_name ?? user.id}</p>
                                  <p className="text-xs text-gray-500">{user.user_principal_name}</p>
                                  <div className="mt-1 flex gap-1">
                                    {user.is_admin ? <Tag>Admin</Tag> : null}
                                    {user.is_guest ? <Tag>Guest</Tag> : null}
                                    {!user.enabled ? <Tag>Disabled</Tag> : null}
                                  </div>
                                </div>
                              </div>
                            </td>
                            {COVERAGE_QUESTIONS.map(({ key }) => (
                              <td key={key} className="px-3 py-3 align-top">
                                <StatusPill status={user[key].status} />
                              </td>
                            ))}
                          </tr>
                          {open ? (
                            <tr className="border-b border-gray-800/60 bg-gray-950/50">
                              <td colSpan={4} className="space-y-3 px-5 py-4 pl-11">
                                {COVERAGE_QUESTIONS.map(({ key, label }) => (
                                  <ResultDetail key={key} label={label} result={user[key]} />
                                ))}
                              </td>
                            </tr>
                          ) : null}
                        </Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          <Card className="space-y-2 px-5 py-4 text-xs text-gray-400">
            <p className="flex items-center gap-2 font-semibold text-gray-300">
              <Info size={13} /> What this does not evaluate
            </p>
            <p>{report.disclaimer}</p>
            <ul className="list-disc space-y-0.5 pl-5">
              {report.limits.map((limit) => (
                <li key={limit}>{limit}</li>
              ))}
            </ul>
          </Card>
        </>
      ) : null}
    </div>
  );
}
