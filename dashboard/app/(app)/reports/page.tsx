"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  FileBarChart2,
  Download,
  ExternalLink,
  ShieldCheck,
  AlertOctagon,
  TrendingUp,
  FileText,
  RefreshCw,
  BadgeCheck,
} from "lucide-react";
import { Card, StatCard, PageHeader, Button, EmptyState, TableSkeleton, ErrorState } from "@/components/ui";
import PostureChart from "@/components/charts/PostureChart";
import { useExecutiveSummary, useEvidenceReports, usePostureTimeline } from "@/lib/api/hooks";
import { useAuth } from "@/lib/auth-context";
import * as ep from "@/lib/api/endpoints";
import { calculateTrend, getLast14Days, scoreBandAccent } from "@/utils/posture";

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

const BAND_COLOR: Record<string, string> = {
  GOOD: "text-green-400",
  MODERATE: "text-yellow-400",
  POOR: "text-red-400",
};

const BAND_LABEL: Record<string, string> = {
  GOOD: "Good",
  MODERATE: "Needs Attention",
  POOR: "Needs Attention",
};

export default function ReportsPage() {
  const { tenantId } = useAuth();
  const router = useRouter();
  const [generating, setGenerating] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);
  const [dateFilter, setDateFilter] = useState("");

  const summaryQuery = useExecutiveSummary();
  const reportsQuery = useEvidenceReports();
  const timelineQuery = usePostureTimeline(tenantId);

  const summary = summaryQuery.data;
  const reports = useMemo(
    () =>
      [...(reportsQuery.data ?? [])].sort((left, right) =>
        right.generated_at.localeCompare(left.generated_at),
      ),
    [reportsQuery.data],
  );
  const postureWindow = useMemo(() => getLast14Days(timelineQuery.data ?? []), [timelineQuery.data]);
  const trendSummary = useMemo(() => calculateTrend(timelineQuery.data ?? []), [timelineQuery.data]);
  const hasTrendData = postureWindow.some((point) => point.score !== null);

  const filteredReports = dateFilter
    ? reports.filter((report) => report.generated_at.startsWith(dateFilter.slice(0, 7)))
    : reports;

  async function handleRegeneratePDF() {
    setGenerating(true);
    setReportError(null);
    try {
      const blob = await ep.downloadEvidenceReportPdf();
      const url = URL.createObjectURL(blob);
      window.open(url, "_blank");
      reportsQuery.refetch();
    } catch (error) {
      console.error("PDF generation failed:", error);
      setReportError(error instanceof Error ? error.message : "Unable to generate evidence report PDF");
    } finally {
      setGenerating(false);
    }
  }

  async function handleDownloadArchived(reportPayloadId: number) {
    setReportError(null);
    try {
      const blob = await ep.downloadArchivedReportPdf(reportPayloadId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "cloud-locksmith-evidence-report.pdf";
      a.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error("Archived PDF download failed:", error);
      setReportError(error instanceof Error ? error.message : "Unable to download report");
    }
  }

  async function handleCyberInsurancePDF() {
    try {
      setReportError(null);
      const blob = await ep.getCyberInsurancePdf();
      window.open(URL.createObjectURL(blob), "_blank");
    } catch (error) {
      console.error("Cyber insurance PDF failed:", error);
      setReportError(error instanceof Error ? error.message : "Unable to generate cyber insurance PDF");
    }
  }

  async function handleVerifyIntegrity() {
    setVerifying(true);
    setReportError(null);
    try {
      const archived = await ep.getArchivedReportJson();
      router.push(`/reports/${archived.report_id}`);
    } catch (error) {
      setReportError(error instanceof Error ? error.message : "No archived report found to verify");
    } finally {
      setVerifying(false);
    }
  }

  function refetchAll() {
    summaryQuery.refetch();
    reportsQuery.refetch();
    timelineQuery.refetch();
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Reports"
        subtitle="Executive summaries and evidence reports"
        actions={
          <>
            <Button variant="secondary" size="sm" onClick={refetchAll}>
              <RefreshCw
                size={13}
                className={summaryQuery.loading || timelineQuery.loading ? "animate-spin" : ""}
              />
            </Button>
            <Button variant="ghost" size="sm" loading={verifying} onClick={handleVerifyIntegrity}>
              <BadgeCheck size={13} /> {verifying ? "Loading…" : "Verify Integrity"}
            </Button>
            <Button variant="primary" size="sm" loading={generating} onClick={handleRegeneratePDF}>
              <FileText size={13} /> {generating ? "Generating..." : "Regenerate Report"}
            </Button>
          </>
        }
      />

      {reportError ? <ErrorState message={reportError} /> : null}

      {summaryQuery.loading ? (
        <div className="h-24">
          <TableSkeleton rows={1} cols={4} />
        </div>
      ) : summaryQuery.error ? (
        <ErrorState message="Unable to load data. Please try again." />
      ) : !summary ? null : (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard
            label="Posture Score"
            value={summary.posture_score ?? "-"}
            sub={summary.tenant_name}
            accent={scoreBandAccent(summary.score_band ?? null)}
            icon={<ShieldCheck size={18} />}
          />
          <StatCard
            label="Total Findings"
            value={summary.total_findings}
            sub="all severities"
            accent="text-gray-200"
            icon={<FileBarChart2 size={18} />}
          />
          <StatCard
            label="Critical Findings"
            value={summary.critical_findings}
            sub="immediate action required"
            accent="text-red-400"
            icon={<AlertOctagon size={18} />}
          />
          <StatCard
            label="Remediations (30d)"
            value={summary.remediations_last_30_days}
            sub="last 30 days"
            accent="text-green-400"
            icon={<TrendingUp size={18} />}
          />
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="p-5 lg:col-span-2">
          <div className="mb-4 flex flex-col gap-2">
            <p className="text-sm font-semibold text-gray-200">Posture Trend - Report Context</p>
            <div className="flex flex-wrap items-center gap-3 text-sm">
              <span
                className={`font-semibold ${
                  trendSummary.label === "Improving"
                    ? "text-emerald-300"
                    : trendSummary.label === "Declining"
                      ? "text-red-300"
                      : "text-gray-300"
                }`}
              >
                {trendSummary.label}
              </span>
              <span className="text-gray-400">{trendSummary.summary}</span>
            </div>
          </div>
          {timelineQuery.loading ? (
            <TableSkeleton rows={3} cols={1} />
          ) : timelineQuery.error ? (
            <ErrorState message="Unable to load data. Please try again." />
          ) : !hasTrendData ? (
            <EmptyState message="Not enough data yet. Run a scan to generate posture history." />
          ) : (
            <PostureChart data={postureWindow} height={200} showGrid />
          )}
        </Card>

        <Card className="flex flex-col gap-4 p-5">
          <p className="text-sm font-semibold text-gray-200">Export Reports</p>
          <div className="flex flex-col gap-3">
            <Button
              variant="primary"
              size="sm"
              className="justify-center"
              loading={generating}
              onClick={handleRegeneratePDF}
            >
              <Download size={13} /> Evidence Report PDF
            </Button>
            <Button
              variant="secondary"
              size="sm"
              className="justify-center"
              onClick={handleCyberInsurancePDF}
            >
              <ExternalLink size={13} /> Cyber Insurance PDF
            </Button>
          </div>
          {summary && (summary.top_risks?.length ?? 0) > 0 ? (
            <div className="mt-2 space-y-1.5">
              <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">Top Risks</p>
              {(summary.top_risks ?? []).map((risk, i) => {
                const label = risk.short_name || risk.name || risk.control_id;
                return (
                  <div key={risk.control_id || i} className="flex items-center gap-2 text-xs text-red-400">
                    <span className="h-1 w-1 shrink-0 rounded-full bg-red-400" />
                    {label}
                  </div>
                );
              })}
            </div>
          ) : null}
        </Card>
      </div>

      <Card className="overflow-hidden">
        <div className="flex flex-col justify-between gap-3 border-b border-gray-800 px-5 py-4 sm:flex-row sm:items-center">
          <p className="text-sm font-semibold text-gray-200">Evidence Report History</p>
          <div className="flex items-center gap-3">
            <input
              type="month"
              value={dateFilter}
              onChange={(event) => setDateFilter(event.target.value)}
              className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-gray-300 outline-none transition-colors focus:border-cyan-500"
            />
            {dateFilter ? (
              <Button variant="ghost" size="sm" onClick={() => setDateFilter("")}>
                Clear
              </Button>
            ) : null}
          </div>
        </div>

        {reportsQuery.loading ? (
          <div className="p-5">
            <TableSkeleton rows={3} cols={5} />
          </div>
        ) : reportsQuery.error ? (
          <ErrorState message="Unable to load data. Please try again." />
        ) : reports.length === 0 ? (
          <EmptyState message="No reports generated yet. Generate your first evidence report to get started." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  {["Report Date", "Period", "Score", "Status", "Generated", "Actions"].map((heading) => (
                    <th
                      key={heading}
                      className="whitespace-nowrap px-5 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-400"
                    >
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/50">
                {filteredReports.length === 0 ? (
                  <tr>
                    <td colSpan={6}>
                      <EmptyState message="No reports found for the selected period" />
                    </td>
                  </tr>
                ) : (
                  filteredReports.map((report) => (
                    <tr key={report.report_id} className="transition-colors hover:bg-gray-800/40">
                      <td className="px-5 py-3.5 font-medium text-gray-200">
                        {formatDate(report.generated_at)}
                      </td>
                      <td className="px-5 py-3.5 font-medium text-gray-200">{report.reporting_period}</td>
                      <td className="px-5 py-3.5 font-bold tabular-nums text-white">{report.score}</td>
                      <td className="px-5 py-3.5">
                        <span
                          className={`text-xs font-semibold ${BAND_COLOR[report.score_band] ?? "text-gray-400"}`}
                        >
                          {BAND_LABEL[report.score_band] ?? report.score_band}
                        </span>
                      </td>
                      <td className="px-5 py-3.5 text-xs text-gray-500">{formatDate(report.generated_at)}</td>
                      <td className="px-5 py-3.5">
                        <div className="flex gap-1.5">
                          {report.report_payload_id != null ? (
                            <Button
                              variant="secondary"
                              size="sm"
                              onClick={() => handleDownloadArchived(report.report_payload_id!)}
                              title="Download this report"
                            >
                              <Download size={11} /> Download
                            </Button>
                          ) : (
                            <Button
                              variant="secondary"
                              size="sm"
                              disabled
                              title="No archived version — regenerate to download"
                            >
                              <Download size={11} /> Download
                            </Button>
                          )}
                          {report.report_payload_id != null ? (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => router.push(`/reports/${report.report_payload_id}`)}
                              title="View this report"
                            >
                              <ExternalLink size={11} />
                            </Button>
                          ) : (
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled
                              title="No archived version — regenerate to view"
                            >
                              <ExternalLink size={11} />
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
