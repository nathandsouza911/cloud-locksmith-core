"use client";

import { useState } from "react";

import { CostOptimizationView } from "@/components/license/CostOptimizationView";
import { ApiError } from "@/lib/api/client";
import * as ep from "@/lib/api/endpoints";
import { useLicenseFindings, useLicenseSummary } from "@/lib/api/hooks";
import { useAuth } from "@/lib/auth-context";

export default function CostOptimizationPage() {
  const { tenantId } = useAuth();
  const summaryQuery = useLicenseSummary(tenantId);
  const findingsQuery = useLicenseFindings(tenantId);
  const [reportLoading, setReportLoading] = useState(false);
  const [scanLoading, setScanLoading] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  async function handleDownloadReport() {
    setReportLoading(true);
    setActionError(null);
    try {
      const blob = await ep.downloadLicenseReport();
      window.open(URL.createObjectURL(blob), "_blank");
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Unable to download the license report");
    } finally {
      setReportLoading(false);
    }
  }

  async function handleRefreshScan() {
    setScanLoading(true);
    setActionError(null);
    try {
      await ep.runLicenseScan();
      summaryQuery.refetch();
      findingsQuery.refetch();
    } catch (error) {
      const message =
        error instanceof ApiError
          ? error.message
          : error instanceof Error
            ? error.message
            : "Unable to refresh the license scan";
      setActionError(message);
    } finally {
      setScanLoading(false);
    }
  }

  return (
    <CostOptimizationView
      title="Cost Optimization"
      subtitle="Track Microsoft 365 waste across inactive accounts, premium overspend, and unused seats."
      summary={summaryQuery.data}
      findings={findingsQuery.data?.findings ?? []}
      loading={summaryQuery.loading || findingsQuery.loading}
      error={actionError ?? summaryQuery.error ?? findingsQuery.error}
      onDownloadReport={handleDownloadReport}
      onRefreshScan={handleRefreshScan}
      reportLoading={reportLoading}
      scanLoading={scanLoading}
    />
  );
}
