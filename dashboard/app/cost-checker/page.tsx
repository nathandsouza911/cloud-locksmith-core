"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ArrowRight, Shield, Sparkles } from "lucide-react";

import { CostOptimizationView } from "@/components/license/CostOptimizationView";
import { ApiError } from "@/lib/api/client";
import * as ep from "@/lib/api/endpoints";
import { startMicrosoftOAuth } from "@/lib/auth";
import { useAuth } from "@/lib/auth-context";
import type { LicenseFinding, LicenseSummary } from "@/types";

const EMPTY_SUMMARY: LicenseSummary = {
  currency: "USD",
  total_waste: 0,
  inactive_users_cost: 0,
  overlicensed_cost: 0,
  unused_license_cost: 0,
};

export default function CostCheckerPage() {
  const { authed, loading: authLoading, tenantId } = useAuth();
  const [summary, setSummary] = useState<LicenseSummary | null>(null);
  const [findings, setFindings] = useState<LicenseFinding[]>([]);
  const [scanLoading, setScanLoading] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (authLoading || !authed || !tenantId) return;

    let active = true;

    async function scanAndLoad() {
      setScanLoading(true);
      setError(null);
      try {
        await ep.runLicenseScan();
        const [nextSummary, nextFindings] = await Promise.all([
          ep.getLicenseSummary(),
          ep.getLicenseFindings(),
        ]);
        if (!active) return;
        setSummary(nextSummary);
        setFindings(nextFindings.findings);
      } catch (scanError) {
        if (!active) return;
        setError(scanError instanceof Error ? scanError.message : "Unable to analyze your tenant");
      } finally {
        if (active) {
          setScanLoading(false);
        }
      }
    }

    void scanAndLoad();
    return () => {
      active = false;
    };
  }, [authLoading, authed, tenantId]);

  async function handleDownloadReport() {
    setReportLoading(true);
    setError(null);
    try {
      const blob = await ep.downloadLicenseReport();
      window.open(URL.createObjectURL(blob), "_blank");
    } catch (downloadError) {
      setError(downloadError instanceof Error ? downloadError.message : "Unable to download the full report");
    } finally {
      setReportLoading(false);
    }
  }

  async function handleRefreshScan() {
    setScanLoading(true);
    setError(null);
    try {
      await ep.runLicenseScan();
      const [nextSummary, nextFindings] = await Promise.all([
        ep.getLicenseSummary(),
        ep.getLicenseFindings(),
      ]);
      setSummary(nextSummary);
      setFindings(nextFindings.findings);
    } catch (scanError) {
      const message =
        scanError instanceof ApiError
          ? scanError.message
          : scanError instanceof Error
            ? scanError.message
            : "Unable to refresh your analysis";
      setError(message);
    } finally {
      setScanLoading(false);
    }
  }

  if (authLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-950">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-emerald-400 border-t-transparent" />
      </div>
    );
  }

  if (!authed) {
    return (
      <main className="min-h-screen overflow-hidden bg-[radial-gradient(circle_at_top,#123524,transparent_35%),linear-gradient(180deg,#020617,#031015)] text-white">
        <section className="mx-auto flex min-h-screen max-w-6xl flex-col justify-center px-6 py-16">
          <div className="max-w-3xl">
            <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-4 py-2 text-xs font-semibold uppercase tracking-[0.26em] text-emerald-200">
              <Sparkles size={14} />
              License Cost Optimizer
            </div>
            <h1 className="text-5xl font-semibold tracking-tight text-white sm:text-6xl">
              Stop wasting money on Microsoft 365 licenses
            </h1>
            <p className="mt-6 max-w-2xl text-lg leading-8 text-gray-300">
              Connect your tenant in read-only mode, analyze inactive users and unused seats, and get a clean
              dollar-based summary of monthly license waste.
            </p>
            <div className="mt-10 flex flex-wrap items-center gap-4">
              <button
                onClick={() => startMicrosoftOAuth("cost_checker")}
                className="inline-flex items-center gap-2 rounded-xl bg-emerald-400 px-6 py-3 text-sm font-semibold text-gray-950 shadow-lg shadow-emerald-500/20 transition hover:bg-emerald-300"
              >
                Scan my tenant
                <ArrowRight size={16} />
              </button>
              <Link
                href="/login"
                className="inline-flex items-center gap-2 rounded-xl border border-gray-700 px-6 py-3 text-sm font-medium text-gray-300 transition hover:border-gray-500 hover:text-white"
              >
                Full product login
              </Link>
            </div>
            <div className="mt-10 grid gap-4 sm:grid-cols-3">
              <div className="rounded-2xl border border-gray-800 bg-gray-900/60 p-5">
                <p className="text-xs uppercase tracking-[0.22em] text-gray-500">Permissions</p>
                <p className="mt-2 text-sm text-gray-200">
                  User.Read.All, Directory.Read.All, Reports.Read.All
                </p>
              </div>
              <div className="rounded-2xl border border-gray-800 bg-gray-900/60 p-5">
                <p className="text-xs uppercase tracking-[0.22em] text-gray-500">Mode</p>
                <p className="mt-2 text-sm text-gray-200">
                  Read-only OAuth, no remediation, no write actions
                </p>
              </div>
              <div className="rounded-2xl border border-gray-800 bg-gray-900/60 p-5">
                <p className="text-xs uppercase tracking-[0.22em] text-gray-500">Outcome</p>
                <p className="mt-2 text-sm text-gray-200">Monthly waste estimate plus downloadable report</p>
              </div>
            </div>
          </div>
        </section>
      </main>
    );
  }

  if (scanLoading && findings.length === 0 && summary === null) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-950 px-6 text-center">
        <div className="max-w-md">
          <div className="mx-auto mb-5 flex h-16 w-16 items-center justify-center rounded-2xl bg-emerald-500/10 text-emerald-300">
            <Shield size={30} />
          </div>
          <div className="mx-auto mb-5 h-6 w-6 animate-spin rounded-full border-2 border-emerald-400 border-t-transparent" />
          <h1 className="text-2xl font-semibold text-white">Analyzing your licenses...</h1>
          <p className="mt-3 text-sm text-gray-400">
            We&apos;re reviewing Microsoft 365 seat usage, activity, and license waste for this tenant.
          </p>
        </div>
      </div>
    );
  }

  return (
    <main className="min-h-screen bg-gray-950 px-4 py-10 text-white sm:px-6 lg:px-8">
      <div className="mx-auto max-w-6xl">
        <CostOptimizationView
          title="Microsoft 365 Cost Checker"
          subtitle="A read-only review of monthly Microsoft 365 license waste for this tenant."
          summary={summary ?? EMPTY_SUMMARY}
          findings={findings}
          loading={scanLoading && summary === null}
          error={error}
          onDownloadReport={handleDownloadReport}
          onRefreshScan={handleRefreshScan}
          reportLoading={reportLoading}
          scanLoading={scanLoading}
          findingsLimit={5}
          compactHeader
        />
      </div>
    </main>
  );
}
