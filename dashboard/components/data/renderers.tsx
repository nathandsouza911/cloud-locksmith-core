"use client";

import type { FindingGuidance, FleetOverviewTenant } from "@/types";
import { scoreBandAccent, scoreBandLabel } from "@/utils/posture";

function isRenderablePrimitive(value: unknown): value is string | number {
  return typeof value === "string" || typeof value === "number";
}

export function renderUnknownValue(value: unknown): React.ReactNode {
  if (value == null) {
    return <span className="text-gray-600">—</span>;
  }

  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }

  if (isRenderablePrimitive(value)) {
    return value;
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return <span className="text-gray-600">—</span>;
    }

    const allPrimitive = value.every(
      (entry) => entry == null || isRenderablePrimitive(entry) || typeof entry === "boolean",
    );
    if (allPrimitive) {
      return value
        .map((entry) => (typeof entry === "boolean" ? (entry ? "Yes" : "No") : String(entry ?? "—")))
        .join(", ");
    }

    return (
      <pre className="max-w-full overflow-x-auto whitespace-pre-wrap break-words text-xs text-gray-400">
        {JSON.stringify(value, null, 2)}
      </pre>
    );
  }

  if (typeof value === "object") {
    return (
      <pre className="max-w-full overflow-x-auto whitespace-pre-wrap break-words text-xs text-gray-400">
        {JSON.stringify(value, null, 2)}
      </pre>
    );
  }

  return String(value);
}

function renderManualSteps(manualSteps?: string | string[]) {
  if (!manualSteps) return <p className="text-xs text-gray-500">No manual steps provided.</p>;

  if (Array.isArray(manualSteps)) {
    return (
      <ul className="list-disc space-y-1 pl-4 text-xs text-gray-400">
        {manualSteps.map((step, index) => (
          <li key={`${step}-${index}`}>{step}</li>
        ))}
      </ul>
    );
  }

  return <p className="text-xs text-gray-400">{manualSteps}</p>;
}

export function FindingGuidanceCard({ guidance }: { guidance?: string | FindingGuidance }) {
  if (!guidance) {
    return <span className="text-gray-500">—</span>;
  }

  if (typeof guidance === "string") {
    return <p className="text-xs text-gray-400">{guidance}</p>;
  }

  return (
    <div className="space-y-2">
      <div className="space-y-1">
        <p className="text-xs font-semibold text-gray-200">{guidance?.title ?? "Guidance"}</p>
        <p className="text-xs text-gray-400">{guidance?.summary ?? "No summary available."}</p>
        {guidance?.severity ? (
          <span className="inline-flex rounded-md bg-gray-800 px-2 py-0.5 text-[11px] font-semibold text-gray-300">
            {guidance?.severity}
          </span>
        ) : null}
      </div>
      {renderManualSteps(guidance?.manual_steps)}
    </div>
  );
}

function formatLastScan(value: string | null) {
  if (!value) return "No scans yet";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "No scans yet";
  return date.toLocaleString();
}

export function TenantCard({ tenant, onClick }: { tenant: FleetOverviewTenant; onClick: () => void }) {
  return (
    <button
      type="button"
      className="rounded-2xl border border-gray-800 bg-gray-900/70 p-5 text-left transition hover:border-cyan-500/40 hover:bg-gray-900"
      onClick={onClick}
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-lg font-semibold text-gray-100">{tenant?.tenant_name ?? "Unknown tenant"}</p>
          <p className="mt-1 text-xs font-mono text-gray-500">{tenant?.tenant_id ?? "—"}</p>
        </div>
        <div className={`text-sm font-semibold ${scoreBandAccent(tenant?.risk_score_band ?? null)}`}>
          {scoreBandLabel(tenant?.risk_score_band ?? null)}
        </div>
      </div>

      <div className="mt-5 grid grid-cols-2 gap-4">
        <div>
          <p className="text-xs uppercase tracking-wide text-gray-500">Risk Score</p>
          <p className={`mt-1 text-2xl font-bold ${scoreBandAccent(tenant?.risk_score_band ?? null)}`}>
            {tenant?.risk_score ?? 0}
          </p>
        </div>
        <div>
          <p className="text-xs uppercase tracking-wide text-gray-500">Critical Findings</p>
          <p className="mt-1 text-2xl font-bold text-red-400">{tenant?.critical_findings ?? 0}</p>
        </div>
        <div>
          <p className="text-xs uppercase tracking-wide text-gray-500">MFA Coverage</p>
          <p className="mt-1 text-xl font-semibold text-cyan-300">{tenant?.mfa_coverage ?? 0}%</p>
        </div>
        <div>
          <p className="text-xs uppercase tracking-wide text-gray-500">Last Scan</p>
          <p className="mt-1 text-sm text-gray-300">{formatLastScan(tenant?.last_scan ?? null)}</p>
        </div>
      </div>
    </button>
  );
}
