"use client";

import { useState, useMemo, useRef, useEffect } from "react";
import { Shield, Search, X, ExternalLink } from "lucide-react";

import { Card, ErrorState, PageHeader, TableSkeleton } from "@/components/ui";
import { useComplianceDashboard } from "@/lib/api/hooks";
import type { FrameworkSummary, ControlDashboardRow, ControlStatus } from "@/types";

// ─── Framework Card ───────────────────────────────────────────────────────────

function FrameworkCard({
  fw,
  active,
  onClick,
}: {
  fw: FrameworkSummary;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`w-full rounded-2xl border p-4 text-left transition-colors ${
        active
          ? "border-cyan-500/60 bg-cyan-500/10"
          : "border-gray-800 bg-gray-900/40 hover:border-gray-700 hover:bg-gray-800/60"
      }`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold text-gray-100">{fw.name}</p>
          <div className="mt-1 flex flex-wrap items-center gap-1.5">
            <span className="rounded-md border border-gray-700 bg-gray-800 px-1.5 py-0.5 text-[10px] font-medium text-gray-400">
              {fw.version}
            </span>
            {fw.kind === "derived" ? (
              <span className="rounded-md border border-blue-500/40 bg-blue-500/10 px-1.5 py-0.5 text-[10px] font-medium text-blue-300">
                Derived
              </span>
            ) : null}
          </div>
        </div>
      </div>
      <div className="mt-3 flex flex-wrap gap-1.5">
        <span className="inline-flex items-center gap-1 rounded-full bg-green-100 px-2 py-0.5 text-[10px] font-semibold text-green-800 dark:bg-green-900/30 dark:text-green-400">
          PASS {fw.pass_count}
        </span>
        <span className="inline-flex items-center gap-1 rounded-full bg-red-100 px-2 py-0.5 text-[10px] font-semibold text-red-800 dark:bg-red-900/30 dark:text-red-400">
          FAIL {fw.fail_count}
        </span>
        <span className="inline-flex items-center gap-1 rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-semibold text-amber-800 dark:bg-amber-900/30 dark:text-amber-400">
          PARTIAL {fw.partial_count}
        </span>
        <span className="inline-flex items-center gap-1 rounded-full bg-gray-100 px-2 py-0.5 text-[10px] font-semibold text-gray-600 dark:bg-gray-800 dark:text-gray-400">
          N/A {fw.not_applicable_count}
        </span>
      </div>
    </button>
  );
}

// ─── Status Badge ─────────────────────────────────────────────────────────────

function StatusBadgeCompliance({ status }: { status: ControlStatus }) {
  const classes: Record<ControlStatus, string> = {
    PASS: "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400",
    FAIL: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
    PARTIAL: "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400",
    NOT_APPLICABLE: "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400",
  };
  const labels: Record<ControlStatus, string> = {
    PASS: "PASS",
    FAIL: "FAIL",
    PARTIAL: "PARTIAL",
    NOT_APPLICABLE: "N/A",
  };
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${classes[status]}`}
    >
      {labels[status]}
    </span>
  );
}

// ─── Mapping Strength Badge ───────────────────────────────────────────────────

function MappingStrengthBadge({
  strength,
}: {
  strength: "direct" | "partial" | "evidence" | "informational";
}) {
  const classes: Record<string, string> = {
    direct: "border border-cyan-500/40 bg-cyan-500/10 text-cyan-300",
    partial: "border border-amber-500/40 bg-amber-500/10 text-amber-300",
    evidence: "border border-purple-500/40 bg-purple-500/10 text-purple-300",
    informational: "border border-gray-600/40 bg-gray-800/60 text-gray-400",
  };
  return (
    <span
      className={`inline-flex items-center rounded-md px-2 py-0.5 text-[10px] font-semibold capitalize ${classes[strength] ?? classes.informational}`}
    >
      {strength}
    </span>
  );
}

// ─── Control Drawer ───────────────────────────────────────────────────────────

const MAPPING_STRENGTH_TOOLTIP: Record<string, string> = {
  direct: "Directly addresses this requirement",
  partial: "Partially addresses this requirement",
  evidence: "Provides supporting evidence",
  informational: "Provides informational context",
};

function ControlDrawer({ control, onClose }: { control: ControlDashboardRow; onClose: () => void }) {
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const evidenceTypeLabel = control.evidence_type.replace(/_/g, " ");
  const strengthTooltip = MAPPING_STRENGTH_TOOLTIP[control.mapping_strength] ?? control.mapping_strength;
  const showRiskFeedLink = control.status === "FAIL" || control.status === "PARTIAL";

  // When drawer opens: focus the close button
  useEffect(() => {
    closeButtonRef.current?.focus();
  }, []);

  return (
    <>
      {/* Overlay */}
      <div
        className="fixed inset-0 z-40 bg-gray-950/60 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden="true"
      />
      {/* Drawer */}
      <div className="fixed inset-y-0 right-0 z-50 flex w-full max-w-md flex-col border-l border-gray-800 bg-gray-950 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-gray-800 px-6 py-4">
          <div className="min-w-0 flex-1">
            <p className="font-mono text-xs font-medium uppercase tracking-wider text-gray-500">
              Control Detail
            </p>
            <p className="mt-1 truncate font-mono text-lg font-bold text-gray-100">{control.control_id}</p>
          </div>
          <button
            ref={closeButtonRef}
            type="button"
            aria-label="Close drawer"
            onClick={onClose}
            className="ml-4 rounded-full border border-white/10 p-2 text-gray-400 transition hover:border-white/30 hover:text-white"
          >
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5">
          {/* Framework + reference */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-md border border-gray-700 bg-gray-800 px-2 py-0.5 text-xs text-gray-300">
              {control.framework_name}
            </span>
            <span className="font-mono text-xs text-gray-400">{control.reference_id}</span>
          </div>

          {/* Label */}
          <p className="mt-3 text-sm text-gray-300">{control.label}</p>

          {/* Status badge */}
          <div className="mt-4">
            <StatusBadgeCompliance status={control.status} />
          </div>

          <div className="my-5 border-t border-gray-800" />

          {/* Details grid */}
          <dl className="space-y-4">
            <div>
              <dt className="text-xs font-semibold uppercase tracking-wider text-gray-500">
                Mapping Strength
              </dt>
              <dd className="mt-1.5 flex flex-wrap items-center gap-2">
                <MappingStrengthBadge strength={control.mapping_strength} />
                <span className="text-xs text-gray-400">{strengthTooltip}</span>
              </dd>
            </div>

            <div>
              <dt className="text-xs font-semibold uppercase tracking-wider text-gray-500">Evidence Type</dt>
              <dd className="mt-1.5 text-sm capitalize text-gray-300">{evidenceTypeLabel}</dd>
            </div>

            <div>
              <dt className="text-xs font-semibold uppercase tracking-wider text-gray-500">
                NIST CSF Functions
              </dt>
              <dd className="mt-1.5">
                {control.nist_csf_functions.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {control.nist_csf_functions.map((fn) => (
                      <span
                        key={fn}
                        className="rounded-md border border-indigo-500/30 bg-indigo-500/10 px-2 py-0.5 text-[10px] font-semibold text-indigo-300"
                      >
                        {fn}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="text-xs text-gray-500">None</span>
                )}
              </dd>
            </div>
          </dl>

          <div className="my-5 border-t border-gray-800" />

          {/* Actions */}
          <div className="space-y-2">
            {showRiskFeedLink ? (
              <a
                href="/risk-feed"
                className="flex w-full items-center justify-center gap-2 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-2.5 text-sm font-medium text-red-300 transition hover:border-red-500/50 hover:bg-red-500/20"
              >
                <ExternalLink size={14} />
                View in Risk Feed
              </a>
            ) : null}
            <a
              href="/reports"
              className="flex w-full items-center justify-center gap-2 rounded-xl border border-gray-700 bg-gray-800/60 px-4 py-2.5 text-sm font-medium text-gray-300 transition hover:border-gray-600 hover:bg-gray-700/60"
            >
              <ExternalLink size={14} />
              View Reports
            </a>
          </div>
        </div>
      </div>
    </>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function CompliancePage() {
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null);
  const [selectedStatus, setSelectedStatus] = useState<ControlStatus | null>(null);
  const [search, setSearch] = useState("");
  const [selectedControl, setSelectedControl] = useState<ControlDashboardRow | null>(null);
  const triggerRef = useRef<HTMLElement | null>(null);

  // When drawer opens: focus the close button; when it closes, restore focus to trigger
  useEffect(() => {
    if (selectedControl) {
      triggerRef.current = document.activeElement as HTMLElement;
    } else {
      triggerRef.current?.focus();
    }
  }, [selectedControl]);

  // search is filtered client-side (small dataset, avoids round-trip per keystroke)
  const { data, loading, error } = useComplianceDashboard({
    framework_id: selectedFramework ?? undefined,
    status: selectedStatus ?? undefined,
  });

  const filteredControls = useMemo(() => {
    if (!data?.controls) return [];
    if (!search.trim()) return data.controls;
    const needle = search.toLowerCase();
    return data.controls.filter(
      (c) =>
        c.control_id.toLowerCase().includes(needle) ||
        c.reference_id.toLowerCase().includes(needle) ||
        c.label.toLowerCase().includes(needle),
    );
  }, [data?.controls, search]);

  const hasActiveFilters = Boolean(selectedFramework || selectedStatus || search.trim());

  function clearFilters() {
    setSelectedFramework(null);
    setSelectedStatus(null);
    setSearch("");
  }

  return (
    <div className="space-y-6">
      {/* Drawer */}
      {selectedControl ? (
        <ControlDrawer control={selectedControl} onClose={() => setSelectedControl(null)} />
      ) : null}

      {/* Section A: Page Header */}
      <PageHeader
        title="Compliance Coverage"
        subtitle="Evidence platform view of framework control status"
        actions={
          <div className="flex items-center gap-2">
            <Shield size={18} className="text-cyan-400" />
          </div>
        }
      />

      {/* Section B: Framework Summary Cards */}
      {loading ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-32 animate-pulse rounded-2xl border border-gray-800 bg-gray-900/40" />
          ))}
        </div>
      ) : error ? null : data?.frameworks && data.frameworks.length > 0 ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {data.frameworks
            .filter((fw) => fw.id !== "nist-csf")
            .map((fw) => (
              <FrameworkCard
                key={fw.id}
                fw={fw}
                active={selectedFramework === fw.id}
                onClick={() => setSelectedFramework((prev) => (prev === fw.id ? null : fw.id))}
              />
            ))}
        </div>
      ) : null}

      {/* Section C: Filter Bar */}
      <Card className="overflow-hidden">
        <div className="flex flex-col gap-3 border-b border-gray-800 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-wrap items-center gap-3">
            {/* Status dropdown */}
            <select
              aria-label="Filter by status"
              value={selectedStatus ?? ""}
              onChange={(e) => setSelectedStatus((e.target.value as ControlStatus) || null)}
              className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5 text-sm text-gray-200 outline-none transition-colors focus:border-cyan-500"
            >
              <option value="">All Status</option>
              <option value="PASS">PASS</option>
              <option value="FAIL">FAIL</option>
              <option value="PARTIAL">PARTIAL</option>
              <option value="NOT_APPLICABLE">NOT APPLICABLE</option>
            </select>

            {/* Search input */}
            <div className="relative flex items-center">
              <Search size={14} className="absolute left-3 text-gray-500" />
              <input
                aria-label="Search controls"
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search controls..."
                className="rounded-lg border border-gray-700 bg-gray-900 py-1.5 pl-8 pr-3 text-sm text-gray-200 outline-none transition-colors placeholder:text-gray-500 focus:border-cyan-500"
              />
            </div>

            {/* Clear filters */}
            {hasActiveFilters ? (
              <button
                type="button"
                onClick={clearFilters}
                className="flex items-center gap-1 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs font-medium text-gray-300 transition hover:border-gray-600 hover:text-white"
              >
                <X size={12} />
                Clear
              </button>
            ) : null}
          </div>

          {!loading && data?.controls ? (
            <span className="rounded-full bg-gray-800 px-2.5 py-0.5 text-xs text-gray-400">
              {filteredControls.length} controls
            </span>
          ) : null}
        </div>

        {/* Section D: Controls Table */}
        {loading ? (
          <div className="p-5">
            <TableSkeleton rows={8} cols={4} />
          </div>
        ) : error ? (
          <ErrorState message={error} />
        ) : filteredControls.length === 0 ? (
          <div className="px-5 py-12 text-center">
            <p className="text-sm text-gray-500">No controls match the current filters.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  {["Framework Control", "Cloud Locksmith Control", "Mapping", "Status"].map((heading) => (
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
                {filteredControls.map((control) => (
                  <tr
                    key={`${control.framework_id}-${control.reference_id}-${control.control_id}`}
                    className="cursor-pointer transition-colors hover:bg-gray-800/40"
                    onClick={() => setSelectedControl(control)}
                    tabIndex={0}
                    role="button"
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setSelectedControl(control);
                      }
                    }}
                  >
                    {/* Framework Control */}
                    <td className="px-5 py-3.5">
                      <div className="max-w-[14rem]">
                        <p className="font-mono text-xs font-bold text-gray-200">{control.reference_id}</p>
                        <p className="mt-0.5 text-xs text-gray-500 line-clamp-2">{control.label}</p>
                        <p className="mt-1 text-[10px] font-medium uppercase tracking-wider text-gray-600">
                          {control.framework_name}
                        </p>
                      </div>
                    </td>

                    {/* Cloud Locksmith Control */}
                    <td className="px-5 py-3.5">
                      <div>
                        <p className="font-mono text-xs text-gray-300">{control.control_id}</p>
                        {control.nist_csf_functions.length > 0 ? (
                          <div className="mt-1.5 flex flex-wrap gap-1">
                            {control.nist_csf_functions.map((fn) => (
                              <span
                                key={fn}
                                className="rounded-md border border-indigo-500/30 bg-indigo-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-indigo-300"
                              >
                                {fn}
                              </span>
                            ))}
                          </div>
                        ) : null}
                      </div>
                    </td>

                    {/* Mapping Strength */}
                    <td className="px-5 py-3.5">
                      <MappingStrengthBadge strength={control.mapping_strength} />
                    </td>

                    {/* Status */}
                    <td className="px-5 py-3.5">
                      <StatusBadgeCompliance status={control.status} />
                    </td>
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
