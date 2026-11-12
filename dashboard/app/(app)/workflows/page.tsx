"use client";

/**
 * Workflow Library (Sprint 3) — /workflows.
 *
 * Informational, read-only catalogue of the workflow *types* the platform
 * knows how to run — not any tenant's outstanding work (that's /work).
 * Tenant-neutral: does not depend on the currently selected tenant.
 */

import {
  BookOpen,
  Clock,
  KeyRound,
  LayoutList,
  LifeBuoy,
  Lock,
  Radar,
  Receipt,
  RefreshCw,
  Shield,
  ShieldCheck,
  Sparkles,
  UserPlus,
  Wrench,
  type LucideIcon,
} from "lucide-react";

import { Card, ErrorState, PageHeader, TableSkeleton } from "@/components/ui";
import { useWorkflowLibrary } from "@/lib/api/hooks";
import type { WorkflowDefinition } from "@/types/workflow";

// Explicit lookup rather than dynamic import() — the backend sends an icon
// *name*, not a component, and dynamic import() of lucide-react by string is
// unsupported/unsafe. Unknown names fall back to Shield.
const ICONS: Record<string, LucideIcon> = {
  KeyRound,
  ShieldCheck,
  UserPlus,
  Sparkles,
  Lock,
  LifeBuoy,
  Radar,
  Receipt,
  FileBarChart2: BookOpen,
  Shield,
};

function resolveIcon(name: string): LucideIcon {
  return ICONS[name] ?? Shield;
}

function formatMinutes(minutes: number): string {
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  const remainder = minutes % 60;
  return remainder === 0 ? `${hours} hr` : `${hours} hr ${remainder} min`;
}

function categoryLabel(category: string): string {
  return category.replace(/_/g, " ");
}

function cadenceLabel(cadence: string): string {
  return cadence.replace(/_/g, " ");
}

function CapabilityBadge({ label, active, testKey }: { label: string; active: boolean; testKey: string }) {
  return (
    <span
      data-testid={active ? `badge-${testKey}-on` : `badge-${testKey}-off`}
      className={`inline-flex items-center px-2 py-0.5 rounded-md border text-[10px] font-semibold uppercase tracking-wider ${
        active
          ? "bg-cyan-500/15 text-cyan-400 border-cyan-500/30"
          : "bg-gray-800/40 text-gray-600 border-gray-700/40"
      }`}
    >
      {label}
    </span>
  );
}

function WorkflowCard({ workflow }: { workflow: WorkflowDefinition }) {
  const Icon = resolveIcon(workflow.icon);
  const effort = workflow.estimated_effort;

  return (
    <Card data-testid="workflow-card" className="p-5 flex flex-col gap-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3 min-w-0">
          <div className="w-9 h-9 rounded-lg bg-gray-800 border border-gray-700 flex items-center justify-center shrink-0 text-cyan-400">
            <Icon size={16} />
          </div>
          <div className="min-w-0">
            <h3 className="text-base font-semibold text-white">{workflow.name}</h3>
            <p className="text-sm text-gray-400 mt-0.5">{workflow.description}</p>
          </div>
        </div>
        <span className="shrink-0 px-2 py-0.5 rounded-md border text-[10px] font-semibold uppercase tracking-wider bg-gray-700/40 text-gray-300 border-gray-600/40">
          {categoryLabel(workflow.category)}
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 text-xs text-gray-400">
        <span className="flex items-center gap-1.5">
          <LayoutList size={13} className="text-gray-500" />
          {workflow.supported_controls.length}{" "}
          {workflow.supported_controls.length === 1 ? "control" : "controls"}
        </span>
        <span className="flex items-center gap-1.5">
          <Clock size={13} className="text-gray-500" />
          {formatMinutes(effort.base_minutes)} base
          {" + "}
          {formatMinutes(effort.minutes_per_item)}/item
          {" (cap "}
          {formatMinutes(effort.cap_minutes)}
          {")"}
        </span>
        <span className="flex items-center gap-1.5">
          <RefreshCw size={13} className="text-gray-500" />
          {cadenceLabel(workflow.typical_cadence)}
        </span>
        <span className="flex items-center gap-1.5">
          <Wrench size={13} className="text-gray-500" />
          {workflow.recommended_role}
        </span>
      </div>

      {workflow.supported_controls.length > 0 && (
        <details className="text-xs text-gray-500">
          <summary className="cursor-pointer select-none hover:text-gray-300 transition-colors">
            View supported controls
          </summary>
          <ul className="mt-2 flex flex-wrap gap-1.5">
            {workflow.supported_controls.map((controlId) => (
              <li
                key={controlId}
                className="px-2 py-0.5 rounded-md bg-gray-800/60 border border-gray-700/50 font-mono text-[10px] text-gray-400"
              >
                {controlId}
              </li>
            ))}
          </ul>
        </details>
      )}

      <p className="text-xs text-gray-500 border-t border-gray-800/60 pt-3">{workflow.review_philosophy}</p>

      <div className="flex flex-wrap items-center gap-2 pt-1">
        <CapabilityBadge label="Delta" active={workflow.supports_delta} testKey="delta" />
        <CapabilityBadge
          label="Verification"
          active={workflow.supports_verification}
          testKey="verification"
        />
        <CapabilityBadge label="Reports" active={workflow.supports_reports} testKey="reports" />
        <CapabilityBadge label="Remediation" active={workflow.supports_remediation} testKey="remediation" />
      </div>
    </Card>
  );
}

export default function WorkflowsPage() {
  const { data, loading, error } = useWorkflowLibrary();
  const workflows = data?.workflows ?? [];

  return (
    <div>
      <PageHeader
        title="Workflow Library"
        subtitle="What each workflow reviews, how it estimates effort, and what it can do"
      />

      {loading && (
        <div data-testid="workflows-loading">
          <TableSkeleton rows={4} cols={4} />
        </div>
      )}

      {!loading && error && <ErrorState message={error} />}

      {!loading && !error && workflows.length === 0 && (
        <Card data-testid="workflows-empty" className="p-12 text-center">
          <BookOpen size={32} className="mx-auto text-gray-600 mb-3" />
          <p className="text-base font-semibold text-white">No workflows available</p>
          <p className="text-sm text-gray-400 mt-1">The workflow catalogue is empty for this deployment.</p>
        </Card>
      )}

      {!loading && !error && workflows.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {workflows.map((workflow) => (
            <WorkflowCard key={workflow.id} workflow={workflow} />
          ))}
        </div>
      )}
    </div>
  );
}
