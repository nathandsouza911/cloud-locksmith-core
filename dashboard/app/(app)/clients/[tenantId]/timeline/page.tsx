"use client";

/**
 * Client Timeline (Sprint 3) — /clients/[tenantId]/timeline.
 *
 * Chronological, newest-first, read-only merged history for a single tenant:
 * review decisions, remediation, verification, audit log, reports, posture
 * snapshots and workflow runs. No editing here.
 *
 * Tenant isolation: the tenantId in the URL is never trusted blindly. It is
 * checked against the tenants the signed-in user actually has access to
 * (mirrors the pattern in app/(app)/tenants/[id]/page.tsx) before any query
 * is issued — a malicious/typo'd path segment must not leak another
 * tenant's timeline.
 */

import { useCallback, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import {
  CheckCircle2,
  ClipboardList,
  Clock,
  FileBarChart2,
  FileText,
  Radar,
  RefreshCw,
  ScrollText,
  Shield,
  ShieldCheck,
  User,
  type LucideIcon,
} from "lucide-react";

import { Card, ErrorState, PageHeader, TableSkeleton } from "@/components/ui";
import { useClientTimeline } from "@/lib/api/hooks";
import { useAuth } from "@/lib/auth-context";
import type { SourceSystem, TimelineEvent } from "@/types/timeline";

const SOURCE_COLORS: Record<SourceSystem, string> = {
  REVIEW_DECISIONS: "border-cyan-500/30 bg-cyan-500/10 text-cyan-400",
  REMEDIATION: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
  VERIFICATION: "border-blue-500/30 bg-blue-500/10 text-blue-400",
  AUDIT_LOG: "border-gray-600/40 bg-gray-700/30 text-gray-300",
  REPORTS: "border-purple-500/30 bg-purple-500/10 text-purple-400",
  POSTURE_SNAPSHOT: "border-yellow-500/30 bg-yellow-500/10 text-yellow-400",
  WORKFLOW_RUN: "border-orange-500/30 bg-orange-500/10 text-orange-400",
};

const SOURCE_ICONS: Record<SourceSystem, LucideIcon> = {
  REVIEW_DECISIONS: ClipboardList,
  REMEDIATION: ShieldCheck,
  VERIFICATION: CheckCircle2,
  AUDIT_LOG: ScrollText,
  REPORTS: FileBarChart2,
  POSTURE_SNAPSHOT: Radar,
  WORKFLOW_RUN: RefreshCw,
};

const EVENT_TYPE_OPTIONS = [
  { label: "Review Decision", value: "REVIEW_DECISION" },
  { label: "Remediation", value: "REMEDIATION" },
  { label: "Verification", value: "VERIFICATION" },
  { label: "Audit", value: "AUDIT" },
  { label: "Report Generated", value: "REPORT_GENERATED" },
  { label: "Posture Snapshot", value: "POSTURE_SNAPSHOT" },
  { label: "Workflow Run", value: "WORKFLOW_RUN" },
];

function formatDateTime(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

// Local date input (yyyy-mm-dd) -> ISO instant. Kept simple and explicit
// rather than relying on ambient timezone parsing quirks.
function dateInputToIso(value: string, endOfDay: boolean): string | undefined {
  if (!value) return undefined;
  const suffix = endOfDay ? "T23:59:59.999Z" : "T00:00:00.000Z";
  return `${value}${suffix}`;
}

function TimelineRow({ event }: { event: TimelineEvent }) {
  const Icon = SOURCE_ICONS[event.source_system] ?? ScrollText;
  const colorClasses = SOURCE_COLORS[event.source_system] ?? SOURCE_COLORS.AUDIT_LOG;

  return (
    <div data-testid="timeline-event" className="flex items-start gap-3 p-4">
      <div className={`w-8 h-8 rounded-lg border flex items-center justify-center shrink-0 ${colorClasses}`}>
        <Icon size={14} />
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <p className="text-sm font-medium text-white">{event.title}</p>
          {event.evidence_reference && (
            <span
              data-testid="evidence-indicator"
              title={event.evidence_reference}
              className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-md border border-gray-700 bg-gray-800/60 text-[10px] text-gray-400"
            >
              <FileText size={10} />
              Evidence
            </span>
          )}
        </div>

        {event.description && <p className="text-xs text-gray-500 mt-0.5">{event.description}</p>}

        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-1.5 text-xs text-gray-500">
          <span className="flex items-center gap-1.5">
            <Clock size={11} />
            {formatDateTime(event.timestamp)}
          </span>
          {event.workflow_name && (
            <span className="flex items-center gap-1.5">
              <Shield size={11} />
              {event.workflow_name}
            </span>
          )}
          {event.actor && (
            <span className="flex items-center gap-1.5">
              <User size={11} />
              {event.actor}
            </span>
          )}
          {event.outcome && <span className="text-gray-400 font-medium">{event.outcome}</span>}
        </div>
      </div>
    </div>
  );
}

export default function ClientTimelinePage() {
  const params = useParams();
  const tenantId = (params?.tenantId as string | undefined) ?? null;
  const { tenants } = useAuth();

  const hasAccess = useMemo(
    () => !!tenantId && tenants.some((tenant) => tenant.tenant_id === tenantId),
    [tenantId, tenants],
  );

  const [workflowFilter, setWorkflowFilter] = useState("");
  const [eventTypeFilter, setEventTypeFilter] = useState("");
  const [sinceFilter, setSinceFilter] = useState("");
  const [untilFilter, setUntilFilter] = useState("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [accumulated, setAccumulated] = useState<TimelineEvent[]>([]);

  const scopedTenantId = hasAccess ? tenantId : null;

  const queryParams = useMemo(
    () => ({
      cursor,
      workflow_id: workflowFilter || undefined,
      event_types: eventTypeFilter ? [eventTypeFilter] : undefined,
      since: dateInputToIso(sinceFilter, false),
      until: dateInputToIso(untilFilter, true),
    }),
    [cursor, workflowFilter, eventTypeFilter, sinceFilter, untilFilter],
  );

  const { data, loading, error } = useClientTimeline(scopedTenantId, queryParams);

  const events = data?.events ?? [];
  const allEvents = cursor ? [...accumulated, ...events] : events;

  const resetPaging = useCallback(() => {
    setCursor(undefined);
    setAccumulated([]);
  }, []);

  const handleLoadMore = useCallback(() => {
    if (!data?.next_cursor) return;
    setAccumulated((prev) => [...prev, ...events]);
    setCursor(data.next_cursor);
  }, [data?.next_cursor, events]);

  if (!hasAccess) {
    return (
      <div>
        <PageHeader title="Client Timeline" />
        <ErrorState message="Access denied" />
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title="Client Timeline"
        subtitle={data?.tenant_name ? `History for ${data.tenant_name}` : "Chronological history"}
      />

      <Card className="p-4 mb-4 flex flex-wrap items-center gap-3">
        <select
          data-testid="filter-workflow"
          value={workflowFilter}
          onChange={(e) => {
            setWorkflowFilter(e.target.value);
            resetPaging();
          }}
          className="bg-gray-800 border border-gray-700 text-sm text-gray-300 rounded-lg px-3 py-1.5 outline-none focus:border-cyan-500 transition-colors"
        >
          <option value="">All Workflows</option>
          <option value="OAUTH_REVIEW">OAuth Review</option>
          <option value="GUEST_REVIEW">Guest Access Review</option>
        </select>
        <select
          data-testid="filter-event-type"
          value={eventTypeFilter}
          onChange={(e) => {
            setEventTypeFilter(e.target.value);
            resetPaging();
          }}
          className="bg-gray-800 border border-gray-700 text-sm text-gray-300 rounded-lg px-3 py-1.5 outline-none focus:border-cyan-500 transition-colors"
        >
          <option value="">All Event Types</option>
          {EVENT_TYPE_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        <input
          data-testid="filter-since"
          type="date"
          value={sinceFilter}
          onChange={(e) => {
            setSinceFilter(e.target.value);
            resetPaging();
          }}
          className="bg-gray-800 border border-gray-700 text-sm text-gray-300 rounded-lg px-3 py-1.5 outline-none focus:border-cyan-500 transition-colors"
        />
        <input
          data-testid="filter-until"
          type="date"
          value={untilFilter}
          onChange={(e) => {
            setUntilFilter(e.target.value);
            resetPaging();
          }}
          className="bg-gray-800 border border-gray-700 text-sm text-gray-300 rounded-lg px-3 py-1.5 outline-none focus:border-cyan-500 transition-colors"
        />
      </Card>

      {loading && (
        <div data-testid="timeline-loading">
          <TableSkeleton rows={6} cols={3} />
        </div>
      )}

      {!loading && error && <ErrorState message={error} />}

      {!loading && !error && allEvents.length === 0 && (
        <Card data-testid="timeline-empty" className="p-12 text-center">
          <ScrollText size={32} className="mx-auto text-gray-600 mb-3" />
          <p className="text-base font-semibold text-white">No history yet</p>
          <p className="text-sm text-gray-400 mt-1">
            Events appear here as reviews, remediations and reports happen for this client.
          </p>
        </Card>
      )}

      {!loading && !error && allEvents.length > 0 && (
        <div className="space-y-3">
          <Card className="divide-y divide-gray-800/60">
            {allEvents.map((event) => (
              <TimelineRow key={event.id} event={event} />
            ))}
          </Card>

          {data?.has_more && (
            <div className="flex justify-center">
              <button
                data-testid="load-more"
                onClick={handleLoadMore}
                className="px-4 py-2 rounded-lg text-sm font-medium bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700 transition-colors"
              >
                Load more
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
