"use client";

import { useEffect, useMemo, useState } from "react";
import { Activity, Filter, RefreshCw } from "lucide-react";
import {
  Card,
  PageHeader,
  FilterSelect,
  Button,
  EmptyState,
  TableSkeleton,
  ErrorState,
} from "@/components/ui";
import PostureChart from "@/components/charts/PostureChart";
import { useAuditLogs, useRemediationTimeline, usePostureTimeline } from "@/lib/api/hooks";
import { useAuth } from "@/lib/auth-context";
import { getLast14Days } from "@/utils/posture";

function formatDt(iso: string) {
  return new Date(iso).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function relTime(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

type EventKind = "audit" | "remediation";

interface UnifiedEvent {
  id: string;
  kind: EventKind;
  timestamp: string;
  title: string;
  subtitle: string;
  status?: string;
  actor?: string;
}

const KIND_STYLE: Record<EventKind, { dot: string; label: string; bg: string }> = {
  audit: { dot: "bg-blue-400", label: "Audit", bg: "bg-blue-500/10 border-blue-500/20" },
  remediation: { dot: "bg-green-400", label: "Remediation", bg: "bg-green-500/10 border-green-500/20" },
};

const STATUS_COLOR: Record<string, string> = {
  SUCCESS: "text-green-400",
  FAILURE: "text-red-400",
  EXECUTED: "text-green-400",
  VERIFIED: "text-cyan-400",
  APPROVED: "text-blue-400",
  ROLLED_BACK: "text-purple-400",
};

export default function RemediationTimelinePage() {
  const [kindFilter, setKindFilter] = useState("");
  const [actorFilter, setActorFilter] = useState("");
  const { tenantId, tenants, selectedTenant, setActiveTenantId } = useAuth();

  useEffect(() => {
    if (!tenantId && tenants.length > 0) {
      setActiveTenantId(tenants[0].tenant_id);
    }
  }, [tenantId, tenants, setActiveTenantId]);

  const auditQuery = useAuditLogs();
  const remediationQuery = useRemediationTimeline();
  const timelineQuery = usePostureTimeline(tenantId);

  const isLoading = auditQuery.loading || remediationQuery.loading;
  const auditLogs = auditQuery.data ?? [];
  const remediationTimeline = remediationQuery.data ?? [];
  const postureWindow = useMemo(() => getLast14Days(timelineQuery.data ?? []), [timelineQuery.data]);
  const hasChartData = postureWindow.some((point) => point.score !== null);

  const allEvents = useMemo<UnifiedEvent[]>(() => {
    const audit: UnifiedEvent[] = auditLogs.map((item) => ({
      id: item.id,
      kind: "audit",
      timestamp: item.created_at,
      title: item.action.replace(/_/g, " "),
      subtitle: `${item.target} - ${item.reason}`,
      status: item.status,
      actor: item.actor,
    }));

    const remediation: UnifiedEvent[] = remediationTimeline.map((item) => ({
      id: item.snapshot_id,
      kind: "remediation",
      timestamp: item.timestamp,
      title: `${item.action} - ${item.control_id.replace(/_/g, " ")}`,
      subtitle: item.tenant_name,
      status: item.action,
      actor: "system",
    }));

    return [...audit, ...remediation].sort(
      (left, right) => new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime(),
    );
  }, [auditLogs, remediationTimeline]);

  const actors = useMemo(
    () => [...new Set(allEvents.map((event) => event.actor).filter(Boolean))],
    [allEvents],
  );

  const tenantOptions = useMemo(
    () =>
      tenants.map((tenant) => ({
        label: tenant.tenant_name,
        value: tenant.tenant_id,
      })),
    [tenants],
  );

  const filtered = useMemo(
    () =>
      allEvents.filter((event) => {
        if (kindFilter && event.kind !== kindFilter) return false;
        if (actorFilter && event.actor !== actorFilter) return false;
        return true;
      }),
    [allEvents, kindFilter, actorFilter],
  );

  function refetchAll() {
    auditQuery.refetch();
    remediationQuery.refetch();
    timelineQuery.refetch();
  }

  useEffect(() => {
    const handleScanStarted = () => {
      refetchAll();
      window.setTimeout(() => refetchAll(), 3000);
      window.setTimeout(() => refetchAll(), 10000);
    };
    window.addEventListener("cloud-locksmith:scan-started", handleScanStarted);
    return () => window.removeEventListener("cloud-locksmith:scan-started", handleScanStarted);
  }, [tenantId]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Remediation Timeline"
        subtitle={
          selectedTenant
            ? `Chronological audit and remediation activity log for ${selectedTenant.tenant_name}`
            : "Chronological audit and remediation activity log"
        }
        actions={
          <>
            <FilterSelect
              value={tenantId ?? ""}
              onChange={(value) => setActiveTenantId(value || null)}
              options={tenantOptions}
              placeholder="Current tenant"
            />
            <Button variant="secondary" size="sm" onClick={refetchAll}>
              <RefreshCw size={13} className={isLoading || timelineQuery.loading ? "animate-spin" : ""} />
            </Button>
            <Button variant="secondary" size="sm">
              <Filter size={13} /> Export
            </Button>
          </>
        }
      />

      <Card className="p-5">
        <div className="mb-4 flex items-center justify-between gap-3">
          <p className="text-sm font-semibold text-gray-200">Score Over Time - Last 14 Days</p>
          <span className="text-xs text-gray-500">Posture history</span>
        </div>
        {timelineQuery.loading ? (
          <TableSkeleton rows={3} cols={1} />
        ) : timelineQuery.error ? (
          <ErrorState message="Unable to load data. Please try again." />
        ) : !hasChartData ? (
          <EmptyState message="Not enough data yet. Run a scan to generate posture history." />
        ) : (
          <PostureChart data={postureWindow} height={200} showGrid />
        )}
      </Card>

      <div className="flex flex-wrap items-center gap-3">
        {(["audit", "remediation"] as EventKind[]).map((kind) => (
          <button
            key={kind}
            onClick={() => setKindFilter((value) => (value === kind ? "" : kind))}
            className={`flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-medium transition-all ${
              kindFilter === kind
                ? `${KIND_STYLE[kind].bg} text-gray-200`
                : "border-gray-700 bg-transparent text-gray-400 hover:border-gray-500"
            }`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${KIND_STYLE[kind].dot}`} />
            {KIND_STYLE[kind].label}
          </button>
        ))}
        <div className="ml-auto">
          <FilterSelect
            value={actorFilter}
            onChange={setActorFilter}
            options={actors.map((actor) => ({ label: actor!, value: actor! }))}
            placeholder="All actors"
          />
        </div>
      </div>

      <Card className="overflow-hidden">
        <div className="flex items-center gap-2 border-b border-gray-800 px-5 py-4">
          <Activity size={14} className="text-cyan-400" />
          <p className="text-sm font-semibold text-gray-200">Event Feed</p>
          {!isLoading ? (
            <span className="ml-1 rounded-full bg-gray-800 px-2 py-0.5 text-xs text-gray-500">
              {filtered.length} events
            </span>
          ) : null}
        </div>

        {isLoading ? (
          <div className="p-5">
            <TableSkeleton rows={6} cols={3} />
          </div>
        ) : (auditQuery.error || remediationQuery.error) && allEvents.length === 0 ? (
          <ErrorState message="Unable to load data. Please try again." />
        ) : filtered.length === 0 ? (
          <EmptyState message="No events available" />
        ) : (
          <div className="relative px-5 py-4">
            <div className="absolute bottom-4 left-[2.125rem] top-4 w-px bg-gray-800" />
            <div className="space-y-4">
              {filtered.map((event) => {
                const style = KIND_STYLE[event.kind];
                return (
                  <div key={event.id} className="group flex gap-4">
                    <div className="relative z-10 mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border-2 border-gray-900">
                      <div className={`h-2 w-2 rounded-full ${style.dot}`} />
                    </div>
                    <div className={`flex-1 rounded-xl border p-3.5 transition-all ${style.bg}`}>
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0 flex-1">
                          <p className="text-sm font-semibold leading-tight text-gray-200">{event.title}</p>
                          <p className="mt-0.5 truncate text-xs text-gray-400">{event.subtitle}</p>
                        </div>
                        <div className="shrink-0 text-right">
                          <p
                            className={`text-xs font-semibold ${STATUS_COLOR[event.status ?? ""] ?? "text-gray-400"}`}
                          >
                            {event.status}
                          </p>
                          <p className="mt-0.5 text-[10px] text-gray-500">{relTime(event.timestamp)}</p>
                        </div>
                      </div>
                      <div className="mt-2 flex items-center gap-3">
                        {event.actor ? (
                          <span className="text-[10px] text-gray-500">by {event.actor}</span>
                        ) : null}
                        <span className="text-[10px] text-gray-600">{formatDt(event.timestamp)}</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}
