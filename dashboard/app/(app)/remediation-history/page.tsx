"use client";

import { useMemo, useState } from "react";
import { History, RefreshCw, RotateCcw } from "lucide-react";

import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  PageHeader,
  StatusBadge,
  TableSkeleton,
} from "@/components/ui";
import * as ep from "@/lib/api/endpoints";
import { useRemediationHistory } from "@/lib/api/hooks";
import type { RemediationHistoryItem } from "@/types";

function formatDt(iso: string | null) {
  if (!iso) return "Unknown";
  return new Date(iso).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function RemediationHistoryPage() {
  const historyQuery = useRemediationHistory();
  const [rows, setRows] = useState<RemediationHistoryItem[] | null>(null);
  const [actionId, setActionId] = useState<number | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const history = rows ?? historyQuery.data ?? [];
  const recentChanges = useMemo(() => history.slice(0, 5), [history]);

  async function handleRollback(item: RemediationHistoryItem) {
    setActionId(item.compliance_result_id);
    setToast(null);
    try {
      await ep.rollbackRemediation(String(item.compliance_result_id));
      setRows((current) =>
        (current ?? historyQuery.data ?? []).map((row) =>
          row.compliance_result_id === item.compliance_result_id
            ? { ...row, status: "REVERSED", can_rollback: false }
            : row,
        ),
      );
      setToast("Rollback completed");
    } catch (error) {
      setToast(error instanceof Error ? error.message : "Rollback failed");
    } finally {
      setActionId(null);
    }
  }

  function refetch() {
    setRows(null);
    historyQuery.refetch();
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Remediation History & Rollback"
        subtitle="Review recent successful remediations and manage rollback from a dedicated audit surface"
        actions={
          <Button variant="secondary" size="sm" onClick={refetch} loading={historyQuery.loading}>
            <RefreshCw size={13} /> Refresh
          </Button>
        }
      />

      {toast ? (
        <Card className="border-cyan-500/30 bg-cyan-500/10 px-4 py-3 text-sm text-cyan-100">{toast}</Card>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="p-5 lg:col-span-1">
          <div className="flex items-center gap-2">
            <History size={14} className="text-cyan-400" />
            <p className="text-sm font-semibold text-gray-200">Recent Changes</p>
          </div>
          {historyQuery.loading ? (
            <div className="mt-4">
              <TableSkeleton rows={5} cols={1} />
            </div>
          ) : recentChanges.length === 0 ? (
            <EmptyState message="No rollbackable remediations yet" />
          ) : (
            <div className="mt-4 space-y-3">
              {recentChanges.map((item) => (
                <div
                  key={item.compliance_result_id}
                  className="rounded-xl border border-gray-800 bg-gray-900 px-3 py-3"
                >
                  <p className="text-sm font-semibold text-gray-100">{item.control_id.replace(/_/g, " ")}</p>
                  <p className="mt-1 text-xs text-gray-400">{item.resource_label}</p>
                  <div className="mt-2 flex items-center justify-between gap-2">
                    <StatusBadge value={item.status} />
                    <span className="text-[11px] text-gray-500">{formatDt(item.executed_at)}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card className="overflow-hidden lg:col-span-2">
          <div className="border-b border-gray-800 px-5 py-4">
            <p className="text-sm font-semibold text-gray-200">Rollback Queue</p>
          </div>

          {historyQuery.loading ? (
            <div className="p-5">
              <TableSkeleton rows={6} cols={5} />
            </div>
          ) : historyQuery.error ? (
            <ErrorState message={historyQuery.error} />
          ) : history.length === 0 ? (
            <EmptyState message="No successful remediations are currently eligible for rollback" />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-800">
                    {["Control", "Resource", "Executed At", "Status", "Actions"].map((heading) => (
                      <th
                        key={heading}
                        className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-400"
                      >
                        {heading}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/50">
                  {history.map((item) => (
                    <tr key={item.compliance_result_id} className="hover:bg-gray-800/30 transition-colors">
                      <td className="px-5 py-4 text-gray-200">{item.control_id.replace(/_/g, " ")}</td>
                      <td className="px-5 py-4 text-gray-300">{item.resource_label}</td>
                      <td className="px-5 py-4 text-gray-400">{formatDt(item.executed_at)}</td>
                      <td className="px-5 py-4">
                        <StatusBadge value={item.status} />
                      </td>
                      <td className="px-5 py-4">
                        <Button
                          variant="secondary"
                          size="sm"
                          loading={actionId === item.compliance_result_id}
                          disabled={!item.can_rollback}
                          onClick={() => handleRollback(item)}
                        >
                          <RotateCcw size={12} /> Rollback
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
