"use client";

import { useEffect, useState } from "react";
import { Button, Card } from "@/components/ui";
import { getChangeRecords } from "@/lib/api/endpoints";
import type { ChangeRecord } from "@/types";

function show(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

function when(iso: string | null | undefined): string {
  return iso ? new Date(iso).toLocaleString() : "—";
}

/** Fetch every change record for the tenant and save it as a JSON file. */
export async function downloadChangeRecords(): Promise<void> {
  const body = await getChangeRecords({});
  const blob = new Blob([JSON.stringify(body, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "cloud-locksmith-change-records.json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

export default function ChangeRecordPanel({
  complianceResultId,
  onClose,
}: {
  complianceResultId: number;
  onClose: () => void;
}) {
  const [record, setRecord] = useState<ChangeRecord | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getChangeRecords({ compliance_result_id: complianceResultId })
      .then((body) => {
        if (!cancelled) setRecord(body.records[0] ?? null);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Could not load the change record.");
      });
    return () => {
      cancelled = true;
    };
  }, [complianceResultId]);

  return (
    <Card className="p-5 space-y-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm font-semibold text-gray-200">Change record</p>
        <Button variant="ghost" size="sm" onClick={onClose}>
          Close
        </Button>
      </div>

      {error && (
        <p role="alert" className="text-sm text-red-400">
          {error}
        </p>
      )}
      {record === undefined && !error && <p className="text-sm text-gray-400">Loading…</p>}
      {record === null && <p className="text-sm text-gray-400">No change record for this fix.</p>}

      {record && (
        <>
          <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-xs text-gray-500">Executed by</dt>
              <dd className="text-gray-200">
                {record.executed_by ?? "Not recorded (before this was tracked)"}
              </dd>
            </div>
            <div>
              <dt className="text-xs text-gray-500">Executed at</dt>
              <dd className="text-gray-200">{when(record.executed_at)}</dd>
            </div>
            <div>
              <dt className="text-xs text-gray-500">Approved by</dt>
              <dd className="text-gray-200">{record.approval?.approved_by ?? "—"}</dd>
            </div>
            <div>
              <dt className="text-xs text-gray-500">Approved at</dt>
              <dd className="text-gray-200">{when(record.approval?.approved_at)}</dd>
            </div>
            <div>
              <dt className="text-xs text-gray-500">Verification</dt>
              <dd className="text-gray-200">
                {record.verification.verified === true
                  ? "Verified"
                  : record.verification.verified === false
                    ? "Not verified"
                    : "Unknown"}
              </dd>
            </div>
            <div>
              <dt className="text-xs text-gray-500">Rollback</dt>
              <dd className="text-gray-200">
                {record.rollback
                  ? `Rolled back ${when(record.rollback.rolled_back_at)} by ${record.rollback.requested_by ?? "—"}`
                  : "Not rolled back"}
              </dd>
            </div>
          </dl>

          {record.changes.length === 0 ? (
            <p className="text-sm text-gray-400">No setting-level changes recorded for this fix.</p>
          ) : (
            <div className="overflow-x-auto">
              <table aria-label="Changed settings" className="w-full text-xs">
                <thead>
                  <tr className="border-b border-gray-800 text-left text-gray-400">
                    <th className="px-3 py-2 font-semibold">Setting</th>
                    <th className="px-3 py-2 font-semibold">Before</th>
                    <th className="px-3 py-2 font-semibold">After</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/50">
                  {record.changes.map((change) => (
                    <tr key={change.setting}>
                      <td className="px-3 py-2 font-mono text-gray-200 break-all">{change.setting}</td>
                      <td className="px-3 py-2 font-mono text-red-300 break-all">{show(change.before)}</td>
                      <td className="px-3 py-2 font-mono text-green-300 break-all">{show(change.after)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </Card>
  );
}
