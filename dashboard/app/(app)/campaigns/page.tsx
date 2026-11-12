"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Plus } from "lucide-react";
import { Button, Card, EmptyState, ErrorState, PageHeader, TableSkeleton } from "@/components/ui";
import { useAuth } from "@/lib/auth-context";
import { useCampaigns } from "@/lib/api/hooks";
import type { Campaign, CampaignStatus } from "@/types/campaign";

const TERMINAL_STATUSES: CampaignStatus[] = ["COMPLETED", "CANCELLED", "ROLLED_BACK"];

// ── Status badge ──────────────────────────────────────────────────────────────

const STATUS_LABEL: Record<CampaignStatus, string> = {
  PLAN: "Planning",
  AWAITING_APPROVAL: "Awaiting Approval",
  EXECUTING: "Executing",
  COMPLETED: "Completed",
  FAILED: "Failed",
  CANCELLED: "Cancelled",
  ROLLED_BACK: "Rolled Back",
};

const STATUS_CLASS: Record<CampaignStatus, string> = {
  PLAN: "bg-gray-700 text-gray-300",
  AWAITING_APPROVAL: "bg-yellow-900/60 text-yellow-300",
  EXECUTING: "bg-blue-900/60 text-blue-300",
  COMPLETED: "bg-green-900/60 text-green-300",
  FAILED: "bg-red-900/60 text-red-300",
  CANCELLED: "bg-gray-700 text-gray-400",
  ROLLED_BACK: "bg-purple-900/60 text-purple-300",
};

function StatusBadge({ status }: { status: CampaignStatus }) {
  return (
    <span
      className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-semibold ${STATUS_CLASS[status] ?? "bg-gray-700 text-gray-300"}`}
    >
      {STATUS_LABEL[status] ?? status}
    </span>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

function CampaignTable({ campaigns }: { campaigns: Campaign[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-800">
            {["Status", "Controls", "Tasks", "Created By", "Created At", ""].map((h) => (
              <th
                key={h}
                className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider whitespace-nowrap"
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800/50">
          {campaigns.map((c: Campaign) => (
            <tr key={c.campaign_id} className="hover:bg-gray-800/40 transition-colors">
              <td className="px-5 py-3.5">
                <StatusBadge status={c.status} />
              </td>
              <td className="px-5 py-3.5 text-gray-300 font-mono text-xs">{c.control_ids.join(", ")}</td>
              <td className="px-5 py-3.5 text-gray-300 tabular-nums">{c.total_tasks}</td>
              <td className="px-5 py-3.5 text-gray-400">{c.created_by}</td>
              <td className="px-5 py-3.5 text-gray-500 text-xs">
                {c.created_at ? new Date(c.created_at).toLocaleString() : "—"}
              </td>
              <td className="px-5 py-3.5">
                <Link href={`/campaigns/${c.campaign_id}`} data-testid="link">
                  <Button variant="secondary" size="sm">
                    View
                  </Button>
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function CampaignsPage() {
  const { isSmb } = useAuth();
  const router = useRouter();
  const { data: campaigns, loading, error } = useCampaigns();
  const [showArchived, setShowArchived] = useState(false);

  if (isSmb) {
    router.replace("/dashboard");
    return null;
  }

  const allCampaigns: Campaign[] = campaigns ?? [];
  const active = allCampaigns.filter((c) => !TERMINAL_STATUSES.includes(c.status));
  const archived = allCampaigns.filter((c) => TERMINAL_STATUSES.includes(c.status));
  const hasArchived = archived.length > 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Campaigns"
        subtitle="Fleet-wide remediation campaigns"
        actions={
          <Link href="/campaigns/new" data-testid="link">
            <Button variant="primary" size="sm">
              <Plus size={13} />
              New Campaign
            </Button>
          </Link>
        }
      />

      {loading ? (
        <TableSkeleton rows={5} cols={5} />
      ) : error ? (
        <ErrorState message={error} />
      ) : allCampaigns.length === 0 ? (
        <EmptyState message="No campaigns yet. Create one to start fleet-wide remediation." />
      ) : (
        <div className="space-y-4">
          {/* Active campaigns */}
          {active.length > 0 && (
            <Card>
              <CampaignTable campaigns={active} />
            </Card>
          )}

          {active.length === 0 && !showArchived && (
            <EmptyState message="No active campaigns. All campaigns have completed." />
          )}

          {/* Archived toggle */}
          {hasArchived && (
            <div className="flex items-center gap-3">
              <Button variant="ghost" size="sm" onClick={() => setShowArchived((v) => !v)}>
                {showArchived ? "Hide Archived" : "Show Archived"}
              </Button>
              <span className="text-xs text-gray-500">
                {archived.length} archived campaign{archived.length !== 1 ? "s" : ""}
              </span>
            </div>
          )}

          {/* Archived campaigns — shown when toggle is on */}
          {showArchived && archived.length > 0 && (
            <Card className="opacity-70">
              <div className="px-5 py-3 border-b border-gray-800">
                <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Archived</p>
              </div>
              <CampaignTable campaigns={archived} />
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
