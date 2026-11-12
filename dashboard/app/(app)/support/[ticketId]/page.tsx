"use client";

import { useRouter } from "next/navigation";
import { ArrowLeft, Clock3, LifeBuoy, Tag } from "lucide-react";

import { Button, Card, ErrorState, PageHeader, StatusBadge, TableSkeleton } from "@/components/ui";
import { useSupportTicket } from "@/lib/api/hooks";
import { useAuth } from "@/lib/auth-context";
import type { SupportTicketPriority, SupportTicketType } from "@/types";

const TYPE_LABELS: Record<SupportTicketType, string> = {
  BUG: "Bug Report",
  FEATURE: "Feature Suggestion",
  SUPPORT: "Support Request",
  BILLING: "Billing Issue",
  OTHER: "Other",
};

const PRIORITY_LABELS: Record<SupportTicketPriority, string> = {
  LOW: "Low",
  MEDIUM: "Medium",
  HIGH: "High",
};

function formatDate(value: string | null): string {
  if (!value) return "Unknown";
  return new Date(value).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function MetaCard({ icon, label, value }: { icon: React.ReactNode; label: string; value: React.ReactNode }) {
  return (
    <Card className="p-4">
      <div className="flex items-center gap-3">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gray-800 text-gray-300">
          {icon}
        </div>
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-gray-500">{label}</p>
          <div className="mt-1 text-sm text-gray-100">{value}</div>
        </div>
      </div>
    </Card>
  );
}

export default function SupportTicketDetailPage({ params }: { params: { ticketId: string } }) {
  const router = useRouter();
  const { tenantId } = useAuth();
  const ticketQuery = useSupportTicket(params.ticketId, tenantId);
  const ticket = ticketQuery.data;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-1">
        <Button variant="ghost" size="sm" onClick={() => router.push("/support")}>
          <ArrowLeft size={13} /> Back
        </Button>
      </div>

      <PageHeader
        title={ticket?.subject ?? "Support Request"}
        subtitle={ticket ? `Ticket ID: ${ticket.id}` : "Loading support request details"}
      />

      {ticketQuery.loading ? (
        <TableSkeleton rows={4} cols={2} />
      ) : ticketQuery.error ? (
        <ErrorState message={ticketQuery.error} />
      ) : !ticket ? (
        <ErrorState message="Ticket not found" />
      ) : (
        <>
          <div className="grid gap-4 md:grid-cols-3">
            <MetaCard icon={<LifeBuoy size={16} />} label="Type" value={TYPE_LABELS[ticket.type]} />
            <MetaCard
              icon={<Tag size={16} />}
              label="Priority"
              value={ticket.priority ? PRIORITY_LABELS[ticket.priority] : "Not specified"}
            />
            <MetaCard icon={<Clock3 size={16} />} label="Submitted" value={formatDate(ticket.created_at)} />
          </div>

          <Card className="p-6">
            <div className="flex flex-col gap-3 border-b border-gray-800 pb-4 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <p className="text-sm font-semibold text-gray-200">Submission Details</p>
                <p className="mt-1 text-xs text-gray-500">
                  This is the exact request currently stored for your ticket.
                </p>
              </div>
              <StatusBadge value={ticket.status} />
            </div>

            <div className="mt-5 space-y-5">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">Subject</p>
                <p className="mt-2 text-sm text-gray-100">{ticket.subject}</p>
              </div>

              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">Description</p>
                <div className="mt-2 rounded-xl border border-gray-800 bg-gray-950/80 px-4 py-4">
                  <pre className="whitespace-pre-wrap break-words font-sans text-sm leading-6 text-gray-200">
                    {ticket.description}
                  </pre>
                </div>
              </div>
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
