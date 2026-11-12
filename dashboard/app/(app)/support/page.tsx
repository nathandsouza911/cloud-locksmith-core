"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { LifeBuoy, RefreshCw } from "lucide-react";

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
import { useSupportTickets } from "@/lib/api/hooks";
import { useAuth } from "@/lib/auth-context";
import type { SupportTicketCreatePayload, SupportTicketPriority, SupportTicketType } from "@/types";

const TYPE_OPTIONS: Array<{ label: string; value: SupportTicketType }> = [
  { label: "Bug Report", value: "BUG" },
  { label: "Feature Suggestion", value: "FEATURE" },
  { label: "Support Request", value: "SUPPORT" },
  { label: "Billing Issue", value: "BILLING" },
  { label: "Other", value: "OTHER" },
];

const PRIORITY_OPTIONS: Array<{ label: string; value: SupportTicketPriority }> = [
  { label: "Low", value: "LOW" },
  { label: "Medium", value: "MEDIUM" },
  { label: "High", value: "HIGH" },
];

function formatTicketType(value: SupportTicketType): string {
  return TYPE_OPTIONS.find((option) => option.value === value)?.label ?? value;
}

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

function trimFormValues(payload: SupportTicketCreatePayload) {
  return {
    ...payload,
    subject: payload.subject.trim(),
    description: payload.description.trim(),
    priority: payload.priority ?? null,
  };
}

export default function SupportPage() {
  const { tenantId } = useAuth();
  const ticketsQuery = useSupportTickets(tenantId);
  const [form, setForm] = useState<SupportTicketCreatePayload>({
    type: "BUG",
    subject: "",
    description: "",
    priority: null,
  });
  const [submitting, setSubmitting] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [validation, setValidation] = useState<{ subject?: string; description?: string }>({});

  useEffect(() => {
    if (!toast) return undefined;
    const timeout = window.setTimeout(() => setToast(null), 3000);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  const trimmed = useMemo(() => trimFormValues(form), [form]);

  function validate() {
    const nextErrors: { subject?: string; description?: string } = {};
    if (trimmed.subject.length < 5) {
      nextErrors.subject = "Subject must be at least 5 characters";
    }
    if (trimmed.description.length < 20) {
      nextErrors.description = "Description must be at least 20 characters";
    }
    setValidation(nextErrors);
    return Object.keys(nextErrors).length === 0;
  }

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setToast(null);
    setError(null);

    if (!validate()) return;

    setSubmitting(true);
    try {
      await ep.createSupportTicket(trimmed);
      setForm({
        type: "BUG",
        subject: "",
        description: "",
        priority: null,
      });
      setValidation({});
      setToast("Request submitted successfully");
      ticketsQuery.refetch();
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Request failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Support & Feedback"
        subtitle="Send product feedback, report issues, and track your recent requests."
        actions={
          <Button variant="secondary" size="sm" onClick={ticketsQuery.refetch} loading={ticketsQuery.loading}>
            <RefreshCw size={13} /> Refresh
          </Button>
        }
      />

      {toast ? (
        <Card className="border-cyan-500/30 bg-cyan-500/10 px-4 py-3 text-sm text-cyan-100">{toast}</Card>
      ) : null}

      {error ? (
        <Card className="border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">{error}</Card>
      ) : null}

      <Card className="p-6">
        <div className="mb-5 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-300">
            <LifeBuoy size={18} />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-gray-200">Submit a request</h2>
            <p className="mt-1 text-xs text-gray-500">
              Need screenshots or logs? Reply to the confirmation email after submitting.
            </p>
          </div>
        </div>

        <form className="space-y-4" onSubmit={handleSubmit}>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-1.5">
              <label className="text-xs font-medium uppercase tracking-wider text-gray-400">Type</label>
              <select
                value={form.type}
                onChange={(event) =>
                  setForm((current) => ({ ...current, type: event.target.value as SupportTicketType }))
                }
                className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2.5 text-sm text-gray-200 outline-none transition-colors focus:border-cyan-500"
              >
                {TYPE_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium uppercase tracking-wider text-gray-400">Severity</label>
              <select
                value={form.priority ?? ""}
                onChange={(event) =>
                  setForm((current) => ({
                    ...current,
                    priority: event.target.value ? (event.target.value as SupportTicketPriority) : null,
                  }))
                }
                className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2.5 text-sm text-gray-200 outline-none transition-colors focus:border-cyan-500"
              >
                <option value="">Not specified</option>
                {PRIORITY_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium uppercase tracking-wider text-gray-400">Subject</label>
            <input
              value={form.subject}
              onChange={(event) => setForm((current) => ({ ...current, subject: event.target.value }))}
              className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2.5 text-sm text-gray-200 outline-none transition-colors focus:border-cyan-500"
              placeholder="Briefly summarize the request"
            />
            {validation.subject ? <p className="text-xs text-red-400">{validation.subject}</p> : null}
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium uppercase tracking-wider text-gray-400">Description</label>
            <textarea
              value={form.description}
              onChange={(event) => setForm((current) => ({ ...current, description: event.target.value }))}
              rows={6}
              className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2.5 text-sm text-gray-200 outline-none transition-colors focus:border-cyan-500"
              placeholder="Share enough detail for us to understand the issue or idea."
            />
            {validation.description ? <p className="text-xs text-red-400">{validation.description}</p> : null}
          </div>

          <div className="rounded-lg border border-dashed border-gray-700 bg-gray-900/70 px-4 py-3">
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-gray-500">
              Attachments coming soon
            </p>
            <p className="mt-1 text-xs text-gray-400">
              Need screenshots or logs? Reply to the confirmation email after submitting.
            </p>
          </div>

          <div className="flex items-center justify-end">
            <Button variant="primary" size="sm" loading={submitting} disabled={!tenantId || submitting}>
              Submit
            </Button>
          </div>
        </form>
      </Card>

      <Card className="overflow-hidden">
        <div className="border-b border-gray-800 px-5 py-4">
          <p className="text-sm font-semibold text-gray-200">My Requests</p>
        </div>

        {ticketsQuery.loading ? (
          <div className="p-5">
            <TableSkeleton rows={5} cols={4} />
          </div>
        ) : ticketsQuery.error ? (
          <ErrorState message={ticketsQuery.error} />
        ) : (ticketsQuery.data ?? []).length === 0 ? (
          <EmptyState message="No requests submitted yet" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  {["Type", "Subject", "Status", "Created At"].map((heading) => (
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
                {(ticketsQuery.data ?? []).map((ticket) => (
                  <tr key={ticket.id} className="transition-colors hover:bg-gray-800/30">
                    <td className="px-5 py-4 text-gray-300">
                      <Link href={`/support/${ticket.id}`} className="block">
                        {formatTicketType(ticket.type)}
                      </Link>
                    </td>
                    <td className="px-5 py-4 text-gray-100">
                      <Link
                        href={`/support/${ticket.id}`}
                        className="block font-medium hover:text-cyan-300 transition-colors"
                      >
                        {ticket.subject}
                      </Link>
                    </td>
                    <td className="px-5 py-4">
                      <Link href={`/support/${ticket.id}`} className="block">
                        <StatusBadge value={ticket.status} />
                      </Link>
                    </td>
                    <td className="px-5 py-4 text-gray-400">
                      <Link href={`/support/${ticket.id}`} className="block">
                        {formatDate(ticket.created_at)}
                      </Link>
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
