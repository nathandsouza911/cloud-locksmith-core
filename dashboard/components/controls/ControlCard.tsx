"use client";

import { AlertTriangle, CheckCircle2, ShieldAlert } from "lucide-react";

import { capabilityModeClasses, capabilityModeLabel } from "@/lib/control-capabilities";
import { Button, Card, SeverityBadge } from "@/components/ui";
import type { ControlCapabilityMode, Severity } from "@/types";

export type { ControlDisplayStatus } from "@/lib/control-status";
import type { ControlDisplayStatus } from "@/lib/control-status";

interface ControlCardProps {
  controlId: string;
  title: string;
  description: string;
  severity: Severity;
  status: ControlDisplayStatus;
  actionLabel?: string | null;
  detail?: string | null;
  warning?: string | null;
  loading?: boolean;
  buttonLabel?: string;
  buttonDisabled?: boolean;
  buttonTooltip?: string;
  capabilityMode?: ControlCapabilityMode | null;
  capabilityNotes?: string | null;
  onFixNow: () => void;
}

const statusStyles: Record<ControlDisplayStatus, string> = {
  NOT_CONFIGURED: "border border-gray-700 bg-gray-800/80 text-gray-300",
  PARTIAL: "border border-yellow-500/30 bg-yellow-500/10 text-yellow-300",
  ENFORCED: "border border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
  COMPLIANT: "border border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
};

function statusIcon(status: ControlDisplayStatus) {
  if (status === "ENFORCED" || status === "COMPLIANT")
    return <CheckCircle2 size={14} className="text-emerald-300" />;
  if (status === "PARTIAL") return <AlertTriangle size={14} className="text-yellow-300" />;
  return <ShieldAlert size={14} className="text-gray-300" />;
}

export default function ControlCard({
  controlId,
  title,
  description,
  severity,
  status,
  actionLabel,
  detail,
  warning,
  loading = false,
  buttonLabel = "Fix Now",
  buttonDisabled = false,
  buttonTooltip,
  capabilityMode,
  capabilityNotes,
  onFixNow,
}: ControlCardProps) {
  return (
    <Card className="flex h-full flex-col p-5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-gray-100">{title}</h2>
          <p className="mt-1 text-[11px] font-mono text-gray-500">{controlId}</p>
        </div>
        <SeverityBadge value={severity} />
      </div>

      <div className="mt-4 flex-1 space-y-4">
        <p className="text-sm leading-6 text-gray-400">{description}</p>

        <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-gray-500">Current State</p>
          <div className="mt-2 flex items-center gap-2">
            {statusIcon(status)}
            <span
              className={`inline-flex items-center rounded-md px-2 py-1 text-[11px] font-semibold tracking-wide ${statusStyles[status]}`}
            >
              {status.replaceAll("_", " ")}
            </span>
          </div>
          {detail ? <p className="mt-2 text-xs text-gray-300">{detail}</p> : null}
          {actionLabel ? <p className="mt-2 text-xs text-gray-400">{actionLabel}</p> : null}
          {capabilityMode ? (
            <div className="mt-3 flex items-center gap-2">
              <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-gray-500">Execution</p>
              <span
                className={`inline-flex items-center rounded-md px-2 py-1 text-[11px] font-semibold tracking-wide ${capabilityModeClasses(
                  capabilityMode,
                )}`}
              >
                {capabilityModeLabel(capabilityMode)}
              </span>
            </div>
          ) : null}
          {warning ? <p className="mt-2 text-xs text-yellow-300">{warning}</p> : null}
          {capabilityNotes ? (
            <div className="mt-2 flex items-start gap-2 text-xs text-gray-300">
              <AlertTriangle size={12} className="mt-0.5 shrink-0 text-yellow-300" />
              <span>{capabilityNotes}</span>
            </div>
          ) : null}
        </div>
      </div>

      <div className="mt-5 flex items-center justify-end">
        <span title={buttonTooltip}>
          <Button
            variant={buttonDisabled ? "secondary" : "primary"}
            size="sm"
            loading={loading}
            disabled={buttonDisabled}
            onClick={onFixNow}
          >
            {buttonLabel}
          </Button>
        </span>
      </div>
    </Card>
  );
}
