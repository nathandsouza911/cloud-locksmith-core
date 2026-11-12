// Sprint 3 — client timeline.
//
// Mirrors app/schemas/timeline.py. A merged, chronological read of everything
// that has happened for a tenant across review decisions, remediation,
// verification, audit log, reports, posture snapshots and workflow runs.
// Read-only.

export type SourceSystem =
  | "REVIEW_DECISIONS"
  | "REMEDIATION"
  | "VERIFICATION"
  | "AUDIT_LOG"
  | "REPORTS"
  | "POSTURE_SNAPSHOT"
  | "WORKFLOW_RUN";

export type TimelineEventType =
  | "REVIEW_DECISION"
  | "REMEDIATION"
  | "VERIFICATION"
  | "AUDIT"
  | "REPORT_GENERATED"
  | "POSTURE_SNAPSHOT"
  | "WORKFLOW_RUN";

export interface TimelineEvent {
  id: string;
  tenant_id: string;
  timestamp: string;
  source_system: SourceSystem;
  event_type: TimelineEventType;
  action: string;
  title: string;
  description: string | null;
  actor: string | null;
  outcome: string | null;
  workflow_id: string | null;
  workflow_name: string | null;
  evidence_reference: string | null;
  control_id: string | null;
  resource_type: string | null;
  resource_id: string | null;
  metadata: Record<string, unknown>;
}

export interface TimelineResponse {
  tenant_id: string;
  tenant_name: string;
  events: TimelineEvent[];
  next_cursor: string | null;
  has_more: boolean;
}

export interface TimelineQueryParams {
  limit?: number;
  cursor?: string;
  workflow_id?: string;
  event_types?: string[];
  since?: string;
  until?: string;
}
