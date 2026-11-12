// Sprint 1 — technician work queue.
//
// These mirror app/schemas/work.py. A WorkItem is a presentation model derived
// from an existing compliance result — it is not persisted server-side, so
// there is no id to round-trip and no write operations in this sprint.

export type WorkPriority = "HIGH" | "NORMAL";

// Sprint 2 — persistent review memory. Mirrors the DeltaState enum backing
// app/schemas/work.py: whether an item has been reviewed before, and whether
// the underlying evidence has changed since that review.
export type DeltaState = "NEW" | "PREVIOUSLY_REVIEWED" | "CHANGED" | "NEEDS_REVIEW" | "IGNORED" | "RESOLVED";

export type ReviewDecisionType = "KEEP" | "IGNORE" | "FIX" | "ESCALATE";

export interface WorkItem {
  id: number;
  tenant_id: string;
  tenant_name: string | null;
  title: string;
  category: string;
  severity: string;
  priority: WorkPriority;
  estimated_minutes: number;
  recommended_action: string;
  related_control: string;
  created_at: string | null;

  compliance_result_id: number;
  resource_type: string | null;
  resource_id: string | null;
  workflow_id: string;
  drift_count: number;

  delta_state: DeltaState;
  last_reviewed_at: string | null;
  last_reviewed_by: string | null;
  last_decision: ReviewDecisionType | null;
}

export interface WorkGroup {
  workflow_id: string;
  workflow_name: string;
  category: string;
  tenant_id: string;
  tenant_name: string | null;
  item_count: number;
  priority: WorkPriority;
  estimated_minutes: number;
  recommended_action: string;
  summary: string;
  cadence: string;
  items: WorkItem[];

  new_count: number;
  reviewed_count: number;
  changed_count: number;
  needs_attention_count: number;
  resolved_count: number;

  // Sprint 4 — workflow runtime. run_id is null if the workflow was never
  // opened (no run has been created yet).
  run_id: string | null;
  run_state: string | null;
  run_started_at: string | null;
}

export interface WorkQueueSummary {
  today_count: number;
  item_count: number;
  estimated_minutes: number;
  high_priority: number;
  normal_priority: number;
  completed: number;

  new_count: number;
  reviewed_count: number;
  changed_count: number;
  needs_attention_count: number;
}

export interface WorkQueue {
  tenant_id: string;
  tenant_name: string | null;
  generated_at: string;
  summary: WorkQueueSummary;
  groups: WorkGroup[];
}

// ─── Review memory (Sprint 2) ──────────────────────────────────────────────

export interface ReviewSubmitPayload {
  compliance_result_id: number;
  decision: ReviewDecisionType;
  reason?: string;
  workflow_type?: string;
}

export interface ReviewSubmitResponse {
  compliance_result_id: number;
  decision: ReviewDecisionType;
  reason?: string | null;
  reviewed_by?: string | null;
  reviewed_at?: string | null;
}

export interface WorkflowDeltaItem {
  delta_state: DeltaState;
  control_id: string;
  resource_type: string | null;
  resource_id: string | null;
  title: string;
  severity: string;
  compliance_result_id: number;
  last_decision: ReviewDecisionType | null;
  last_reviewed_by: string | null;
  last_reviewed_at: string | null;
}

// Sprint 4 — the run this delta was generated against. Calling the delta
// endpoint lazily creates a run if none is active for this workflow.
export interface WorkflowDeltaRun {
  id: string | null;
  state: string | null;
  started_at: string | null;
  current_stage: string | null;
  trigger: string | null;
  created_by: string | null;
}

export interface WorkflowDelta {
  tenant_id: string;
  workflow_id: string;
  workflow_name: string;
  generated_at: string;
  counts: Record<string, number>;
  needs_attention_count: number;
  reviewed_count: number;
  items: WorkflowDeltaItem[];
  run: WorkflowDeltaRun;
}
