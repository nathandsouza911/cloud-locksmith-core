// Sprint 3 — read-only workflow library.
//
// Mirrors app/schemas/workflow.py. This describes the catalogue of workflow
// *types* the platform knows how to run (OAuth Review, Guest Access Review,
// ...) — not any particular tenant's outstanding work. Informational only;
// there is no create/edit/delete here.

export type WorkflowCategory =
  | "IDENTITY"
  | "ACCESS_CONTROL"
  | "RESILIENCE"
  | "EXPOSURE"
  | "COST"
  | "REPORTING"
  | "OTHER";

export type ReviewMode = "PER_RESOURCE" | "PER_TENANT" | "SUMMARY";

export type WorkflowCadence = "MONTHLY" | "QUARTERLY" | "WEEKLY" | "AS_NEEDED";

export type EvidenceStrategy = "MATERIAL_KEYS" | "FULL_PAYLOAD" | "NOT_APPLICABLE";

export interface EffortModel {
  base_minutes: number;
  minutes_per_item: number;
  cap_minutes: number;
}

export interface WorkflowDefinition {
  id: string;
  key: string;
  name: string;
  description: string;
  category: string;
  icon: string;
  supported_controls: string[];
  resource_types: string[];
  review_modes: string[];
  default_priority: "HIGH" | "NORMAL";
  display_order: number;
  enabled: boolean;
  estimated_effort: EffortModel;
  supports_delta: boolean;
  supports_reports: boolean;
  supports_remediation: boolean;
  supports_verification: boolean;
  supported_reports: string[];
  review_philosophy: string;
  typical_cadence: string;
  evidence_strategy: string;
  recommended_role: string;
}

export interface WorkflowLibraryResponse {
  workflows: WorkflowDefinition[];
}

// ─── Workflow runtime (Sprint 4) ───────────────────────────────────────────
//
// A WorkflowRun is a single execution of a workflow definition for a tenant:
// discovery -> review -> execution -> verification. Mirrors
// app/schemas/workflow_run.py (backend, done).

export type RunState =
  | "CREATED"
  | "DISCOVERING"
  | "READY_FOR_REVIEW"
  | "IN_REVIEW"
  | "EXECUTING"
  | "VERIFYING"
  | "COMPLETED"
  | "FAILED"
  | "CANCELLED";

export type StageState = "PENDING" | "ACTIVE" | "COMPLETED" | "FAILED" | "SKIPPED";

export interface WorkflowStage {
  stage_key: string;
  sequence: number;
  state: StageState;
  started_at: string | null;
  completed_at: string | null;
}

export interface WorkflowRun {
  id: string;
  tenant_id: string;
  workflow_definition_key: string;
  workflow_name: string;
  trigger: string;
  state: RunState;
  current_stage: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  created_by: string | null;
  summary: Record<string, unknown>;
  stages: WorkflowStage[];
}

export interface RunStateChangePayload {
  state: RunState;
  summary?: Record<string, unknown>;
  reason?: string;
}

// Legal state transitions. The UI must only ever offer these — anything else
// is rejected by the backend with 409 Conflict.
export const LEGAL_RUN_TRANSITIONS: Record<RunState, RunState[]> = {
  CREATED: ["DISCOVERING", "FAILED", "CANCELLED"],
  DISCOVERING: ["READY_FOR_REVIEW", "FAILED", "CANCELLED"],
  READY_FOR_REVIEW: ["IN_REVIEW", "COMPLETED", "FAILED", "CANCELLED"],
  IN_REVIEW: ["EXECUTING", "COMPLETED", "FAILED", "CANCELLED"],
  EXECUTING: ["VERIFYING", "COMPLETED", "FAILED", "CANCELLED"],
  VERIFYING: ["COMPLETED", "FAILED", "CANCELLED"],
  COMPLETED: [],
  FAILED: [],
  CANCELLED: [],
};

// ─── Wave 2 — the generic workflow review surface ────────────────────────────
//
// One response shape for every workflow. What differs between workflows is
// data (labels, risk prose, facts), never structure — that is what lets one
// screen serve all of them.

import type { DeltaState } from "./work";

/** One button a technician can press. Labels are per-workflow; the decision
 *  value is what the platform stores. */
export interface WorkflowReviewAction {
  decision: string;
  label: string;
  description: string;
}

export interface WorkflowResourceFact {
  label: string;
  value: unknown;
  emphasis: boolean;
}

export interface WorkflowReviewResource {
  control_id: string;
  resource_id: string;
  resource_type: string;
  title: string;
  subtitle: string | null;
  risk_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  risk_explanation: string;
  risk_drivers: string[];
  recommended_action: string;
  facts: WorkflowResourceFact[];
  evidence: Record<string, unknown>;
  evidence_hash: string;
  compliance_result_id: number | null;
  delta_state: DeltaState | null;
  previous_decision: string | null;
  previous_reviewed_by: string | null;
  previous_reviewed_at: string | null;
}

export interface WorkflowReviewResponse {
  tenant_id: string;
  workflow: {
    id: string;
    key: string;
    name: string;
    description: string;
    category: string;
    icon: string;
    review_philosophy: string;
    supports_remediation: boolean;
    supports_reports: boolean;
  };
  review_actions: WorkflowReviewAction[];
  run: {
    id: string;
    state: RunState;
    current_stage: string | null;
    started_at: string | null;
    completed_at: string | null;
    created_by: string;
    summary: Record<string, unknown>;
  };
  stages: {
    stage_key: string;
    state: string;
    started_at: string | null;
    completed_at: string | null;
  }[];
  progress: {
    total_resources: number;
    reviewed_resources: number;
    remaining_resources: number;
    percent_complete: number;
    is_complete: boolean;
  };
  resources: WorkflowReviewResource[];
  next_resource_id: string | null;
}

export interface WorkflowRemediationSimulation {
  control_id: string;
  selected_resource_ids: string[];
  changes: {
    resource_id: string;
    title: string;
    resource_type: string;
    recommended_action: string;
    risk_level: string;
  }[];
  reversible: boolean;
  rollback_strategy: string;
  requires_confirmation: boolean;
  summary: string;
}
