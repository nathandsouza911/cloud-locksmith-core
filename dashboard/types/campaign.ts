// Campaign status values — exact strings returned by the backend.
// PLAN is transient; AWAITING_APPROVAL is the stable state until execute.
export type CampaignStatus =
  | "PLAN"
  | "AWAITING_APPROVAL"
  | "EXECUTING"
  | "COMPLETED"
  | "FAILED"
  | "CANCELLED"
  | "ROLLED_BACK";

// Task-level status values.
export type TaskStatus =
  | "PLANNED"
  | "SKIPPED"
  | "LOCK_DEFERRED"
  | "EXECUTING"
  | "EXECUTED"
  | "VERIFY_PENDING"
  | "VERIFIED"
  | "FAILED"
  | "ROLLED_BACK";

export interface CampaignTaskResourceDetail {
  resource_id: string | null;
  display_name: string | null;
  upn: string | null;
  last_sign_in: string | null;
}

export interface CampaignTaskChange {
  action: string;
  [key: string]: unknown;
}

export interface CampaignTaskResultJson {
  changes?: CampaignTaskChange[];
  [key: string]: unknown;
}

export interface CampaignTask {
  id: string;
  tenant_id: string;
  tenant_name: string | null;
  compliance_result_id: number;
  control_id: string;
  status: TaskStatus;
  attempts: number;
  audit_log_id: string | null;
  error: string | null;
  resource_detail: CampaignTaskResourceDetail | null;
  result_json?: CampaignTaskResultJson | null;
}

export interface CampaignPreviewItem {
  tenant_id: string;
  tenant_name: string | null;
  finding_count: number;
}

export interface CampaignPreviewResponse {
  items: CampaignPreviewItem[];
}

// Full campaign object returned by GET /fleet/campaigns/{id} and create/approve/execute/rollback/cancel.
export interface Campaign {
  campaign_id: string;
  status: CampaignStatus;
  control_ids: string[];
  dry_run: boolean;
  created_by: string;
  created_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  plan_hash: string | null;
  approved_plan_hash: string | null;
  approved_by: string | null;
  approved_at: string | null;
  total_tasks: number;
  tasks_by_status: Partial<Record<TaskStatus, number>>;
  tasks_executed: number;
  tasks_failed: number;
  tenants_affected: number;
  rollback_available: boolean;
  tasks: CampaignTask[];
}

// Payloads sent to the API.
export interface CreateCampaignPayload {
  control_ids: string[];
  target_tenant_ids: string[];
  dry_run?: boolean;
}

export interface ApproveCampaignPayload {
  expected_plan_hash: string;
}
