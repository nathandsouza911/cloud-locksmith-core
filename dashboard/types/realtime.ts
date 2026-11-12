export interface RealtimeEventBase {
  event_id: string;
  event_type: string;
  event_version: string;
  organization_id: string;
  occurred_at: string;
  payload: Record<string, unknown>;
}

export interface CampaignCreatedEvent extends RealtimeEventBase {
  event_type: "CampaignCreated";
  payload: {
    campaign_id: string;
    status: string;
    plan_hash: string;
    task_count: number;
    dry_run: boolean;
    created_by: string;
  };
}

export interface CampaignApprovedEvent extends RealtimeEventBase {
  event_type: "CampaignApproved";
  payload: { campaign_id: string; status: string; approved_by: string; approved_plan_hash: string };
}

export interface CampaignPartiallyApprovedEvent extends RealtimeEventBase {
  event_type: "CampaignPartiallyApproved";
  payload: {
    campaign_id: string;
    status: string;
    approved_by: string;
    approved_tenant_ids: string[];
    approved_plan_hash: string;
  };
}

export interface CampaignExecutingEvent extends RealtimeEventBase {
  event_type: "CampaignExecuting";
  payload: { campaign_id: string; status: string; started_at: string | null };
}

export interface CampaignCompletedEvent extends RealtimeEventBase {
  event_type: "CampaignCompleted";
  payload: { campaign_id: string; status: string; completed_at: string | null };
}

export interface CampaignRolledBackEvent extends RealtimeEventBase {
  event_type: "CampaignRolledBack";
  payload: { campaign_id: string; status: string };
}

export interface TaskExecutedEvent extends RealtimeEventBase {
  event_type: "TaskExecuted";
  payload: { task_id: string; tenant_id: string; control_id: string; campaign_id: string };
}

export interface TaskFailedEvent extends RealtimeEventBase {
  event_type: "TaskFailed";
  payload: {
    task_id: string;
    tenant_id: string;
    control_id: string;
    campaign_id: string;
    error: string | null;
  };
}

export interface RemediationFailureEvent extends RealtimeEventBase {
  event_type: "RemediationFailure";
  payload: {
    task_id: string;
    tenant_id: string;
    control_id: string;
    campaign_id: string;
    error: string | null;
  };
}

export interface TaskLockDeferredEvent extends RealtimeEventBase {
  event_type: "TaskLockDeferred";
  payload: { task_id: string; tenant_id: string; campaign_id: string };
}

export interface ScheduledJobCreatedEvent extends RealtimeEventBase {
  event_type: "ScheduledJobCreated";
  payload: { job_id: string; campaign_id: string; scheduled_at: string | null };
}

export interface ScheduledJobClaimedEvent extends RealtimeEventBase {
  event_type: "ScheduledJobClaimed";
  payload: { job_id: string; campaign_id: string };
}

export interface ScheduledJobExecutedEvent extends RealtimeEventBase {
  event_type: "ScheduledJobExecuted";
  payload: { job_id: string; campaign_id: string };
}

export interface ScheduledJobFailedEvent extends RealtimeEventBase {
  event_type: "ScheduledJobFailed";
  payload: { job_id: string; campaign_id: string; error: string };
}

export interface ScheduledJobRecoveredEvent extends RealtimeEventBase {
  event_type: "ScheduledJobRecovered";
  payload: { job_id: string; campaign_id: string };
}

export type RealtimeEvent =
  | CampaignCreatedEvent
  | CampaignApprovedEvent
  | CampaignPartiallyApprovedEvent
  | CampaignExecutingEvent
  | CampaignCompletedEvent
  | CampaignRolledBackEvent
  | TaskExecutedEvent
  | TaskFailedEvent
  | RemediationFailureEvent
  | TaskLockDeferredEvent
  | ScheduledJobCreatedEvent
  | ScheduledJobClaimedEvent
  | ScheduledJobExecutedEvent
  | ScheduledJobFailedEvent
  | ScheduledJobRecoveredEvent;
