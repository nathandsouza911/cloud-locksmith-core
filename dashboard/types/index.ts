// ─── Auth & Tenant ───────────────────────────────────────────────────────────

export interface AuthState {
  authenticated: boolean;
  tenant_id: string;
}

export interface UserTenantAccessItem {
  tenant_id: string;
  tenant_name: string;
  role: string;
  account_type?: "SMB" | "MSP";
  status?: "Connected" | "Needs Re-auth";
  needs_reauth?: boolean;
  last_token_refresh?: string | null;
  token_expires_at?: string | null;
}

export interface TenantOut {
  id: string;
  tenant_name?: string;
  tenant_identifier: string;
  created_at?: string;
  asset_flags?: Record<string, unknown>;
}

export interface LicenseSummary {
  currency: "USD" | string;
  total_waste: number;
  inactive_users_cost: number;
  overlicensed_cost: number;
  unused_license_cost: number;
}

export interface LicenseFinding {
  id: string;
  type: "inactive_user" | "overlicensed_user" | "unused_license";
  tenant_id: string;
  user_id: string | null;
  license_type: string;
  currency: "USD" | string;
  estimated_monthly_cost: number;
  metadata: Record<string, unknown>;
  created_at: string | null;
}

export interface LicenseFindingsResponse {
  tenant_id: string;
  total: number;
  findings: LicenseFinding[];
}

export interface LicenseScanResponse {
  status: string;
  tenant_id: string;
  snapshot_id: string;
  scanned_at: string;
  summary: LicenseSummary;
  findings_count: number;
}

export interface ControlStateSnapshot {
  id: string;
  created_at: string | null;
  policy_count: number;
}

export interface ControlStateDetails {
  mode: string;
  rollout_phase: string;
  rollout_percentage: number;
  target_group_id: string | null;
  policy_version: number;
  status: string;
  last_applied_at: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface ControlStateResponse {
  control_id: string;
  tenant_id: string;
  state: ControlStateDetails | null;
  latest_snapshot: ControlStateSnapshot | null;
}

export interface ControlApplyResponse {
  status: string;
  verified: boolean;
  control_id: string;
  reason?: string;
  execution_id?: string;
  snapshot_id?: string;
  affected_users?: number;
}

export type ControlCapabilityMode = "auto" | "manual" | "blocked";

export interface ControlCapabilityDecision {
  allowed: boolean;
  mode: ControlCapabilityMode;
  reason: string;
  notes: string;
  ca_license_available?: boolean;
  license_note?: string;
}

export type ControlCapabilityMap = Record<string, ControlCapabilityDecision>;

// ─── Fleet ───────────────────────────────────────────────────────────────────

export interface FleetTenantPosture {
  tenant_id: string;
  tenant_name: string;
  posture_score: number | null;
  score_band?: ScoreBand | null;
  failed_controls: number;
  has_snapshot: boolean;
  status: "Active" | "Awaiting scan";
  latest_snapshot_at?: string | null;
  score_delta_7d?: number | null;
  percentile?: number | null;
  relative_position?: string | null;
}

export interface FleetPostureResponse {
  tenants: FleetTenantPosture[];
  fleet_avg_score?: number | null;
  fleet_size?: number;
}

export interface FleetOverviewTenant {
  tenant_id: string;
  tenant_name: string;
  risk_score: number | null;
  risk_score_band?: ScoreBand | null;
  critical_findings: number;
  mfa_coverage: number;
  last_scan: string | null;
}

export interface FleetOverviewAggregate {
  avg_risk: number;
  avg_risk_band?: ScoreBand | null;
  total_critical: number;
  tenant_count: number;
}

export interface FleetOverviewTopRisk {
  tenant_id: string;
  tenant_name: string;
  control_id: string;
  resource_id: string;
  severity: Severity;
  title: string;
}

export interface FleetOverviewResponse {
  tenants: FleetOverviewTenant[];
  aggregate: FleetOverviewAggregate;
  top_risks: FleetOverviewTopRisk[];
}

// ─── Risk Feed ────────────────────────────────────────────────────────────────

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type ScoreBand = "GOOD" | "MODERATE" | "HIGH" | "CRITICAL";

export interface RiskFeedItem {
  compliance_result_id: string;
  tenant_id: string;
  tenant_name: string;
  control_id: string;
  resource_type?: "USER" | "TENANT";
  resource_id: string;
  resource_name?: string | null;
  resource_email?: string | null;
  is_admin?: boolean;
  severity: Severity;
  available_roles?: Array<Record<string, unknown>>;
  current_roles?: Array<Record<string, unknown>>;
  exposure_status?: "ACTIVE" | "RESOLVED";
  remediation_status?: "PENDING" | "APPROVED" | "EXECUTING" | "SUCCESS" | "FAILED" | "BLOCKED" | "IGNORED";
  acknowledged?: boolean;
  acknowledged_at?: string | null;
  acknowledged_by?: string | null;
  requires_acknowledgment?: boolean;
  action?: {
    action: "acknowledge" | string;
    label: string;
  } | null;
  error_type?: RemediationErrorType | null;
  error_label?: string | null;
  requires_license?: boolean;
  license_available?: boolean;
  approval_status: "pending" | "approved";
  execution_status: "pending" | "executed";
  evaluated_at: string;
  impact_score?: number;
  priority_score?: number;
  is_attack_path?: boolean;
}

export interface AttackPath {
  id: string;
  name: string;
  severity: Severity;
  description: string;
  controls_triggered: string[];
  status: "ACTIVE";
}

export interface AttackPathSummary {
  total_paths: number;
  critical_paths: number;
  high_paths: number;
  affected_controls: string[];
  critical_controls: string[];
  paths: AttackPath[];
}

export interface AttackPathEstimatedImpact {
  score_before?: number;
  score_after?: number;
  score_increase?: number;
  paths_resolved?: number;
}

export interface AttackPathRemediationStep {
  step: number;
  control_id: string;
  title: string;
  status: "pending" | "completed" | "skipped";
  auto_executable: boolean;
  finding_ids: number[];
  active_finding_count: number;
}

export interface AttackPathRemediationPlan {
  path_id: string;
  name?: string;
  severity?: Severity;
  description?: string;
  estimated_impact?: AttackPathEstimatedImpact;
  steps: AttackPathRemediationStep[];
}

export interface AttackPathStepExecutionResult {
  finding_id: number;
  status: "completed" | "skipped" | "failed";
  verified: boolean;
  note?: string;
}

export interface AttackPathStepExecutionResponse {
  path_id: string;
  control_id: string;
  step: number;
  step_completed: boolean;
  status: "completed" | "failed";
  failed_finding_id?: number;
  error?: string;
  results: AttackPathStepExecutionResult[];
  remaining_active_findings?: number[];
}

export interface AttackPathExecuteAllResponse {
  path_id: string;
  message: string;
  completed_steps: string[];
  failed_step: string | null;
  partial: boolean;
  results: AttackPathStepExecutionResponse[];
}

export interface BulkRemediationResultItem {
  tenant_id: string;
  control_id: string;
  resource_id: string;
}

export interface BulkRemediationSkippedItem extends BulkRemediationResultItem {
  reason: string;
}

export interface BulkRemediationFailedItem extends BulkRemediationResultItem {
  error: string;
}

export interface BulkRemediationResponse {
  executed: BulkRemediationResultItem[];
  skipped: BulkRemediationSkippedItem[];
  failed: BulkRemediationFailedItem[];
}

export interface DirectoryUser {
  id: string;
  email: string | null;
  display_name: string | null;
  role: "Admin" | "User";
  roles: string[];
  enabled: boolean;
  last_activity: string | null;
  offboarding_status?: "PENDING" | "IN_PROGRESS" | "COMPLETED" | "REVERSED" | null;
  is_offboarded?: boolean;
  offboarding_completed_at?: string | null;
  risk_level: Severity | "NONE";
  risk_indicators: string[];
  open_findings: number;
}

export interface BreakGlassUsageEvent {
  id: number;
  tenant_id: string;
  user_id: string;
  user_principal_name: string | null;
  source_event_id: string;
  source: string;
  event_type: string;
  timestamp: string | null;
  ip_address: string | null;
  location: string | null;
  status: "success" | "failure" | "unknown";
  created_at: string | null;
}

export type SupportTicketType = "BUG" | "FEATURE" | "SUPPORT" | "BILLING" | "OTHER";
export type SupportTicketStatus = "OPEN" | "CLOSED";
export type SupportTicketPriority = "LOW" | "MEDIUM" | "HIGH";

export interface SupportTicket {
  id: string;
  tenant_id: string;
  user_id: string;
  type: SupportTicketType;
  status: SupportTicketStatus;
  priority: SupportTicketPriority | null;
  subject: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface SupportTicketCreatePayload {
  type: SupportTicketType;
  subject: string;
  description: string;
  priority?: SupportTicketPriority | null;
}

export type OffboardingSessionStatus = "PENDING" | "IN_PROGRESS" | "COMPLETED" | "REVERSED";
export type OffboardingStepType = "automated" | "manual";
export type OffboardingStepStatus = "pending" | "completed" | "failed";

export interface OffboardingStep {
  id: string;
  title: string;
  action: string;
  type: OffboardingStepType;
  status: OffboardingStepStatus;
  automation?: Record<string, unknown> | null;
  error?: string | null;
  disabled?: boolean;
  blocked_reason?: string | null;
}

export interface OffboardingSession {
  session_id: string;
  control_id: string;
  resource_id: string;
  status: OffboardingSessionStatus;
  steps: OffboardingStep[];
  snapshot?: Record<string, unknown> | null;
  current_step?: number;
  step_states?: string[];
  created_at?: string | null;
  offboarding_completed_at?: string | null;
  offboarding_reversed_at?: string | null;
  error?: string | null;
  retryable?: boolean;
}

// ─── Compliance ───────────────────────────────────────────────────────────────

export type DecisionStatus =
  | "PENDING"
  | "APPROVED"
  | "EXECUTED"
  | "VERIFIED"
  | "RESOLVED"
  | "ROLLED_BACK"
  | "BLOCKED"
  | "AUTO_REMEDIATED"
  | "ACKNOWLEDGED"
  | "FAILED"
  | "FAILED_SAFE";

export type BlockReason =
  | "PRIVILEGED_USER"
  | "POLICY_RESTRICTION"
  | "BREAK_GLASS_PROTECTION"
  | "INSUFFICIENT_PERMISSIONS"
  | "INSUFFICIENT_SCOPE"
  | "UNKNOWN";

export type RemediationErrorType =
  | "INSUFFICIENT_PERMISSIONS"
  | "INSUFFICIENT_SCOPE"
  | "INVALID_PAYLOAD"
  | "RESOURCE_NOT_FOUND"
  | "POLICY_RESTRICTION"
  | "UNKNOWN";

export interface FindingGuidance {
  title?: string;
  severity?: string;
  summary?: string;
  manual_steps?: string | string[];
}

export interface ComplianceResult {
  id: string;
  tenant_id: string;
  control_id: string;
  resource_type?: "USER" | "TENANT";
  resource_id: string;
  passed: boolean;
  severity: Severity;
  evidence: Record<string, unknown> | string;
  available_roles?: Array<Record<string, unknown>>;
  current_roles?: Array<Record<string, unknown>>;
  exposure_status?: "ACTIVE" | "RESOLVED";
  remediation_status?: "PENDING" | "APPROVED" | "EXECUTING" | "SUCCESS" | "FAILED" | "BLOCKED" | "IGNORED";
  decision_status: DecisionStatus;
  acknowledged?: boolean;
  acknowledged_at?: string | null;
  acknowledged_by?: string | null;
  requires_acknowledgment?: boolean;
  action?: {
    action: "acknowledge" | string;
    label: string;
  } | null;
  block_reason?: BlockReason | null;
  error_type?: RemediationErrorType | null;
  error_label?: string | null;
  evaluated_at: string;
  requires_license?: boolean;
  license_available?: boolean;
  executable?: boolean;
  rollback_supported?: boolean;
  guidance?: string | FindingGuidance;
  remediation_cta?: {
    label: string;
    method: "POST";
    endpoint: string;
    supports_dry_run?: boolean;
    supports_approval_flow?: boolean;
  } | null;
}

export interface ExecuteRemediationResponse {
  status: string;
  reason?: string;
  message?: string;
  error?: string;
  error_type?: RemediationErrorType;
  remediation_status?: "PENDING" | "APPROVED" | "EXECUTING" | "SUCCESS" | "FAILED" | "BLOCKED" | "IGNORED";
  exposure_status?: "ACTIVE" | "RESOLVED";
  compliance_result_id?: string | number;
  tenant_id?: string;
  control_id?: string;
  evaluated_at?: string | null;
}

export interface BreakGlassCreateResponse {
  status: "preview" | "executed" | string;
  control_id?: string;
  compliance_result_id?: string | number;
  accounts_to_create: number;
  policies_to_modify: string[];
  approval_required?: boolean;
  preview?: Record<string, unknown>;
  created_accounts?: Array<{
    username: string;
    user_principal_name?: string;
    display_name?: string;
    password: string;
    password_revealed?: boolean;
  }>;
  password_revealed?: boolean;
  credentials_delivery?: string;
  reason?: string;
  message?: string;
}

// ─── Posture ──────────────────────────────────────────────────────────────────

export interface PostureSnapshot {
  timestamp: string;
  security_score: number;
  posture: Record<string, unknown>;
}

export interface PostureTimelinePoint {
  timestamp: string;
  score: number;
}

export interface PostureTrendPoint {
  date: string;
  score: number;
}

export interface PostureTrend {
  tenant_id: string;
  trend: PostureTrendPoint[];
}

export interface NormalizedTimelinePoint {
  date: string;
  score: number | null;
}

export interface TimelineTrendSummary {
  label: "Improving" | "Declining" | "Stable";
  delta: number;
  direction: "up" | "down" | "flat";
  summary: string;
}

// ─── Remediation ─────────────────────────────────────────────────────────────

export interface RemediationDecisionStats {
  total: number;
  pending_approvals: number;
  auto_remediated: number;
  blocked: number;
  executed: number;
  failed: number;
  verified: number;
  rolled_back: number;
}

/**
 * Matches the actual backend RemediationAuditLog / decision shape.
 * Fields verified against app/api/routes/remediation_decisions.py
 */
export interface RemediationDecision {
  id: number;
  control_id: string;
  /** The decision value: "PENDING" | "APPROVED" | "EXECUTED" etc. */
  decision: string;
  severity: string;
  approved: boolean;
  created_at: string;
  /** Present when the backend includes the compliance result join */
  compliance_result_id?: string;
  evidence?: Record<string, unknown> | string;
}

export interface RemediationPriorityItem {
  compliance_result_id: string;
  priority_score: number;
}

export interface RemediationTimelineItem {
  timestamp: string;
  tenant_name: string;
  control_id: string;
  action: string;
  snapshot_id: string;
}

export interface RemediationHistoryItem {
  compliance_result_id: number;
  control_id: string;
  resource_id: string;
  resource_label: string;
  status: "SUCCESS" | "REVERSED";
  executed_at: string | null;
  can_rollback: boolean;
  snapshot_available: boolean;
}

export interface RemediationAuditEvent {
  event_type: string;
  timestamp: string;
  metadata: Record<string, unknown>;
}

export interface EligibilityResponse {
  allowed?: boolean;
  executable?: boolean;
  eligible?: boolean;
  reason?: string;
  block_reason?: BlockReason | null;
  execution?: unknown;
}

export interface VerifyResponse {
  verified: boolean;
  reason: string;
  evidence: unknown;
  verified_at: string;
}

// ─── Reports ──────────────────────────────────────────────────────────────────

export interface TopRisk {
  control_id: string;
  name: string;
  short_name: string;
  severity: string;
  narrative?: string;
}

export interface ExecutiveSummary {
  tenant_name: string;
  posture_score: number | null;
  score_band?: ScoreBand | null;
  total_findings: number;
  critical_findings: number;
  remediations_last_30_days: number;
  top_risks: TopRisk[];
}

export interface EvidenceReport {
  id?: string | number;
  report_id: string;
  generated_at: string;
  score: number;
  score_band: string;
  reporting_period: string;
  report_payload_id?: number | null;
}

export interface InsuranceReadiness {
  readiness: string;
  score: number;
  blocking_issues: string[];
  summary: string;
  recommendation: string;
}

export interface AttestationObject {
  report_id: number;
  tenant_id: string;
  report_type: string;
  generated_at: string | null;
  attested_at: string;
  score: number | null;
  content_hash: string;
  chain_hash: string | null;
  system_version: string;
  controls_summary: Record<string, number>;
}

export interface AttestationResponse {
  report_id: number;
  attestation: AttestationObject;
  signature: string;
  signature_valid: boolean;
}

export interface HistoricalComparison {
  previous_score: number | null;
  current_score: number | null;
  delta: number | null;
  improvement_summary: string | null;
}

export interface ArchivedReportResponse {
  archived: boolean;
  report_id: number;
  generated_at: string | null;
  content_hash: string | null;
  report_type: string;
  score: number | null;
  payload: {
    historical_comparison?: HistoricalComparison;
    top_risks?: string[];
    header?: Record<string, unknown>;
    [key: string]: unknown;
  };
}

// ─── Audit ────────────────────────────────────────────────────────────────────

export interface AuditLog {
  id: string;
  action: string;
  actor: string;
  target: string;
  status: string;
  reason: string;
  details: Record<string, unknown>;
  created_at: string;
}

export interface ScanStatusResponse {
  tenant_id: string;
  last_scan_at: string | null;
  last_scheduler_run: string | null;
  scheduler_failures: number;
  in_progress: boolean;
  has_completed_scan: boolean;
}

// Compliance Dashboard types
export type ControlStatus = "PASS" | "FAIL" | "PARTIAL" | "NOT_APPLICABLE";

export interface FrameworkSummary {
  id: string;
  name: string;
  version: string;
  kind: "authored" | "derived";
  pass_count: number;
  fail_count: number;
  partial_count: number;
  not_applicable_count: number;
  total_mapped_controls: number;
}

export interface ControlDashboardRow {
  control_id: string;
  framework_id: string;
  framework_name: string;
  reference_id: string;
  label: string;
  mapping_strength: "direct" | "partial" | "evidence" | "informational";
  evidence_type: string;
  nist_csf_functions: string[];
  status: ControlStatus;
}

export interface ComplianceDashboardResponse {
  frameworks: FrameworkSummary[];
  controls: ControlDashboardRow[];
}
