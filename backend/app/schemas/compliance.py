from pydantic import BaseModel
from datetime import datetime
from typing import Any, Optional


class FrameworkMappingItem(BaseModel):
    framework: str
    reference_id: str
    label: str


class ComplianceResultResponse(BaseModel):
    id: str
    control_id: str
    state: str
    exposure_status: str
    remediation_status: str

    auto_remediation_enabled: bool
    enforcement_mode: str

    drift_detected_at: Optional[datetime]
    drift_count: int
    last_verified_at: Optional[datetime]
    last_remediated_at: Optional[datetime]
    resolved_at: Optional[datetime]
    resolved_by: Optional[str]
    first_seen_at: Optional[datetime]
    last_seen_at: Optional[datetime]

    remediation_count_7d: int
    drift_lock: bool


class RiskFeedItemResponse(BaseModel):
    compliance_result_id: int
    tenant_id: str
    tenant_name: str
    control_id: str
    resource_type: str | None = None
    resource_id: str
    resource_name: str | None = None
    resource_email: str | None = None
    is_admin: bool = False
    severity: str | None = None
    available_roles: list[dict[str, Any]]
    current_roles: list[dict[str, Any]]
    exposure_status: str | None = None
    remediation_status: str | None = None
    error_type: str | None = None
    error_label: str | None = None
    resolved_at: Optional[datetime] = None
    resolved_by: str | None = None
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    drift_count: int | None = None
    labels: list[str]
    requires_license: bool
    license_available: bool
    approval_status: str
    execution_status: str
    evaluated_at: Optional[datetime] = None
    impact_score: float | int | None = None
    priority_score: float | int | None = None
    is_attack_path: bool = False
    framework_mappings: list[FrameworkMappingItem] = []
