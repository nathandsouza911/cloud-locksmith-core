from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel


class RemediationExplanationOut(BaseModel):
    summary: str
    key_factors: List[str]
    risk_note: str


class RemediationLifecycleOut(BaseModel):
    approved: bool
    approved_at: Optional[datetime]
    approved_by: Optional[str]

    execution_status: Optional[str]
    executed_at: Optional[datetime]
    verified: Optional[bool]
    rolled_back: Optional[bool]


class RemediationDecisionOut(BaseModel):
    id: str
    compliance_result_id: int
    tenant_id: str
    control_id: str
    resource_type: str
    resource_id: str
    decision: str
    confidence: float

    explanation: RemediationExplanationOut
    lifecycle: RemediationLifecycleOut

    created_at: datetime


from pydantic import BaseModel


class RemediationDecisionStatsOut(BaseModel):
    total: int
    pending_approvals: int
    auto_remediated: int
    blocked: int
    executed: int
    failed: int
    verified: int
    rolled_back: int
