"""Identity Hygiene against the shared workflow contract.

Note what is *not* here: no projector, no discovery code, no delta handling. The
workflow uses the default FindingProjector, so passing this suite demonstrates
the abstraction rather than the workflow.
"""

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.services.workflows._shared.resource_key import ResourceKey

# Import for the registration side effect.
import app.services.workflows.identity_hygiene  # noqa: F401
from tests.workflows.contract import WorkflowContractTests

CONTROL = "IDENTITY_USER_NO_MFA"


class TestIdentityHygieneContract(WorkflowContractTests):
    workflow_id = "IDENTITY_HYGIENE"

    def create_resources(self, session, resource_ids, tenant_id="t1"):
        for resource_id in resource_ids:
            session.add(
                ComplianceResult(
                    tenant_id=tenant_id,
                    control_id=CONTROL,
                    resource_type="USER",
                    resource_id=resource_id,
                    passed=False,
                    severity="HIGH",
                    exposure_status=ExposureStatus.ACTIVE.value,
                    evidence={"user_principal_name": f"{resource_id}@contoso.com"},
                )
            )
        session.commit()

    def key_for(self, resource_id):
        return ResourceKey(CONTROL, resource_id)
