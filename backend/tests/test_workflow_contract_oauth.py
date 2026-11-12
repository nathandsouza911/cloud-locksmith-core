"""OAuth Review against the shared workflow contract.

The fan-out workflow and the 1:1 workflow assert identical behaviour — that is
the point of the abstraction.
"""

from app.db.models.compliance_result import ComplianceResult, ExposureStatus
from app.services.workflows._shared.resource_key import ResourceKey

# Import for the registration side effect: the projector must be registered
# before the shared session is asked to serve this workflow.
import app.services.workflows.oauth_review  # noqa: F401
from tests.workflows.contract import WorkflowContractTests

CONTROL = "IDENTITY_ILLICIT_CONSENT_GRANTS"


class TestOAuthReviewContract(WorkflowContractTests):
    workflow_id = "OAUTH_REVIEW"

    def create_resources(self, session, resource_ids, tenant_id="t1"):
        """One tenant-level finding carrying every requested grant."""
        finding = (
            session.query(ComplianceResult)
            .filter(
                ComplianceResult.tenant_id == tenant_id,
                ComplianceResult.control_id == CONTROL,
            )
            .one_or_none()
        )
        grants = [
            {
                "id": resource_id,
                "clientId": f"app-{resource_id}",
                "resourceId": "r1",
                "principalId": "u1",
                "consentType": "Principal",
                "scope": "Mail.Read",
                "app_display_name": f"App {resource_id}",
            }
            for resource_id in resource_ids
        ]
        if finding is None:
            session.add(
                ComplianceResult(
                    tenant_id=tenant_id,
                    control_id=CONTROL,
                    resource_type="TENANT",
                    resource_id=tenant_id,
                    passed=False,
                    severity="CRITICAL",
                    exposure_status=ExposureStatus.ACTIVE.value,
                    evidence={"illicit_grants": grants},
                )
            )
        else:
            finding.evidence = {"illicit_grants": [*finding.evidence["illicit_grants"], *grants]}
        session.commit()

    def key_for(self, resource_id):
        return ResourceKey(CONTROL, resource_id)
