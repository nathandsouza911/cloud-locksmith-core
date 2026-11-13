import logging

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from app.services.ca_policy_states import CA_POLICY_STATES

logger = logging.getLogger(__name__)


class ConditionalAccessUsersCondition(BaseModel):
    includeUsers: list[str] = Field(default_factory=list)
    excludeUsers: list[str] = Field(default_factory=list)
    includeRoles: list[str] = Field(default_factory=list)
    excludeRoles: list[str] = Field(default_factory=list)
    includeGroups: list[str] = Field(default_factory=list)
    excludeGroups: list[str] = Field(default_factory=list)
    includeGuestsOrExternalUsers: dict | None = None
    excludeGuestsOrExternalUsers: dict | None = None

    @model_validator(mode="after")
    def validate_target_presence(self):
        has_guest_scope = self.includeGuestsOrExternalUsers is not None
        if not self.includeUsers and not self.includeRoles and not self.includeGroups and not has_guest_scope:
            raise ValueError(
                "Conditional Access users condition requires includeUsers, includeRoles, includeGroups, or includeGuestsOrExternalUsers"
            )
        return self


class ConditionalAccessApplicationsCondition(BaseModel):
    includeApplications: list[str] = Field(default_factory=list)
    excludeApplications: list[str] = Field(default_factory=list)


class ConditionalAccessAuthenticationFlowsCondition(BaseModel):
    transferMethods: list[str] | str | None = None


class ConditionalAccessConditions(BaseModel):
    users: ConditionalAccessUsersCondition
    applications: ConditionalAccessApplicationsCondition | None = None
    clientAppTypes: list[str] = Field(default_factory=list)
    authenticationFlows: ConditionalAccessAuthenticationFlowsCondition | None = None


class ConditionalAccessGrantControls(BaseModel):
    operator: str = "OR"
    builtInControls: list[str] = Field(default_factory=list)
    authenticationStrength: dict | None = None

    @model_validator(mode="after")
    def validate_controls(self):
        if not self.builtInControls and self.authenticationStrength is None:
            raise ValueError("grantControls requires builtInControls or authenticationStrength")
        return self


class ConditionalAccessPolicySchema(BaseModel):
    displayName: str
    state: str
    conditions: ConditionalAccessConditions
    grantControls: ConditionalAccessGrantControls

    @model_validator(mode="after")
    def validate_state(self):
        if self.state not in CA_POLICY_STATES:
            raise ValueError("Conditional Access state must be enabled, disabled, or enabledForReportingButNotEnforced")
        return self


class UserPatchSchema(BaseModel):
    accountEnabled: bool


class UserPasswordProfileSchema(BaseModel):
    forceChangePasswordNextSignIn: bool = False
    password: str


class UserCreateSchema(BaseModel):
    accountEnabled: bool
    displayName: str
    mailNickname: str
    userPrincipalName: str
    passwordProfile: UserPasswordProfileSchema


class DirectoryObjectReferenceSchema(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    odata_id: str = Field(alias="@odata.id")


class RoleEligibilityScheduleRequestSchema(BaseModel):
    principalId: str
    roleDefinitionId: str
    directoryScopeId: str
    assignmentType: str


class RoleAssignmentSchema(BaseModel):
    principalId: str
    roleDefinitionId: str
    directoryScopeId: str
    assignmentType: str


def validate_graph_payload(schema_cls, payload: dict, *, context: str):
    try:
        return schema_cls.model_validate(payload)
    except ValidationError as exc:
        logger.warning("graph_payload_validation_error context=%s errors=%s", context, exc.errors())
        raise
