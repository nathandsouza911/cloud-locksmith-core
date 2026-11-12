"""Workflow Definition Registry — Sprint 3.

Workflows are **data**, not code. A ``WorkflowDefinition`` declares what a
workflow *is*; nothing here executes, schedules or tracks anything.

    The registry answers:            "What is this workflow?"
    The Workflow Engine will answer: "What happened when this workflow ran?"

Those responsibilities stay separate. A definition therefore carries **no
execution state** — no schedule, no assignee, no due date, no status, no
progress. ``test_cadence_is_descriptive_only_and_carries_no_schedule`` fails the
build if any of those leak in.

Adding a workflow
-----------------
Append a ``WorkflowDefinition`` to ``_DEFINITIONS``. No business logic changes:
the work queue, delta engine, review API and library page all resolve through
this registry. The integrity tests will tell you if the definition is
inconsistent with the control registry.

Why code-defined rather than a database table
---------------------------------------------
These definitions are *product* configuration, not *customer* configuration —
they ship with the release, are reviewed in code review, and must stay in step
with ``CONTROL_REGISTRY`` (integrity tests enforce that). Putting them in a table
now would add a migration, a cache, and a class of drift bugs with no customer
able to edit them yet. When MSP-authored workflows arrive, this module becomes
the seed data for that table and the lookup contract below does not change —
which is the point of routing every consumer through ``get_workflow`` /
``resolve_workflow_id`` rather than through a dict literal.
"""

from __future__ import annotations

from dataclasses import dataclass, field

UNGROUPED_WORKFLOW_ID = "GENERAL_REVIEW"


class WorkflowCategory:
    IDENTITY = "IDENTITY"
    ACCESS_CONTROL = "ACCESS_CONTROL"
    RESILIENCE = "RESILIENCE"
    EXPOSURE = "EXPOSURE"
    COST = "COST"
    REPORTING = "REPORTING"
    OTHER = "OTHER"

    ALL = frozenset({IDENTITY, ACCESS_CONTROL, RESILIENCE, EXPOSURE, COST, REPORTING, OTHER})


class ReviewMode:
    """How a technician works through this workflow's items."""

    #: One decision per resource (e.g. per OAuth grant).
    PER_RESOURCE = "PER_RESOURCE"
    #: One decision for the whole tenant-level setting.
    PER_TENANT = "PER_TENANT"
    #: Read-and-acknowledge; there is nothing to decide per item.
    SUMMARY = "SUMMARY"

    ALL = frozenset({PER_RESOURCE, PER_TENANT, SUMMARY})


class EvidenceStrategy:
    """How this workflow's evidence fingerprint is derived.

    Mirrors the behaviour already implemented in ``evidence_fingerprint``; this
    field documents the intent so the library page can explain it.
    """

    MATERIAL_KEYS = "MATERIAL_KEYS"
    FULL_PAYLOAD = "FULL_PAYLOAD"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class EffortModel:
    """Estimated technician effort. Temporary — replaced by measured time
    (``workflow_time_entries``) once the Workflow Engine records it."""

    base_minutes: int
    minutes_per_item: int
    cap_minutes: int = 240


@dataclass(frozen=True)
class ReviewAction:
    """One button a technician can press, and what it stores.

    The label is presentation. ``decision`` is a ``ReviewDecision`` value and is
    what lands in Review Memory, so "Disable", "Remove" and "Restore" all store
    as REVOKE ("remediate now"). Keeping the enum stable is what lets workflows
    be added without touching the delta engine.
    """

    decision: str
    label: str
    description: str = ""


@dataclass(frozen=True)
class WorkflowDefinition:
    # ── Identity ────────────────────────────────────────────────────────────
    id: str
    key: str  # URL-safe slug
    name: str
    description: str
    category: str
    icon: str  # lucide-react icon name, resolved by the frontend

    # ── Scope ───────────────────────────────────────────────────────────────
    supported_controls: tuple[str, ...] = ()
    resource_types: tuple[str, ...] = ()
    review_modes: tuple[str, ...] = (ReviewMode.PER_RESOURCE,)

    # ── Presentation ────────────────────────────────────────────────────────
    recommended_action: str = ""
    default_priority: str = "NORMAL"
    display_order: int = 999
    enabled: bool = True
    review_actions: tuple[ReviewAction, ...] = ()

    # ── Capabilities (asserted against CONTROL_REGISTRY by the tests) ───────
    estimated_effort_model: EffortModel = field(default_factory=lambda: EffortModel(base_minutes=5, minutes_per_item=5))
    supports_delta: bool = True
    supports_reports: bool = False
    supports_remediation: bool = False
    supports_verification: bool = False
    supported_reports: tuple[str, ...] = ()
    report_type: str = ""

    # ── Descriptive metadata (informational only — never scheduling) ────────
    review_philosophy: str = ""
    typical_cadence: str = "AS_NEEDED"
    evidence_strategy: str = EvidenceStrategy.FULL_PAYLOAD
    recommended_role: str = "Technician"


_DEFINITIONS: tuple[WorkflowDefinition, ...] = (
    WorkflowDefinition(
        id="OAUTH_REVIEW",
        key="oauth-review",
        name="OAuth Review",
        description=(
            "Review the applications users have consented to and revoke anything "
            "that is not sanctioned. The highest-value recurring review: consent "
            "grants accumulate silently and are a primary tenant-compromise path."
        ),
        category=WorkflowCategory.IDENTITY,
        icon="KeyRound",
        supported_controls=(
            "IDENTITY_ILLICIT_CONSENT_GRANTS",
            "IDENTITY_USER_CONSENT_POLICY",
            "IDENTITY_OAUTH_APP_CONSENT_DISCOVERY",
        ),
        resource_types=("SERVICE_PRINCIPAL", "TENANT"),
        review_modes=(ReviewMode.PER_RESOURCE, ReviewMode.PER_TENANT),
        recommended_action="Review and revoke unapproved application consent",
        default_priority="HIGH",
        display_order=10,
        review_actions=(
            ReviewAction("KEEP", "Keep", "Sanctioned — leave the consent in place"),
            ReviewAction("REVOKE", "Revoke", "Delete this consent grant now"),
            ReviewAction("ESCALATE", "Escalate", "Needs a decision from someone else"),
            ReviewAction("IGNORE", "Ignore", "Deliberately taking no action"),
        ),
        report_type="OAUTH_REVIEW_SUMMARY",
        estimated_effort_model=EffortModel(base_minutes=5, minutes_per_item=4),
        supports_delta=True,
        supports_reports=True,
        supports_remediation=True,
        supports_verification=True,
        supported_reports=("CLIENT_SUMMARY", "INSURANCE_EVIDENCE"),
        review_philosophy=(
            "Only new and materially changed grants need attention. Previously "
            "approved applications stay settled until their scopes, publisher or "
            "consent scope change."
        ),
        typical_cadence="MONTHLY",
        evidence_strategy=EvidenceStrategy.MATERIAL_KEYS,
        recommended_role="Security Technician",
    ),
    WorkflowDefinition(
        id="ADMIN_REVIEW",
        key="admin-review",
        name="Admin Access Review",
        description=(
            "Confirm every privileged role assignment is still required and "
            "properly protected. Produces the attestation auditors and insurers "
            "ask for."
        ),
        category=WorkflowCategory.IDENTITY,
        icon="ShieldCheck",
        supported_controls=(
            "IDENTITY_ADMIN_NO_MFA",
            "IDENTITY_ADMIN_COUNT_EXCESS",
            "IDENTITY_OVERPRIVILEGED_USER",
            "IDENTITY_PERMANENT_ROLE_ASSIGNMENT",
            "IDENTITY_ADMIN_NO_PHISHING_RESISTANT_MFA",
        ),
        resource_types=("USER", "TENANT"),
        review_modes=(ReviewMode.PER_RESOURCE,),
        recommended_action="Review privileged accounts and remove unnecessary access",
        default_priority="HIGH",
        display_order=20,
        review_actions=(
            ReviewAction("KEEP", "Keep", "Reviewed and accepted as-is"),
            ReviewAction("REVOKE", "Fix now", "Remediate this item now"),
            ReviewAction("ESCALATE", "Escalate", "Needs a decision from someone else"),
            ReviewAction("IGNORE", "Ignore", "Deliberately taking no action"),
        ),
        report_type="ADMIN_REVIEW_SUMMARY",
        estimated_effort_model=EffortModel(base_minutes=10, minutes_per_item=5),
        supports_delta=True,
        supports_reports=True,
        supports_remediation=True,
        supports_verification=True,
        supported_reports=("CLIENT_SUMMARY", "INSURANCE_EVIDENCE", "QBR"),
        review_philosophy=(
            "Privilege is reviewed per person. A role assignment that has not "
            "changed since the last attestation does not need re-justifying."
        ),
        typical_cadence="QUARTERLY",
        evidence_strategy=EvidenceStrategy.MATERIAL_KEYS,
        recommended_role="Senior Technician",
    ),
    WorkflowDefinition(
        id="GUEST_REVIEW",
        key="guest-review",
        name="Guest Access Review",
        description=(
            "Review external guests and remove stale access. Guest accounts "
            "outlive the projects that justified them."
        ),
        category=WorkflowCategory.IDENTITY,
        icon="UserPlus",
        # CA_GUEST_MFA is a Conditional Access control, but the work a
        # technician performs is a guest review — group by workflow, not by
        # control family.
        supported_controls=("IDENTITY_GUEST_INVITES_OPEN", "CA_GUEST_MFA"),
        resource_types=("USER", "TENANT"),
        review_modes=(ReviewMode.PER_RESOURCE, ReviewMode.PER_TENANT),
        recommended_action="Review external guests and remove stale access",
        default_priority="NORMAL",
        display_order=30,
        review_actions=(
            ReviewAction("KEEP", "Keep", "Reviewed and accepted as-is"),
            ReviewAction("REVOKE", "Fix now", "Remediate this item now"),
            ReviewAction("ESCALATE", "Escalate", "Needs a decision from someone else"),
            ReviewAction("IGNORE", "Ignore", "Deliberately taking no action"),
        ),
        report_type="GUEST_REVIEW_SUMMARY",
        estimated_effort_model=EffortModel(base_minutes=5, minutes_per_item=3),
        supports_delta=True,
        supports_reports=True,
        supports_remediation=True,
        supports_verification=True,
        supported_reports=("CLIENT_SUMMARY",),
        review_philosophy=(
            "Guests are reviewed individually; a guest whose access and sponsor " "are unchanged stays settled."
        ),
        typical_cadence="QUARTERLY",
        evidence_strategy=EvidenceStrategy.MATERIAL_KEYS,
        recommended_role="Technician",
    ),
    WorkflowDefinition(
        id="IDENTITY_HYGIENE",
        key="identity-hygiene",
        name="Identity Hygiene",
        description=(
            "Routine identity cleanup: dormant accounts, stale service "
            "principals, expiring app secrets and MFA coverage gaps."
        ),
        category=WorkflowCategory.IDENTITY,
        icon="Sparkles",
        supported_controls=(
            "IDENTITY_USER_NO_MFA",
            "IDENTITY_UNUSED_ACCOUNT",
            "IDENTITY_PASSWORD_NEVER_EXPIRES",
            "IDENTITY_STALE_SERVICE_PRINCIPAL",
            "IDENTITY_SERVICE_ACCOUNT_INTERACTIVE_LOGIN",
            "IDENTITY_APP_SECRET_EXPIRING_SOON",
        ),
        resource_types=("USER", "SERVICE_PRINCIPAL", "TENANT"),
        review_modes=(ReviewMode.PER_RESOURCE,),
        recommended_action=("Clean up dormant accounts, stale service principals and MFA gaps"),
        default_priority="NORMAL",
        display_order=40,
        review_actions=(
            ReviewAction("KEEP", "Keep", "Account is legitimate and stays as-is"),
            ReviewAction("REVOKE", "Disable", "Disable or clean up this identity now"),
            ReviewAction("ESCALATE", "Escalate", "Needs a decision from someone else"),
            ReviewAction("IGNORE", "Ignore", "Deliberately taking no action"),
        ),
        report_type="IDENTITY_HYGIENE_SUMMARY",
        estimated_effort_model=EffortModel(base_minutes=5, minutes_per_item=3),
        supports_delta=True,
        supports_reports=True,
        supports_remediation=True,
        supports_verification=True,
        supported_reports=("CLIENT_SUMMARY", "INSURANCE_EVIDENCE"),
        review_philosophy=(
            "High-volume, low-ceremony. Most items are safe to action in bulk; "
            "the review exists to catch the exceptions."
        ),
        typical_cadence="MONTHLY",
        evidence_strategy=EvidenceStrategy.MATERIAL_KEYS,
        recommended_role="Technician",
    ),
    WorkflowDefinition(
        id="CONDITIONAL_ACCESS_REVIEW",
        key="conditional-access-review",
        name="Conditional Access Review",
        description=(
            "Confirm Conditional Access policies still enforce the intended " "baseline, and close coverage gaps."
        ),
        category=WorkflowCategory.ACCESS_CONTROL,
        icon="Lock",
        supported_controls=(
            "CA_MFA_ALL_USERS",
            "CA_MFA_ADMINS",
            "CA_LEGACY_AUTH_BLOCK",
            "CA_DEVICE_CODE_FLOW_BLOCK",
            "CA_AUTHENTICATION_TRANSFER_BLOCK",
            "CA_HIGH_RISK_SIGN_IN_BLOCK",
            "CA_RISK_BASED_STEP_UP_MFA",
        ),
        resource_types=("TENANT",),
        review_modes=(ReviewMode.PER_TENANT,),
        recommended_action="Review Conditional Access coverage and close policy gaps",
        default_priority="HIGH",
        display_order=50,
        review_actions=(
            ReviewAction("KEEP", "Keep", "Reviewed and accepted as-is"),
            ReviewAction("REVOKE", "Fix now", "Remediate this item now"),
            ReviewAction("ESCALATE", "Escalate", "Needs a decision from someone else"),
            ReviewAction("IGNORE", "Ignore", "Deliberately taking no action"),
        ),
        report_type="CONDITIONAL_ACCESS_REVIEW_SUMMARY",
        estimated_effort_model=EffortModel(base_minutes=10, minutes_per_item=8),
        supports_delta=True,
        supports_reports=True,
        supports_remediation=True,
        supports_verification=True,
        supported_reports=("CLIENT_SUMMARY", "INSURANCE_EVIDENCE", "QBR"),
        review_philosophy=(
            "Policy-level rather than resource-level. The valuable signal is "
            "what changed in CA since the last review, and who changed it."
        ),
        typical_cadence="QUARTERLY",
        evidence_strategy=EvidenceStrategy.FULL_PAYLOAD,
        recommended_role="Senior Technician",
    ),
    WorkflowDefinition(
        id="BREAK_GLASS_REVIEW",
        key="break-glass-review",
        name="Break-Glass Review",
        description=(
            "Verify emergency access accounts remain valid, excluded from "
            "restrictive policy, and that any use of them was justified."
        ),
        category=WorkflowCategory.RESILIENCE,
        icon="LifeBuoy",
        supported_controls=(
            "IDENTITY_BREAK_GLASS_ACCOUNT",
            "IDENTITY_BREAK_GLASS_USAGE",
            "CA_BREAK_GLASS_EXCLUSION",
        ),
        resource_types=("USER", "TENANT"),
        review_modes=(ReviewMode.PER_RESOURCE, ReviewMode.PER_TENANT),
        recommended_action="Verify emergency access accounts and justify any usage",
        default_priority="HIGH",
        display_order=60,
        review_actions=(
            ReviewAction("KEEP", "Keep", "Reviewed and accepted as-is"),
            ReviewAction("REVOKE", "Fix now", "Remediate this item now"),
            ReviewAction("ESCALATE", "Escalate", "Needs a decision from someone else"),
            ReviewAction("IGNORE", "Ignore", "Deliberately taking no action"),
        ),
        report_type="BREAK_GLASS_REVIEW_SUMMARY",
        estimated_effort_model=EffortModel(base_minutes=5, minutes_per_item=6),
        supports_delta=True,
        supports_reports=True,
        supports_remediation=True,
        supports_verification=True,
        supported_reports=("CLIENT_SUMMARY", "INSURANCE_EVIDENCE"),
        review_philosophy=(
            "Low volume, high consequence. Every use of a break-glass account "
            "must be explained, not merely acknowledged."
        ),
        typical_cadence="QUARTERLY",
        evidence_strategy=EvidenceStrategy.FULL_PAYLOAD,
        recommended_role="Senior Technician",
    ),
    WorkflowDefinition(
        id="TENANT_EXPOSURE_REVIEW",
        key="tenant-exposure-review",
        name="Tenant Exposure Review",
        description=(
            "Review external exposure and unexpected mail flow — forwarding "
            "rules and sharing configuration that leak data quietly."
        ),
        category=WorkflowCategory.EXPOSURE,
        icon="Radar",
        supported_controls=("IDENTITY_MAIL_FORWARDING_RULE",),
        resource_types=("USER",),
        review_modes=(ReviewMode.PER_RESOURCE,),
        recommended_action="Review external exposure and unexpected mail flow",
        default_priority="NORMAL",
        display_order=70,
        review_actions=(
            ReviewAction("KEEP", "Keep", "Reviewed and accepted as-is"),
            ReviewAction("REVOKE", "Fix now", "Remediate this item now"),
            ReviewAction("ESCALATE", "Escalate", "Needs a decision from someone else"),
            ReviewAction("IGNORE", "Ignore", "Deliberately taking no action"),
        ),
        estimated_effort_model=EffortModel(base_minutes=5, minutes_per_item=5),
        supports_delta=True,
        supports_reports=False,
        # Detection only today — no executor is registered for this control, so
        # the definition must not promise remediation.
        supports_remediation=False,
        supports_verification=False,
        review_philosophy=(
            "Detect and document. Remediation is manual until an executor " "exists for these controls."
        ),
        typical_cadence="MONTHLY",
        evidence_strategy=EvidenceStrategy.MATERIAL_KEYS,
        recommended_role="Technician",
    ),
    WorkflowDefinition(
        id="LICENSE_CLEANUP",
        key="license-cleanup",
        name="License Cleanup",
        description=(
            "Reclaim unused and over-provisioned licences. Sourced from the "
            "licence optimiser rather than from compliance findings."
        ),
        category=WorkflowCategory.COST,
        icon="Receipt",
        # Intentionally empty: licence findings live in `license_findings`, not
        # `compliance_results`. Wiring that second source is Sprint 4 work.
        supported_controls=(),
        resource_types=("USER",),
        review_modes=(ReviewMode.PER_RESOURCE,),
        recommended_action="Reclaim unused and over-provisioned licences",
        default_priority="NORMAL",
        display_order=80,
        report_type="LICENSE_CLEANUP_SUMMARY",
        estimated_effort_model=EffortModel(base_minutes=5, minutes_per_item=2),
        # No findings source wired yet, so no delta to compute.
        supports_delta=False,
        supports_reports=True,
        supports_remediation=False,
        supports_verification=False,
        supported_reports=("CLIENT_SUMMARY",),
        review_philosophy=("Cost review rather than security review. Decisions are reversible " "and low risk."),
        typical_cadence="MONTHLY",
        evidence_strategy=EvidenceStrategy.NOT_APPLICABLE,
        recommended_role="Technician",
    ),
    WorkflowDefinition(
        id="WEEKLY_SECURITY_REVIEW",
        key="weekly-security-review",
        name="Weekly Security Review",
        description=(
            "Summarise the week: work completed, posture movement, new risks "
            "and outstanding items. An aggregate review rather than a queue of "
            "resources."
        ),
        category=WorkflowCategory.REPORTING,
        icon="FileBarChart2",
        supported_controls=(),
        resource_types=("TENANT",),
        review_modes=(ReviewMode.SUMMARY,),
        recommended_action="Review the week's activity and send the client summary",
        default_priority="NORMAL",
        display_order=90,
        report_type="WEEKLY_SECURITY_REVIEW_SUMMARY",
        estimated_effort_model=EffortModel(base_minutes=10, minutes_per_item=10),
        # Aggregate workflow: there are no per-resource findings to diff.
        supports_delta=False,
        supports_reports=True,
        supports_remediation=False,
        supports_verification=False,
        supported_reports=("WEEKLY_REVIEW", "CLIENT_SUMMARY", "QBR"),
        review_philosophy=("Read, adjust, send. The value is the narrative, not a list of " "decisions."),
        typical_cadence="WEEKLY",
        evidence_strategy=EvidenceStrategy.NOT_APPLICABLE,
        recommended_role="Technician",
    ),
    WorkflowDefinition(
        id=UNGROUPED_WORKFLOW_ID,
        key="general-review",
        name="General Security Review",
        description=(
            "Fallback for controls not yet assigned to a workflow. A finding "
            "landing here means the registry needs a definition, not that the "
            "finding should be hidden."
        ),
        category=WorkflowCategory.OTHER,
        icon="CircleHelp",
        supported_controls=(),
        resource_types=("TENANT", "USER", "SERVICE_PRINCIPAL"),
        review_modes=(ReviewMode.PER_RESOURCE,),
        recommended_action="Review finding and decide on action",
        default_priority="NORMAL",
        display_order=1000,
        # Never advertised in the library — it is an implementation detail.
        enabled=False,
        estimated_effort_model=EffortModel(base_minutes=0, minutes_per_item=5),
        supports_delta=True,
        review_philosophy="Triage into a real workflow.",
        typical_cadence="AS_NEEDED",
        evidence_strategy=EvidenceStrategy.FULL_PAYLOAD,
        recommended_role="Technician",
    ),
)


WORKFLOW_REGISTRY: dict[str, WorkflowDefinition] = {definition.id: definition for definition in _DEFINITIONS}

_BY_KEY: dict[str, WorkflowDefinition] = {definition.key: definition for definition in _DEFINITIONS}

# Reverse index built once at import: control_id -> workflow_id.
_CONTROL_TO_WORKFLOW: dict[str, str] = {
    control_id: definition.id for definition in _DEFINITIONS for control_id in definition.supported_controls
}

WORKFLOW_DISPLAY_ORDER: tuple[str, ...] = tuple(
    definition.id for definition in sorted(_DEFINITIONS, key=lambda d: d.display_order)
)


def all_workflows(*, include_disabled: bool = False) -> list[WorkflowDefinition]:
    """Every definition, ordered for display."""
    definitions = sorted(_DEFINITIONS, key=lambda d: d.display_order)
    if include_disabled:
        return list(definitions)
    return [definition for definition in definitions if definition.enabled]


def get_workflow(workflow_id: str | None) -> WorkflowDefinition:
    """Resolve a definition by id, falling back to the general bucket."""
    if not workflow_id:
        return WORKFLOW_REGISTRY[UNGROUPED_WORKFLOW_ID]
    return WORKFLOW_REGISTRY.get(workflow_id, WORKFLOW_REGISTRY[UNGROUPED_WORKFLOW_ID])


def get_workflow_by_key(key: str | None) -> WorkflowDefinition | None:
    """Resolve a definition by its URL slug."""
    return _BY_KEY.get(key) if key else None


def resolve_workflow_id(control_id: str | None) -> str:
    """Which workflow owns a control, or the fallback bucket."""
    if not control_id:
        return UNGROUPED_WORKFLOW_ID
    return _CONTROL_TO_WORKFLOW.get(control_id, UNGROUPED_WORKFLOW_ID)


def controls_for(workflow_id: str | None) -> tuple[str, ...]:
    """Controls declared by a workflow. Empty for unknown ids."""
    if not workflow_id or workflow_id not in WORKFLOW_REGISTRY:
        return ()
    return WORKFLOW_REGISTRY[workflow_id].supported_controls


def review_actions_for(workflow_id: str | None) -> tuple[ReviewAction, ...]:
    """Review actions declared by a workflow. Empty for unknown ids."""
    if not workflow_id or workflow_id not in WORKFLOW_REGISTRY:
        return ()
    return WORKFLOW_REGISTRY[workflow_id].review_actions
