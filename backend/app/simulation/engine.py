from __future__ import annotations

from typing import Any

from app.simulation.conflict_detector import ConflictDetector
from app.simulation.decision_engine import evaluate_user_access
from app.simulation.identity_expander import IdentityExpander
from app.simulation.impact_analyzer import ImpactAnalyzer
from app.simulation.policy_evaluator import get_applicable_policies
from app.simulation.policy_parser import ConditionalAccessPolicy, PolicyParser


class SimulationEngine:
    """Placeholder orchestration engine for future simulation execution."""

    def __init__(
        self,
        policy_parser: PolicyParser | None = None,
        identity_expander: IdentityExpander | None = None,
        conflict_detector: ConflictDetector | None = None,
        impact_analyzer: ImpactAnalyzer | None = None,
    ) -> None:
        self.policy_parser = policy_parser or PolicyParser()
        self.identity_expander = identity_expander or IdentityExpander()
        self.conflict_detector = conflict_detector or ConflictDetector()
        self.impact_analyzer = impact_analyzer or ImpactAnalyzer()

    def run_simulation(
        self,
        tenant_snapshot: dict[str, Any],
        proposed_change: dict[str, Any],
        role_mapping: dict[str, list[str]],
    ) -> dict[str, Any]:
        policies = tenant_snapshot.get("policies", [])
        merged_policies = self._merge_proposed_change(policies, proposed_change)
        users = self._extract_users(tenant_snapshot.get("users", []))
        group_map = self._normalize_membership_map(tenant_snapshot.get("groups", {}))
        role_map = self._normalize_membership_map(tenant_snapshot.get("roles", {}))
        expander = IdentityExpander(group_map=group_map, role_map=role_map)

        decisions: list[dict[str, Any]] = []
        for user_id in users:
            applicable_policies = get_applicable_policies(
                user_id=user_id,
                policies=merged_policies,
                group_map=group_map,
                role_map=role_map,
            )
            decisions.append(
                evaluate_user_access(
                    user_id=user_id,
                    applicable_policies=applicable_policies,
                )
            )

        blocked_user_ids = [decision["user_id"] for decision in decisions if decision["result"] == "BLOCKED"]
        mfa_required_user_ids = [decision["user_id"] for decision in decisions if decision["result"] == "MFA_REQUIRED"]
        unaffected_user_ids = [decision["user_id"] for decision in decisions if decision["result"] == "ALLOW"]
        impacted_user_ids = self._normalize_string_list(blocked_user_ids + mfa_required_user_ids)

        admin_user_ids = self._extract_admin_users(role_mapping)
        impacted_admins = self._count_impacted_admins(
            impacted_user_ids,
            admin_user_ids,
        )
        blocked_admins = len(set(blocked_user_ids) & set(admin_user_ids))
        mfa_required_admins = len(set(mfa_required_user_ids) & set(admin_user_ids))

        risk_level = self._determine_risk_level(
            total_users=len(users),
            blocked_users=len(blocked_user_ids),
            blocked_admins=blocked_admins,
            mfa_required_admins=mfa_required_admins,
        )
        conflicts = self.conflict_detector.detect(
            [self._policy_to_conflict_input(policy, expander) for policy in merged_policies]
        )
        impact = self.impact_analyzer.analyze(
            expanded_user_ids=impacted_user_ids,
            role_mapping=role_mapping,
        )

        return {
            "status": "completed",
            "risk_level": risk_level,
            "blocked_users": len(blocked_user_ids),
            "mfa_required_users": len(mfa_required_user_ids),
            "unaffected_users": len(unaffected_user_ids),
            "impacted_users": len(impacted_user_ids),
            "impacted_admins": impacted_admins,
            "conflicts": conflicts,
            "impact": impact,
        }

    def _merge_proposed_change(
        self,
        policies: list[dict[str, Any]],
        proposed_change: dict[str, Any],
    ) -> list[ConditionalAccessPolicy]:
        parsed_policies = self.policy_parser.parse_many([policy for policy in policies if isinstance(policy, dict)])

        if not isinstance(proposed_change, dict) or not proposed_change:
            return parsed_policies

        parsed_change = self.policy_parser.parse(proposed_change)
        for index, existing_policy in enumerate(parsed_policies):
            if existing_policy.id and existing_policy.id == parsed_change.id:
                parsed_policies[index] = parsed_change
                return parsed_policies

        parsed_policies.append(parsed_change)
        return parsed_policies

    def _count_impacted_admins(
        self,
        impacted_users: list[str],
        admin_user_ids: list[str],
    ) -> int:
        admin_set = set(self._normalize_string_list(admin_user_ids))
        return sum(1 for user_id in impacted_users if user_id in admin_set)

    @staticmethod
    def _determine_risk_level(
        *,
        total_users: int,
        blocked_users: int,
        blocked_admins: int,
        mfa_required_admins: int,
    ) -> str:
        if blocked_admins > 0:
            return "critical"
        if mfa_required_admins > 0:
            return "medium"
        if total_users > 0 and (blocked_users / total_users) > 0.2:
            return "high"
        return "low"

    @staticmethod
    def _normalize_string_list(values: list[Any]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()

        for value in values:
            if not isinstance(value, str):
                continue
            cleaned = value.strip()
            if not cleaned or cleaned in seen:
                continue
            seen.add(cleaned)
            normalized.append(cleaned)

        return normalized

    def _policy_to_conflict_input(
        self,
        policy: ConditionalAccessPolicy,
        expander: IdentityExpander,
    ) -> dict[str, Any]:
        return {
            "id": policy.id,
            "user_ids": expander.resolve_all_users(
                {
                    "include_users": policy.users,
                    "include_groups": policy.groups,
                    "include_roles": policy.roles,
                }
            ),
            "grant_controls": policy.grant_controls,
        }

    def _extract_users(self, users: Any) -> list[str]:
        if not isinstance(users, list):
            return []

        extracted: list[str] = []
        for user in users:
            if isinstance(user, str):
                extracted.append(user)
            elif isinstance(user, dict):
                user_id = user.get("id") or user.get("user_id")
                if isinstance(user_id, str):
                    extracted.append(user_id)

        return self._normalize_string_list(extracted)

    def _normalize_membership_map(self, mapping: Any) -> dict[str, list[str]]:
        if not isinstance(mapping, dict):
            return {}

        normalized: dict[str, list[str]] = {}
        for object_id, members in mapping.items():
            if not isinstance(object_id, str):
                continue
            normalized[object_id] = self._normalize_string_list(members if isinstance(members, list) else [])

        return normalized

    def _extract_admin_users(self, role_mapping: dict[str, list[str]]) -> list[str]:
        admin_users: list[str] = []

        for role_name, user_ids in role_mapping.items():
            if not isinstance(role_name, str) or "admin" not in role_name.lower():
                continue
            admin_users.extend(user_ids)

        return self._normalize_string_list(admin_users)
