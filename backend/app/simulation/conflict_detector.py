from __future__ import annotations

from typing import Any


class ConflictDetector:
    """Simple O(n^2) conflict detector for simulation policies."""

    def detect(self, policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        conflicts: list[dict[str, Any]] = []

        for index, left_policy in enumerate(policies):
            for right_policy in policies[index + 1 :]:
                overlapping_users = self._find_overlapping_users(left_policy, right_policy)
                if overlapping_users:
                    conflicts.append(
                        {
                            "type": "overlapping_users",
                            "policy_ids": [
                                left_policy.get("id"),
                                right_policy.get("id"),
                            ],
                            "users": overlapping_users,
                        }
                    )

                conflicting_controls = self._find_conflicting_grant_controls(
                    left_policy,
                    right_policy,
                )
                if conflicting_controls:
                    conflicts.append(
                        {
                            "type": "conflicting_grant_controls",
                            "policy_ids": [
                                left_policy.get("id"),
                                right_policy.get("id"),
                            ],
                            "grant_controls": conflicting_controls,
                        }
                    )

        return conflicts

    def _find_overlapping_users(
        self,
        left_policy: dict[str, Any],
        right_policy: dict[str, Any],
    ) -> list[str]:
        left_users = set(self._normalize_string_list(left_policy.get("user_ids", [])))
        right_users = set(self._normalize_string_list(right_policy.get("user_ids", [])))
        overlapping_users = sorted(left_users & right_users)

        if not overlapping_users:
            return []

        left_controls = set(self._normalize_string_list(left_policy.get("grant_controls", [])))
        right_controls = set(self._normalize_string_list(right_policy.get("grant_controls", [])))
        if "block" in left_controls and "mfa" in right_controls:
            return overlapping_users
        if "mfa" in left_controls and "block" in right_controls:
            return overlapping_users

        return []

    def _find_conflicting_grant_controls(
        self,
        left_policy: dict[str, Any],
        right_policy: dict[str, Any],
    ) -> list[dict[str, str]]:
        left_controls = set(self._normalize_string_list(left_policy.get("grant_controls", [])))
        right_controls = set(self._normalize_string_list(right_policy.get("grant_controls", [])))

        conflicting_pairs = [
            ("block", "mfa"),
            ("block", "compliantDevice"),
            ("block", "domainJoinedDevice"),
            ("passwordChange", "block"),
        ]

        conflicts: list[dict[str, str]] = []
        for left_control, right_control in conflicting_pairs:
            if (left_control in left_controls and right_control in right_controls) or (
                right_control in left_controls and left_control in right_controls
            ):
                conflicts.append(
                    {
                        "left": left_control,
                        "right": right_control,
                    }
                )

        return conflicts

    @staticmethod
    def _normalize_string_list(values: Any) -> list[str]:
        if not isinstance(values, list):
            return []

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
