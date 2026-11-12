"""H1 — approval↔execution scope binding (TOCTOU protection).

The approved scope is captured server-side from the finding's evidence at
approval time. At execute time we require (a) the scope is unchanged since
approval (no drift / re-scan) and (b) any client-supplied selected_roles is a
subset of the approved scope. Pure functions here; wiring is in
mark_remediation_approved + execute_approved_remediation.
"""

from app.services.remediation import approval_binding as ab


def test_evidence_roles_normalizes_strings_and_dicts_sorted_deduped():
    evidence = {"current_roles": ["Role.B", {"role_id": "Role.A"}, {"id": "Role.B"}, "Role.A"]}
    assert ab.evidence_roles(evidence) == ["Role.A", "Role.B"]


def test_selected_roles_normalizes_payload():
    assert ab.selected_roles({"selected_roles": [{"role_id": "X"}, "Y", "Y"]}) == ["X", "Y"]


def test_scope_hash_is_order_independent_for_roles():
    h1 = ab.compute_scope_hash("IDENTITY_OVERPRIVILEGED_USER", "u1", ["A", "B"])
    h2 = ab.compute_scope_hash("IDENTITY_OVERPRIVILEGED_USER", "u1", ["B", "A"])
    assert h1 == h2


def test_scope_hash_changes_when_roles_change():
    base = ab.compute_scope_hash("IDENTITY_OVERPRIVILEGED_USER", "u1", ["A", "B"])
    drift = ab.compute_scope_hash("IDENTITY_OVERPRIVILEGED_USER", "u1", ["A", "C"])
    assert base != drift


def test_approved_scope_matches_compute_scope_hash():
    evidence = {"current_roles": ["A", "B"]}
    scope = ab.approved_scope("IDENTITY_OVERPRIVILEGED_USER", "u1", evidence)
    assert scope["approved_roles"] == ["A", "B"]
    assert scope["approved_scope_hash"] == ab.compute_scope_hash("IDENTITY_OVERPRIVILEGED_USER", "u1", ["A", "B"])


def test_selected_roles_within_scope_subset_true():
    assert ab.selected_roles_within_scope({"selected_roles": ["A"]}, approved_roles=["A", "B"]) is True


def test_selected_roles_within_scope_superset_false():
    assert ab.selected_roles_within_scope({"selected_roles": ["A", "C"]}, approved_roles=["A", "B"]) is False


def test_selected_roles_within_scope_empty_request_true():
    # Empty selection is handled by the existing "no roles selected" rejection.
    assert ab.selected_roles_within_scope({"selected_roles": []}, approved_roles=["A"]) is True


def test_scope_unchanged_true_when_evidence_matches_approval():
    evidence = {"current_roles": ["A", "B"]}
    approved = ab.approved_scope("IDENTITY_OVERPRIVILEGED_USER", "u1", evidence)
    assert (
        ab.scope_unchanged(
            "IDENTITY_OVERPRIVILEGED_USER",
            "u1",
            evidence,
            approved_scope_hash=approved["approved_scope_hash"],
        )
        is True
    )


def test_scope_unchanged_false_after_rescan_changes_roles():
    approved = ab.approved_scope("IDENTITY_OVERPRIVILEGED_USER", "u1", {"current_roles": ["A", "B"]})
    drifted_evidence = {"current_roles": ["A", "C"]}  # a re-scan changed the roles
    assert (
        ab.scope_unchanged(
            "IDENTITY_OVERPRIVILEGED_USER",
            "u1",
            drifted_evidence,
            approved_scope_hash=approved["approved_scope_hash"],
        )
        is False
    )


# --- assert_execution_within_approved_scope (the decision seam the service uses) ---


def _approved_evidence(roles):
    ev = {"current_roles": list(roles), "user_id": "u1"}
    ev.update(ab.approved_scope("IDENTITY_OVERPRIVILEGED_USER", "u1", ev))
    return ev


def test_assert_scope_noop_for_fixed_action_control():
    # Fixed-action controls are unconstrained by this binding.
    ab.assert_execution_within_approved_scope(
        control_id="IDENTITY_USER_CONSENT_POLICY",
        resource_id="tenant-1",
        evidence={},
        execution_payload={"selected_roles": ["anything"]},
    )


def test_assert_scope_allows_subset_when_unchanged():
    evidence = _approved_evidence(["A", "B"])
    ab.assert_execution_within_approved_scope(
        control_id="IDENTITY_OVERPRIVILEGED_USER",
        resource_id="u1",
        evidence=evidence,
        execution_payload={"selected_roles": ["A"]},
    )


def test_assert_scope_blocks_roles_outside_approval():
    evidence = _approved_evidence(["A", "B"])
    try:
        ab.assert_execution_within_approved_scope(
            control_id="IDENTITY_OVERPRIVILEGED_USER",
            resource_id="u1",
            evidence=evidence,
            execution_payload={"selected_roles": ["A", "C"]},
        )
        assert False, "expected ApprovalScopeError"
    except ab.ApprovalScopeError as exc:
        assert exc.reason == "roles_exceeded"


def test_assert_scope_blocks_drift_since_approval():
    evidence = _approved_evidence(["A", "B"])
    evidence["current_roles"] = ["A", "C"]  # re-scan drift; approved_scope_hash still reflects A,B
    try:
        ab.assert_execution_within_approved_scope(
            control_id="IDENTITY_OVERPRIVILEGED_USER",
            resource_id="u1",
            evidence=evidence,
            execution_payload={"selected_roles": ["A"]},
        )
        assert False, "expected ApprovalScopeError"
    except ab.ApprovalScopeError as exc:
        assert exc.reason == "scope_changed"
