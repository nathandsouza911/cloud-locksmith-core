"""Projector lookup.

The default matters more than the registry: a workflow whose detectors already
emit per-resource findings should need no registration at all.
"""

import pytest

from app.services.workflows._shared.projector import FindingProjector
from app.services.workflows._shared.projector_registry import (
    get_projector,
    register_projector,
    registered_workflow_ids,
)


# GUEST_REVIEW is a real workflow that registers no projector. IDENTITY_HYGIENE
# would look like it passes — its projector subclasses FindingProjector — while
# actually testing nothing, and only once some other module has imported it.
UNREGISTERED = "GUEST_REVIEW"


def test_an_unregistered_workflow_gets_a_default_finding_projector():
    projector = get_projector(UNREGISTERED)
    assert isinstance(projector, FindingProjector)
    assert type(projector) is FindingProjector
    assert projector.workflow_id == UNREGISTERED


def test_the_default_projector_uses_the_registrys_controls():
    assert "IDENTITY_GUEST_INVITES_OPEN" in get_projector(UNREGISTERED).controls()


def test_a_registered_projector_wins_over_the_default():
    custom = FindingProjector("TEST_WORKFLOW_A")
    register_projector(custom)
    assert get_projector("TEST_WORKFLOW_A") is custom


def test_registering_the_same_workflow_twice_is_refused():
    """Two projectors for one workflow means discovery depends on import order."""
    register_projector(FindingProjector("TEST_WORKFLOW_B"))
    with pytest.raises(ValueError, match="already registered"):
        register_projector(FindingProjector("TEST_WORKFLOW_B"))


def test_registering_a_projector_with_no_workflow_id_is_refused():
    class _Nameless:
        workflow_id = ""

        def controls(self):
            return ()

        def project(self, findings):
            return []

    with pytest.raises(ValueError, match="workflow_id"):
        register_projector(_Nameless())


def test_registered_ids_are_reported():
    register_projector(FindingProjector("TEST_WORKFLOW_C"))
    assert "TEST_WORKFLOW_C" in registered_workflow_ids()
