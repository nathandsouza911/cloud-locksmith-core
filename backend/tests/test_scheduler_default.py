from app.config import Settings


def test_scheduler_is_off_unless_enabled():
    # A first real-tenant run must do nothing in the background unless the operator
    # opts in with ENABLE_SCHEDULER=true.
    assert Settings.model_fields["ENABLE_SCHEDULER"].default is False


def test_auto_remediation_stays_off_by_default():
    assert Settings.model_fields["ENABLE_AUTO_REMEDIATION"].default is False
