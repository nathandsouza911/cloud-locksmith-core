"""REMEDIATION_DRY_RUN is not a safety switch, so nothing may speak as if it were.

It used to drive a startup log line claiming "remediations will NOT be applied" in
production (and the opposite outside it). Neither was true: the setting stops nothing.
Auto-remediation is controlled by ENABLE_AUTO_REMEDIATION; with it off, a fix executes only
after an approval (docs/remediation-lifecycle.md).
"""

from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[1] / "app"


def test_remediation_dry_run_is_not_read_anywhere_in_the_app():
    readers = [
        str(path.relative_to(APP_DIR))
        for path in APP_DIR.rglob("*.py")
        if path.name != "config.py" and "REMEDIATION_DRY_RUN" in path.read_text(encoding="utf-8")
    ]
    assert readers == []


def test_no_startup_handler_claims_what_dry_run_does():
    from app.main import app

    names = {handler.__name__ for handler in app.router.on_startup}
    assert "check_remediation_dry_run_config" not in names
