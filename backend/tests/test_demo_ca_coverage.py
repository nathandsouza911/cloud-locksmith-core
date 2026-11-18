"""Demo mode answers CA coverage and Simulate Fix reads from recordings (ROADMAP 3.1).

The recorded policies must tell the same story as the seeded findings: CA_MFA_ADMINS
passes, CA_MFA_ALL_USERS and CA_LEGACY_AUTH_BLOCK fail.
"""

import pytest

from app.config import settings
from app.demo import DEMO_OWNER_OID, DEMO_TENANT_ID, DemoModeViolation
from app.demo.fixtures import DIRECTORY_USERS, EXCLUDED_USER_ID, OVERPRIVILEGED_USER_ID
from app.simulation.coverage import build_coverage
from app.simulation.tenant_reader import read_tenant_identity

pytestmark = pytest.mark.asyncio


class _Tenant:
    def __init__(self, tenant_id=DEMO_TENANT_ID):
        self.id = tenant_id


@pytest.fixture(autouse=True)
def demo_mode(monkeypatch):
    monkeypatch.setattr(settings, "DEMO_MODE", True)


async def test_demo_coverage_matches_the_seeded_findings():
    report = build_coverage(await read_tenant_identity(None, _Tenant()))
    by_id = {u["id"]: u for u in report["users"]}

    assert len(by_id) == len(DIRECTORY_USERS)
    for admin in (DEMO_OWNER_OID, OVERPRIVILEGED_USER_ID):
        assert by_id[admin]["is_admin"] is True
        assert by_id[admin]["admin_mfa"]["status"] == "covered"  # CA_MFA_ADMINS passes

    excluded = by_id[EXCLUDED_USER_ID]["mfa"]
    assert excluded["status"] == "gap"
    assert excluded["reasons"] == ["Excluded from 'Require MFA for all users (fictional)' by group 'CA exclusions'"]

    others = [u for uid, u in by_id.items() if not u["is_admin"] and uid != EXCLUDED_USER_ID]
    assert others and all(u["mfa"]["status"] == "report_only" for u in others)  # CA_MFA_ALL_USERS fails
    assert report["summary"]["legacy_auth"]["gap"] == len(by_id)  # CA_LEGACY_AUTH_BLOCK fails


async def test_demo_reads_only_the_demo_tenant():
    with pytest.raises(DemoModeViolation):
        await read_tenant_identity(None, _Tenant("someone-else"))
