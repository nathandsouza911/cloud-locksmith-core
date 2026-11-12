from app.utils.datetime import utc_now
import asyncio


from app.db.models.compliance_result import ComplianceResult, ResolutionSource
from app.services.finding_cleanup import resolve_findings_sync
from app.services import identity_scan_service
from app.services.remediation.lifecycle import normalize_resolution_source, update_finding_state


class _ScanResult:
    def __init__(self, *, passed: bool):
        self.passed = passed
        self.evaluated_at = utc_now()


def test_normalize_resolution_source_falls_back_to_system():
    assert normalize_resolution_source("unexpected") == ResolutionSource.SYSTEM.value
    assert normalize_resolution_source(None) == ResolutionSource.SYSTEM.value


def test_scan_resolution_uses_system_source():
    finding = ComplianceResult(
        tenant_id="tenant-1",
        control_id="IDENTITY_GUEST_INVITES_OPEN",
        resource_type="TENANT",
        resource_id="tenant-1",
        passed=False,
        severity="MEDIUM",
        evidence={},
        remediation_status="PENDING",
        decision_status="PENDING",
    )

    update_finding_state(finding, _ScanResult(passed=True))

    assert finding.resolved_by == ResolutionSource.SYSTEM.value


def test_async_scan_upsert_wrapper_rolls_back_and_returns_none(monkeypatch):
    class FakeDb:
        def __init__(self):
            self.rollback_calls = 0

        async def rollback(self):
            self.rollback_calls += 1

    async def fake_upsert_control_result(**kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(identity_scan_service, "upsert_control_result", fake_upsert_control_result)

    db = FakeDb()
    result = asyncio.run(
        identity_scan_service._safe_upsert_control_result(
            db,
            tenant_id="tenant-1",
            control_id="IDENTITY_GUEST_INVITES_OPEN",
            resource_id="tenant-1",
            resource_type="TENANT",
            passed=False,
            severity="MEDIUM",
            evidence={},
        )
    )

    assert result is None
    assert db.rollback_calls == 1


def test_cleanup_resolves_findings_in_place(db_session):
    finding = ComplianceResult(
        tenant_id="tenant-1",
        control_id="IDENTITY_USER_CONSENT_POLICY",
        resource_type="TENANT",
        resource_id="tenant-1",
        passed=False,
        severity="HIGH",
        evidence={},
        exposure_status="ACTIVE",
        remediation_status="PENDING",
        decision_status="PENDING",
    )
    db_session.add(finding)
    db_session.commit()
    finding_id = finding.id

    updated = resolve_findings_sync(
        db_session,
        tenant_id="tenant-1",
        control_ids=["IDENTITY_USER_CONSENT_POLICY"],
        resource_type="TENANT",
    )
    db_session.commit()

    refreshed = db_session.get(ComplianceResult, finding_id)
    assert updated == 1
    assert refreshed is not None
    assert refreshed.id == finding_id
    assert refreshed.exposure_status == "RESOLVED"
    assert refreshed.passed is True
    assert refreshed.resolved_by == ResolutionSource.SYSTEM.value
