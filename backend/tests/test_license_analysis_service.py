import logging
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.models.license_optimizer import LicenseFinding, LicenseFindingType
from app.db.models.tenant import Tenant
from app.services.license_analysis_service import (
    _resolve_pricing_key,
    _build_sku_catalog,
    SKU_ID_TO_PRICING_KEY,
    analyze_license_data,
    get_license_summary,
)


def test_analyze_license_data_detects_expected_waste_categories():
    raw_data = {
        "users": [
            {
                "id": "user-inactive",
                "displayName": "Inactive User",
                "mail": "inactive@contoso.com",
                "userPrincipalName": "inactive@contoso.com",
                "createdDateTime": "2025-01-01T00:00:00Z",
                "assignedLicenses": [{"skuId": "sku-e3"}],
            },
            {
                "id": "user-overlicensed",
                "displayName": "Mailbox Only",
                "mail": "mailbox@contoso.com",
                "userPrincipalName": "mailbox@contoso.com",
                "createdDateTime": "2025-01-01T00:00:00Z",
                "assignedLicenses": [{"skuId": "sku-e5"}],
            },
        ],
        "subscribed_skus": [
            {
                "skuId": "sku-e3",
                "skuPartNumber": "SPE_E3",
                "prepaidUnits": {"enabled": 10},
                "consumedUnits": 7,
            },
            {
                "skuId": "sku-e5",
                "skuPartNumber": "SPE_E5",
                "prepaidUnits": {"enabled": 5},
                "consumedUnits": 5,
            },
        ],
        "office365_active_user_detail": [
            {
                "user_principal_name": "inactive@contoso.com",
                "last_activity_date": "2025-02-01",
            },
            {
                "user_principal_name": "mailbox@contoso.com",
                "exchange_last_activity_date": "2026-04-20",
                "sharepoint_last_activity_date": "",
                "onedrive_last_activity_date": "",
                "teams_last_activity_date": "",
            },
        ],
        "m365_app_user_counts": [],
    }

    findings = analyze_license_data(
        tenant_id="tenant-123",
        raw_data=raw_data,
        now=datetime(2026, 4, 23),
    )

    finding_types = [item["type"] for item in findings]
    assert finding_types.count(LicenseFindingType.INACTIVE_USER) == 1
    assert finding_types.count(LicenseFindingType.OVERLICENSED_USER) == 1
    assert finding_types.count(LicenseFindingType.UNUSED_LICENSE) == 1

    inactive = next(item for item in findings if item["type"] == LicenseFindingType.INACTIVE_USER)
    assert inactive["license_type"] == "M365_E3"
    assert inactive["estimated_monthly_cost"] == 39

    overlicensed = next(item for item in findings if item["type"] == LicenseFindingType.OVERLICENSED_USER)
    assert overlicensed["license_type"] == "M365_E5"
    assert overlicensed["estimated_monthly_cost"] == 60

    unused = next(item for item in findings if item["type"] == LicenseFindingType.UNUSED_LICENSE)
    assert unused["license_type"] == "M365_E3"
    assert unused["estimated_monthly_cost"] == 117
    assert unused["metadata"]["unused_count"] == 3


def test_get_license_summary_aggregates_costs():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Tenant.__table__.create(engine)
    LicenseFinding.__table__.create(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()

    try:
        session.add(Tenant(id="tenant-123", tenant_name="Summary Tenant"))
        session.add_all(
            [
                LicenseFinding(
                    id="f1",
                    tenant_id="tenant-123",
                    finding_type=LicenseFindingType.INACTIVE_USER,
                    user_id="user-1",
                    license_type="M365_E3",
                    estimated_monthly_cost=39,
                    finding_metadata={},
                ),
                LicenseFinding(
                    id="f2",
                    tenant_id="tenant-123",
                    finding_type=LicenseFindingType.OVERLICENSED_USER,
                    user_id="user-2",
                    license_type="M365_E5",
                    estimated_monthly_cost=60,
                    finding_metadata={},
                ),
                LicenseFinding(
                    id="f3",
                    tenant_id="tenant-123",
                    finding_type=LicenseFindingType.UNUSED_LICENSE,
                    user_id=None,
                    license_type="M365_E3",
                    estimated_monthly_cost=117,
                    finding_metadata={},
                ),
            ]
        )
        session.commit()

        assert get_license_summary(session, "tenant-123") == {
            "currency": "USD",
            "total_waste": 216,
            "inactive_users_cost": 39,
            "overlicensed_cost": 60,
            "unused_license_cost": 117,
        }
    finally:
        session.close()


def test_sku_id_mapping_resolves_e5_by_guid():
    sku = {"skuId": "06ebc4ee-1bb5-47dd-8120-11324bc54e06", "skuPartNumber": "SPE_E5"}
    assert _resolve_pricing_key(sku) == "M365_E5"
    assert "06ebc4ee-1bb5-47dd-8120-11324bc54e06" in SKU_ID_TO_PRICING_KEY


def test_sku_id_mapping_resolves_e3_by_guid():
    sku = {"skuId": "05e9a617-0261-4cee-bb44-138d3ef5d965", "skuPartNumber": "SPE_E3"}
    assert _resolve_pricing_key(sku) == "M365_E3"


def test_sku_id_resolves_when_part_number_missing():
    """GUID-only resolution must work even when skuPartNumber is absent."""
    sku = {"skuId": "06ebc4ee-1bb5-47dd-8120-11324bc54e06", "skuPartNumber": ""}
    assert _resolve_pricing_key(sku) == "M365_E5"


def test_unresolved_sku_logs_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="app.services.license_analysis_service"):
        _build_sku_catalog(
            [
                {
                    "skuId": "unknown-guid-1234",
                    "skuPartNumber": "UNKNOWN_SKU_XYZ",
                    "prepaidUnits": {"enabled": 5},
                    "consumedUnits": 3,
                }
            ]
        )
    assert any("unresolved" in record.message.lower() for record in caplog.records)


def test_desklesspack_guid_maps_to_f1_not_f3():
    """DESKLESSPACK is M365_F1 ($3/user); ensure GUID and part-number resolutions are consistent."""
    by_guid = _resolve_pricing_key({"skuId": "4b9405b0-7788-4568-add1-99614e613b69", "skuPartNumber": ""})
    by_part_number = _resolve_pricing_key({"skuId": "", "skuPartNumber": "DESKLESSPACK"})
    assert by_guid == "M365_F1", f"DESKLESSPACK GUID should resolve to M365_F1, got {by_guid!r}"
    assert by_part_number == "M365_F1", f"DESKLESSPACK part-number should resolve to M365_F1, got {by_part_number!r}"
    assert by_guid == by_part_number, "GUID and part-number resolution must agree for the same product"


def test_build_sku_catalog_logs_resolution_for_known_sku(caplog):
    """Each resolved SKU should emit a DEBUG log with skuId, skuPartNumber, pricing_key."""
    with caplog.at_level(logging.DEBUG, logger="app.services.license_analysis_service"):
        _build_sku_catalog(
            [
                {
                    "skuId": "06ebc4ee-1bb5-47dd-8120-11324bc54e06",
                    "skuPartNumber": "SPE_E5",
                    "prepaidUnits": {"enabled": 10},
                    "consumedUnits": 8,
                }
            ]
        )
    assert any("SPE_E5" in record.message and "M365_E5" in record.message for record in caplog.records)


def test_unused_license_detected_when_activity_unavailable():
    """UNUSED_LICENSE findings must be generated even when activity reports are absent."""
    raw_data = {
        "users": [],
        "subscribed_skus": [
            {
                "skuId": "06ebc4ee-1bb5-47dd-8120-11324bc54e06",
                "skuPartNumber": "SPE_E5",
                "prepaidUnits": {"enabled": 10},
                "consumedUnits": 6,
            }
        ],
        "office365_active_user_detail": [],
        "office365_active_user_detail_available": False,
        "m365_app_user_counts": [],
        "m365_app_user_counts_available": False,
    }
    findings = analyze_license_data(tenant_id="tenant-x", raw_data=raw_data)
    unused = [f for f in findings if f["type"] == LicenseFindingType.UNUSED_LICENSE]
    assert len(unused) == 1
    assert unused[0]["license_type"] == "M365_E5"
    assert unused[0]["estimated_monthly_cost"] == 4 * 60  # 4 unused × $60


def test_analyze_logs_warning_when_activity_reports_unavailable(caplog):
    raw_data = {
        "users": [],
        "subscribed_skus": [],
        "office365_active_user_detail": [],
        "office365_active_user_detail_available": False,
        "m365_app_user_counts": [],
        "m365_app_user_counts_available": False,
    }
    with caplog.at_level(logging.WARNING, logger="app.services.license_analysis_service"):
        analyze_license_data(tenant_id="tenant-x", raw_data=raw_data)
    assert any("activity" in r.message.lower() and "unavailable" in r.message.lower() for r in caplog.records)


def test_inactive_user_metadata_flags_activity_unavailable():
    """When activity data is absent, INACTIVE_USER findings must note it in metadata."""
    raw_data = {
        "users": [
            {
                "id": "u1",
                "userPrincipalName": "old@contoso.com",
                "createdDateTime": "2024-01-01T00:00:00Z",
                "assignedLicenses": [{"skuId": "06ebc4ee-1bb5-47dd-8120-11324bc54e06"}],
            }
        ],
        "subscribed_skus": [
            {
                "skuId": "06ebc4ee-1bb5-47dd-8120-11324bc54e06",
                "skuPartNumber": "SPE_E5",
                "prepaidUnits": {"enabled": 5},
                "consumedUnits": 5,
            }
        ],
        "office365_active_user_detail": [],
        "office365_active_user_detail_available": False,
        "m365_app_user_counts": [],
        "m365_app_user_counts_available": False,
    }
    findings = analyze_license_data(
        tenant_id="tenant-x",
        raw_data=raw_data,
        now=datetime(2026, 5, 29),
    )
    inactive = [f for f in findings if f["type"] == LicenseFindingType.INACTIVE_USER]
    assert len(inactive) == 1
    assert inactive[0]["metadata"].get("activity_data_available") is False
