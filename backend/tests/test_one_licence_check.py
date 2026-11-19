"""Review R2-19: one reading of /subscribedSkus for Entra ID P1/P2.

Two checks disagreed: license_service counted Office 365 E5
(ENTERPRISEPREMIUM, no Entra P1) as P1, spelled EMS E5 "EMS_PREMIUM" (the
part number is EMSPREMIUM) and counted suspended SKUs; license_check_service
ignored service plans. Both now use entra_premium_from_skus.
"""

import asyncio

import pytest

from app.services.license_check_service import check_ca_license_from_skus
from app.services.license_service import entra_premium_from_skus


def _sku(part: str, *, plans=(), status="Enabled", enabled=10) -> dict:
    return {
        "skuPartNumber": part,
        "capabilityStatus": status,
        "prepaidUnits": {"enabled": enabled},
        "consumedUnits": 1,
        "servicePlans": [{"servicePlanName": p} for p in plans],
    }


class _Graph:
    def __init__(self, skus):
        self.skus = skus

    async def get(self, path):
        assert path == "/subscribedSkus"
        return {"value": self.skus}


@pytest.mark.parametrize(
    "skus, expected",
    [
        ([_sku("ENTERPRISEPREMIUM", plans=["EXCHANGE_S_ENTERPRISE"])], {"has_p1": False, "has_p2": False}),
        ([_sku("EMSPREMIUM")], {"has_p1": True, "has_p2": True}),
        ([_sku("AAD_PREMIUM", status="Suspended")], {"has_p1": False, "has_p2": False}),
        ([_sku("SOME_BUNDLE", plans=["AAD_PREMIUM"])], {"has_p1": True, "has_p2": False}),
        ([_sku("SPB")], {"has_p1": True, "has_p2": False}),
        ([_sku("SPE_E5")], {"has_p1": True, "has_p2": True}),
    ],
)
def test_entra_premium_from_skus(skus, expected):
    assert entra_premium_from_skus(skus) == expected


@pytest.mark.parametrize(
    "skus",
    [
        [_sku("ENTERPRISEPREMIUM")],
        [_sku("EMSPREMIUM")],
        [_sku("AAD_PREMIUM", status="Suspended")],
        [_sku("SOME_BUNDLE", plans=["AAD_PREMIUM"])],
    ],
)
def test_ca_licence_gate_agrees_with_the_tenant_licence(skus):
    assert asyncio.run(check_ca_license_from_skus(_Graph(skus))) == entra_premium_from_skus(skus)["has_p1"]
