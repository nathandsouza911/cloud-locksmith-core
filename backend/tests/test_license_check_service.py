import pytest
from unittest.mock import AsyncMock, MagicMock
from app.services.graph_client import GraphAPIError


def _make_graph_error(status_code: int, body: str) -> GraphAPIError:
    err = GraphAPIError.__new__(GraphAPIError)
    err.status_code = status_code
    err.response_body = body
    err.method = "POST"
    err.path = "/identity/conditionalAccess/policies"
    err.category = "TEST"
    err.token_claims = {}
    return err


@pytest.mark.asyncio
async def test_probe_returns_true_when_policy_created():
    from app.services.license_check_service import check_conditional_access_license

    graph = MagicMock()
    graph.create_conditional_access_policy = AsyncMock(return_value={"id": "policy-1"})
    graph.delete_conditional_access_policy = AsyncMock(return_value={})
    result = await check_conditional_access_license(graph)
    assert result is True


@pytest.mark.asyncio
async def test_probe_returns_false_for_403_with_licensed_in_body():
    from app.services.license_check_service import check_conditional_access_license

    graph = MagicMock()
    graph.create_conditional_access_policy = AsyncMock(
        side_effect=_make_graph_error(403, "You are not licensed for this feature")
    )
    result = await check_conditional_access_license(graph)
    assert result is False


@pytest.mark.asyncio
async def test_probe_returns_false_for_403_without_licensed_in_body():
    """The bug: previously this 403 was re-raised causing a 500. Now any 403 returns False."""
    from app.services.license_check_service import check_conditional_access_license

    graph = MagicMock()
    graph.create_conditional_access_policy = AsyncMock(
        side_effect=_make_graph_error(403, "Authorization_RequestDenied")
    )
    result = await check_conditional_access_license(graph)
    assert result is False


@pytest.mark.asyncio
async def test_probe_reraises_non_403_errors():
    from app.services.license_check_service import check_conditional_access_license

    graph = MagicMock()
    graph.create_conditional_access_policy = AsyncMock(side_effect=_make_graph_error(500, "Internal Server Error"))
    with pytest.raises(GraphAPIError):
        await check_conditional_access_license(graph)


@pytest.mark.asyncio
async def test_sku_check_returns_true_for_e5():
    from app.services.license_check_service import check_ca_license_from_skus

    graph = MagicMock()
    graph.get = AsyncMock(
        return_value={
            "value": [
                {
                    "skuPartNumber": "SPE_E5",
                    "prepaidUnits": {"enabled": 25},
                    "consumedUnits": 20,
                }
            ]
        }
    )
    result = await check_ca_license_from_skus(graph)
    assert result is True


@pytest.mark.asyncio
async def test_sku_check_returns_false_for_business_standard():
    from app.services.license_check_service import check_ca_license_from_skus

    graph = MagicMock()
    graph.get = AsyncMock(
        return_value={
            "value": [
                {
                    "skuPartNumber": "O365_BUSINESS_PREMIUM",  # Business Standard — no CA
                    "prepaidUnits": {"enabled": 10},
                    "consumedUnits": 10,
                }
            ]
        }
    )
    result = await check_ca_license_from_skus(graph)
    assert result is False


@pytest.mark.asyncio
async def test_sku_check_returns_true_for_business_premium():
    from app.services.license_check_service import check_ca_license_from_skus

    graph = MagicMock()
    graph.get = AsyncMock(
        return_value={
            "value": [
                {
                    "skuPartNumber": "SPB",  # Business Premium — includes Entra P1
                    "prepaidUnits": {"enabled": 5},
                    "consumedUnits": 5,
                }
            ]
        }
    )
    result = await check_ca_license_from_skus(graph)
    assert result is True


@pytest.mark.asyncio
async def test_sku_check_returns_true_on_error():
    """Fail-open: if the SKU check raises, we allow execution (probe has final say)."""
    from app.services.license_check_service import check_ca_license_from_skus

    graph = MagicMock()
    graph.get = AsyncMock(side_effect=RuntimeError("network error"))
    result = await check_ca_license_from_skus(graph)
    assert result is True


@pytest.mark.asyncio
async def test_sku_check_returns_true_for_ems_e3():
    from app.services.license_check_service import check_ca_license_from_skus

    graph = MagicMock()
    graph.get = AsyncMock(
        return_value={
            "value": [
                {
                    "skuPartNumber": "EMS",  # EMS E3 — includes Entra P1
                    "prepaidUnits": {"enabled": 8},
                    "consumedUnits": 8,
                }
            ]
        }
    )
    result = await check_ca_license_from_skus(graph)
    assert result is True


@pytest.mark.asyncio
async def test_sku_check_returns_false_for_rightsmanagement_only():
    """RIGHTSMANAGEMENT (AIP P1) does not grant CA — must not be treated as licensed."""
    from app.services.license_check_service import check_ca_license_from_skus

    graph = MagicMock()
    graph.get = AsyncMock(
        return_value={
            "value": [
                {
                    "skuPartNumber": "RIGHTSMANAGEMENT",
                    "prepaidUnits": {"enabled": 10},
                    "consumedUnits": 10,
                }
            ]
        }
    )
    result = await check_ca_license_from_skus(graph)
    assert result is False
