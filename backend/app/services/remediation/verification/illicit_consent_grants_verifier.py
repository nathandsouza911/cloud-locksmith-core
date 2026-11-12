from app.services.graph_client import GraphAPIError
from app.services.identity_providers import get_identity_provider_adapter


def _snapshot_from_result(compliance_result) -> dict:
    evidence = getattr(compliance_result, "evidence", None) or {}
    snapshot = evidence.get("snapshot") if isinstance(evidence, dict) else None
    if isinstance(snapshot, dict):
        return snapshot
    return {}


async def verify_illicit_consent_grants_removed(*, db, tenant, compliance_result) -> dict:
    snapshot = _snapshot_from_result(compliance_result)
    grants = snapshot.get("grants", []) or []
    adapter = get_identity_provider_adapter(db=db, tenant=tenant)

    still_present: list[str] = []
    for grant in grants:
        grant_id = grant.get("id")
        if not grant_id:
            continue
        try:
            await adapter.get_oauth2_permission_grant(grant_id)
        except GraphAPIError as exc:
            if exc.status_code == 404:
                continue
            raise
        still_present.append(grant_id)

    success = not still_present
    return {
        "success": success,
        "details": {
            "reason": None if success else "ILLICIT_GRANTS_STILL_PRESENT",
            "evidence": {
                "still_present": still_present,
                "total_examined": len(grants),
            },
        },
    }
