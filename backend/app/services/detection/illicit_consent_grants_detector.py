from app.services.graph_client import graph_get


HIGH_RISK_SCOPES = {
    "Mail.Read",
    "Mail.ReadWrite",
    "Files.Read.All",
    "Directory.Read.All",
    "offline_access",
}


async def detect_illicit_consent_grants(*, db, tenant) -> dict:
    grants: list[dict] = []
    url: str | None = "/oauth2PermissionGrants"
    while url:
        response = await graph_get(db, tenant, url)
        grants.extend(response.get("value", []) or [])
        url = response.get("@odata.nextLink")

    illicit: list[dict] = []
    for grant in grants:
        if grant.get("consentType") != "Principal":
            continue
        scope_value = grant.get("scope") or ""
        scopes = [s for s in scope_value.split() if s]
        matched = sorted(set(scopes) & HIGH_RISK_SCOPES)
        if not matched:
            continue
        illicit.append(
            {
                "id": grant.get("id"),
                "clientId": grant.get("clientId"),
                "resourceId": grant.get("resourceId"),
                "principalId": grant.get("principalId"),
                "consentType": grant.get("consentType"),
                "scope": grant.get("scope"),
                "matched_scopes": matched,
            }
        )

    return {
        "control_id": "IDENTITY_ILLICIT_CONSENT_GRANTS",
        "severity": "CRITICAL",
        "passed": len(illicit) == 0,
        "evidence": {
            "illicit_grants": illicit,
            "total_grants_examined": len(grants),
        },
    }
