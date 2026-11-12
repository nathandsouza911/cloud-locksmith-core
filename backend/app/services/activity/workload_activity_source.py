from __future__ import annotations

import csv
import io
import logging
from datetime import datetime
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.db.models.tenant import Tenant
from app.services.graph_client import (
    GRAPH_BASE,
    GraphAPIError,
    decode_access_token_claims,
)
from app.services.token_manager import get_valid_access_token, has_delegated_oauth_token

logger = logging.getLogger(__name__)

# Workload activity columns from getOffice365ActiveUserDetail. Per the
# Identity Activity Engine design, Exchange/Outlook is a WORKLOAD signal
# (uniform with Teams/OneDrive/SharePoint); signInActivity is the only
# identity signal and is NOT sourced from this report.
EXCHANGE_ACTIVITY_COLUMNS = (
    "exchange_last_activity_date",
    "outlook_last_activity_date",
)
NON_EMAIL_ACTIVITY_COLUMNS = (
    "onedrive_last_activity_date",
    "sharepoint_last_activity_date",
    "skype_for_business_last_activity_date",
    "yammer_last_activity_date",
    "teams_last_activity_date",
    "microsoft_teams_last_activity_date",
)
ALL_WORKLOAD_COLUMNS = (*EXCHANGE_ACTIVITY_COLUMNS, *NON_EMAIL_ACTIVITY_COLUMNS)

OFFICE_ACTIVE_USER_DETAIL_PATH = "/reports/getOffice365ActiveUserDetail(period='D180')"


def normalize_header(value: str) -> str:
    return (
        str(value or "")
        .strip()
        .lower()
        .replace("﻿", "")
        .replace("(", "")
        .replace(")", "")
        .replace("/", "_")
        .replace("-", "_")
        .replace(" ", "_")
    )


def normalize_row(row: dict[str, Any]) -> dict[str, str]:
    return {normalize_header(key): str(value).strip() for key, value in row.items() if key is not None}


def parse_csv_rows(csv_text: str) -> list[dict[str, str]]:
    if not csv_text.strip():
        return []
    reader = csv.DictReader(io.StringIO(csv_text.lstrip("﻿")))
    return [normalize_row(row) for row in reader if row]


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(normalized, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(normalized.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def first_present(row: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def build_activity_map(activity_rows: list[dict[str, str]]) -> dict[str, dict[str, Any]]:
    activity_map: dict[str, dict[str, Any]] = {}
    for row in activity_rows:
        user_key = first_present(row, "user_principal_name", "upn")
        if not user_key:
            continue
        last_activity = parse_datetime(first_present(row, "last_activity_date"))
        if last_activity is None:
            workload_dates = [parse_datetime(first_present(row, column)) for column in ALL_WORKLOAD_COLUMNS]
            workload_dates = [item for item in workload_dates if item is not None]
            last_activity = max(workload_dates) if workload_dates else None
        exchange_activity = any(parse_datetime(first_present(row, column)) for column in EXCHANGE_ACTIVITY_COLUMNS)
        non_email_activity = any(parse_datetime(first_present(row, column)) for column in NON_EMAIL_ACTIVITY_COLUMNS)
        activity_map[user_key.lower()] = {
            "row": row,
            "last_activity": last_activity,
            "exchange_activity": exchange_activity,
            "non_email_activity": non_email_activity,
            "workload_activity": exchange_activity or non_email_activity,
        }
    return activity_map


async def fetch_report_csv(db: Session, tenant: Tenant, report_path: str) -> str:
    if not await has_delegated_oauth_token(tenant, db=db):
        raise RuntimeError("Tenant has no OAuth token stored")

    async def _request_text(access_token: str) -> httpx.Response:
        headers = {"Authorization": f"Bearer {access_token}", "Accept": "text/csv"}
        async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
            return await client.get(f"{GRAPH_BASE}{report_path}", headers=headers)

    access_token = await get_valid_access_token(tenant.id, db=db)
    response = await _request_text(access_token)
    if response.status_code == 401:
        access_token = await get_valid_access_token(tenant.id, db=db, force_refresh=True)
        response = await _request_text(access_token)
    if response.status_code >= 400:
        raise GraphAPIError(
            method="GET",
            path=report_path,
            status_code=response.status_code,
            response_body=response.text,
            category="REPORT_FETCH_FAILED",
            token_claims=decode_access_token_claims(access_token),
        )
    text = (response.text or "").strip()
    if text.startswith("https://"):
        async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
            download = await client.get(text)
        if download.status_code >= 400:
            raise GraphAPIError(
                method="GET",
                path=report_path,
                status_code=download.status_code,
                response_body=download.text,
                category="REPORT_DOWNLOAD_FAILED",
                token_claims=decode_access_token_claims(access_token),
            )
        text = download.text
    return text


async def fetch_office_activity_rows(db: Session, tenant: Tenant) -> tuple[list[dict[str, str]], bool]:
    """Return (rows, available). Fails soft to ([], False) on Graph errors."""
    try:
        rows = parse_csv_rows(await fetch_report_csv(db, tenant, OFFICE_ACTIVE_USER_DETAIL_PATH))
        return rows, True
    except (GraphAPIError, RuntimeError) as exc:
        logger.warning("[WorkloadActivity] Reports API failed for tenant %s: %s", tenant.id, exc)
        return [], False


async def fetch_workload_activity(db: Session, tenant: Tenant) -> tuple[dict[str, dict[str, Any]], bool]:
    """Return (activity_map keyed by lower UPN, available)."""
    rows, available = await fetch_office_activity_rows(db, tenant)
    return build_activity_map(rows), available
