"""Conditional Access coverage across all users (ROADMAP 3.1). Read-only.

The tenant is the session tenant (``get_explicit_current_tenant`` checks X-Tenant-ID
against the user's tenant access); nothing in the request selects data.
"""

from __future__ import annotations

import csv
import io
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.dependencies.current_user import get_explicit_current_tenant
from app.db.models.tenant import Tenant
from app.db.session import get_sync_db
from app.services.graph_client import GraphAPIError
from app.simulation.coverage import build_coverage
from app.simulation.tenant_reader import read_tenant_identity

router = APIRouter(prefix="/ca-coverage", tags=["Conditional Access coverage"])

_QUESTIONS = ("mfa", "legacy_auth", "admin_mfa")
_CSV_FIELDS = [
    "id",
    "display_name",
    "user_principal_name",
    "enabled",
    "is_guest",
    "is_admin",
    *(f"{q}_{part}" for q in _QUESTIONS for part in ("status", "policies", "reasons")),
]
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


@router.get("")
async def get_ca_coverage(
    format: Literal["json", "csv"] = Query("json"),
    db: Session = Depends(get_sync_db),
    current_tenant: Tenant = Depends(get_explicit_current_tenant),
):
    try:
        identity = await read_tenant_identity(db, current_tenant)
    except GraphAPIError as exc:
        # Never report from partial data.
        raise HTTPException(status_code=502, detail={"code": "GRAPH_READ_FAILED", "category": exc.category}) from exc

    report = build_coverage(identity)
    if format == "json":
        return report
    return Response(
        content=_to_csv(report),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="ca-coverage.csv"'},
    )


def _to_csv(report: dict) -> str:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=_CSV_FIELDS)
    writer.writeheader()
    for user in report["users"]:
        row = {key: user.get(key) for key in _CSV_FIELDS[:6]}
        for question in _QUESTIONS:
            result = user[question]
            row[f"{question}_status"] = result["status"]
            row[f"{question}_policies"] = "; ".join(result["policies"])
            row[f"{question}_reasons"] = "; ".join(result["reasons"])
        writer.writerow({key: _safe_cell(value) for key, value in row.items()})
    return out.getvalue()


def _safe_cell(value):
    """Directory names are tenant-controlled: stop spreadsheet formula injection."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value
