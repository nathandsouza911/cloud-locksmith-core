"""Campaign results export — CSV and PDF formats.

Both functions accept the dict returned by ``campaign_service.get_campaign_status``
and write to the shared reports directory. Returns the file path as a string so
callers can stream the file to the client.
"""

from __future__ import annotations

import csv
import uuid
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

REPORTS_BASE = "/app/reports"


async def export_campaign_csv(campaign_status: dict) -> str:
    """Write a per-task CSV for the campaign and return the file path."""
    campaign_id = campaign_status["campaign_id"]
    base = Path(REPORTS_BASE) / "campaigns"
    base.mkdir(parents=True, exist_ok=True)

    path = base / f"campaign_{campaign_id}.csv"

    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "Campaign ID",
                "Campaign Status",
                "Tenant ID",
                "Tenant Name",
                "Control ID",
                "Resource ID",
                "Display Name",
                "UPN",
                "Status",
                "Attempts",
                "Error",
                "Rollback Available",
            ]
        )
        rollback_available = campaign_status.get("rollback_available", False)
        for task in campaign_status.get("tasks", []):
            rd = task.get("resource_detail") or {}
            writer.writerow(
                [
                    campaign_id,
                    campaign_status.get("status", ""),
                    task.get("tenant_id", ""),
                    task.get("tenant_name", ""),
                    task.get("control_id", ""),
                    rd.get("resource_id", ""),
                    rd.get("display_name", ""),
                    rd.get("upn", ""),
                    task.get("status", ""),
                    task.get("attempts", 0),
                    task.get("error") or "",
                    str(rollback_available),
                ]
            )

    return str(path)


async def export_campaign_pdf(campaign_status: dict) -> str:
    """Write an executive-summary PDF for the campaign and return the file path."""
    campaign_id = campaign_status["campaign_id"]
    base = Path(REPORTS_BASE) / "campaigns"
    base.mkdir(parents=True, exist_ok=True)

    unique_id = uuid.uuid4().hex
    path = base / f"campaign_{campaign_id}_{unique_id}.pdf"

    c = canvas.Canvas(str(path), pagesize=A4)
    text = c.beginText(40, 800)

    # --- Executive summary header ---
    text.textLine("Campaign Results Report")
    text.textLine(f"Campaign ID:     {campaign_id}")
    text.textLine(f"Status:          {campaign_status.get('status', '')}")
    text.textLine(f"Created by:      {campaign_status.get('created_by', '')}")
    text.textLine(f"Approved by:     {campaign_status.get('approved_by', '')}")
    text.textLine(f"Started:         {campaign_status.get('started_at', 'N/A')}")
    text.textLine(f"Completed:       {campaign_status.get('completed_at', 'N/A')}")
    text.textLine(f"Dry run:         {campaign_status.get('dry_run', False)}")
    text.textLine("")

    # --- Summary metrics ---
    text.textLine("Summary:")
    text.textLine(f"  Tenants affected:  {campaign_status.get('tenants_affected', 0)}")
    text.textLine(f"  Tasks executed:    {campaign_status.get('tasks_executed', 0)}")
    text.textLine(f"  Tasks failed:      {campaign_status.get('tasks_failed', 0)}")
    text.textLine(f"  Rollback available:{campaign_status.get('rollback_available', False)}")
    text.textLine(f"  Controls:          {', '.join(campaign_status.get('control_ids', []))}")
    text.textLine("")

    # --- Per-tenant breakdown ---
    text.textLine("Per-Tenant Breakdown:")
    tenant_tasks: dict[str, list[dict]] = {}
    for task in campaign_status.get("tasks", []):
        tid = task.get("tenant_id", "")
        tenant_tasks.setdefault(tid, []).append(task)

    for tid, tasks in tenant_tasks.items():
        tenant_name = tasks[0].get("tenant_name") or tid
        text.textLine(f"  Tenant: {tenant_name} ({tid})")
        for task in tasks:
            rd = task.get("resource_detail") or {}
            resource = rd.get("display_name") or rd.get("resource_id") or "-"
            error = f" ERR: {task['error']}" if task.get("error") else ""
            text.textLine(f"    [{task.get('status', '')}] {task.get('control_id', '')} — {resource}{error}")

    c.drawText(text)
    c.showPage()
    c.save()

    return str(path)
