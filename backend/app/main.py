import logging
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from app.api.v1 import auth, health, session, tenants
from app.config import settings
from app.api.v1.remediation_verification import router as remediation_verification_router
from app.middleware.tenant_context import TenantContextMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.core.redis_client import verify_redis_available_in_production
from app.services.auth.jwt_service import decode_access_token
from app.services.graph_client import verify_graph_remediation_permissions_startup
from app.db.models.compliance_result import ComplianceResult
from app.db.models.control_execution import ControlExecution
from app.db.models.control_snapshot import ControlSnapshot
from app.db.models.control_state import ControlState
from app.db.models.remediation_audit import RemediationAuditLog
from app.demo.guards import DemoModeMiddleware, install_outbound_block, validate_demo_settings


logger_startup = logging.getLogger("app.startup")

# Demo mode refuses to start next to real credentials or production settings, and
# blocks all outbound HTTP before any route can run.
validate_demo_settings(settings)
if settings.DEMO_MODE:
    install_outbound_block()

app = FastAPI(title=settings.APP_NAME, version="0.1.0")
logger = logging.getLogger(__name__)
from starlette.middleware.sessions import SessionMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

app.state.auth_cookie_name = settings.APP_AUTH_COOKIE_NAME

# Origins are driven by CORS_ALLOWED_ORIGINS env var (see config.py)
CORS_ALLOW_ORIGINS = settings.cors_allowed_origins

# NOTE on ordering: Starlette's add_middleware inserts at index 0, so the
# LAST middleware registered is the OUTERMOST (runs first). ProxyHeaders must
# normalise request.client.host BEFORE anything reads it (rate limiting,
# HTTPS/HSTS), so it is registered LAST — see the ProxyHeaders block near the
# RateLimit registration below. (Previously it was registered first here,
# which made it the innermost middleware: it ran AFTER the rate limiter had
# already keyed on the un-normalised proxy IP.)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SESSION_SECRET,
    same_site="lax",
    https_only=settings.app_auth_cookie_secure,
)


# Core APIs
app.include_router(health.router, prefix="/api/v1")
app.include_router(tenants.router, prefix="/api/v1")
app.include_router(session.router, prefix="/api/v1")
# Auth router is mounted ONCE under /api. A second mount without a prefix
# would create a duplicate route surface (e.g. /auth/login-password vs
# /api/auth/login-password) — the rate limiter previously only matched the
# /api/v1/... path and silently ignored requests to the alias, fully
# bypassing the limit. Endpoint-name-based limiting (see rate_limit.py)
# now makes route-name uniqueness essential.
app.include_router(auth.router, prefix="/api")

# OAuth
from app.api.routes import auth_microsoft
from app.api.routes import attack_paths

app.include_router(auth_microsoft.router, prefix="/api/v1/auth")
app.include_router(attack_paths.router, prefix="/api/v1")

# Graph
from app.api.routes import graph

app.include_router(graph.router, prefix="/api/v1")

# Remediation
from app.api.routes import (
    remediation_decisions,
    remediation_execution,
    remediation_audit,
)

app.include_router(remediation_decisions.router, prefix="/api/v1")
app.include_router(remediation_execution.router, prefix="/api/v1")
app.include_router(remediation_audit.router, prefix="/api/v1")

from app.api.routes import identity_scan

app.include_router(identity_scan.router)


# Compliance
from app.api.routes import compliance_results, posture_history
from app.api.v1.compliance_dashboard import router as compliance_dashboard_router

app.include_router(compliance_results.router, prefix="/api/v1")
app.include_router(posture_history.router, prefix="/api/v1")
app.include_router(compliance_dashboard_router, prefix="/api/v1")

from app.api.routes import alerts, notifications

app.include_router(alerts.router, prefix="/api/v1")
app.include_router(notifications.router, prefix="/api/v1")

from app.api.routes import scan_status

app.include_router(scan_status.router)

app.include_router(remediation_verification_router)
from app.api.v1.remediation_rollback import (
    router as remediation_rollback_router,
)

app.include_router(remediation_rollback_router, prefix="/api/v1")

from app.api.v1.remediation_rollback_eligibility import (
    router as remediation_rollback_eligibility_router,
)

app.include_router(remediation_rollback_eligibility_router)

from app.services.remediation.crash_recovery import recover_stuck_executions
from app.db.session import SyncSessionLocal
from app.db.schema_guard import verify_required_schema


@app.get("/")
async def root():
    return {"app": settings.APP_NAME, "version": "0.1.0"}


from app.api.v1.remediation_execution_eligibility import (
    router as remediation_execution_eligibility_router,
)

app.include_router(remediation_execution_eligibility_router)

_CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_CSRF_ALLOWED_ORIGINS = set(CORS_ALLOW_ORIGINS)


@app.middleware("http")
async def https_redirect_and_hsts(request: Request, call_next):
    if settings.ENVIRONMENT.lower() == "production":
        # ProxyHeadersMiddleware only updates request.url.scheme when the
        # upstream proxy IP is in TRUSTED_PROXY_HOSTS. On Railway the proxy IP
        # is dynamic, so fall back to X-Forwarded-Proto directly. This is safe
        # because Railway's uvicorn port is not publicly reachable — only
        # Railway's own load balancer can set this header in practice.
        forwarded_proto = request.headers.get("x-forwarded-proto", "").lower()
        is_https = request.url.scheme == "https" or forwarded_proto == "https"
        if not is_https:
            https_url = str(request.url).replace("http://", "https://", 1)
            return Response(status_code=301, headers={"Location": https_url})
    response = await call_next(request)
    if settings.ENVIRONMENT.lower() == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.middleware("http")
async def csrf_origin_check(request: Request, call_next):
    if request.method not in _CSRF_SAFE_METHODS:
        # Require Origin header on all state-changing requests. Browsers send
        # Origin on every non-safe fetch/XHR/form submission from a real web
        # context. A missing Origin on a non-safe method indicates either a
        # non-browser client without CSRF protection assumptions, or an
        # attempt to bypass this check — fail closed in both cases.
        #
        # Referer is intentionally NOT accepted as a fallback: it is frequently
        # stripped by privacy extensions, proxies, and referrer-policy
        # settings, so using it as a source of origin truth causes both false
        # accepts and false rejects.
        origin = request.headers.get("origin")
        if not origin or origin not in _CSRF_ALLOWED_ORIGINS:
            logger.warning(
                "csrf_origin_rejected method=%s path=%s origin=%s",
                request.method,
                request.url.path,
                origin or "<missing>",
            )
            return Response(content="Forbidden", status_code=403)
    return await call_next(request)


@app.middleware("http")
async def attach_auth_payload(request: Request, call_next):
    logger.debug("auth_middleware_hit path=%s", request.url.path)
    token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
    elif settings.APP_AUTH_COOKIE_NAME in request.cookies:
        token = request.cookies.get(settings.APP_AUTH_COOKIE_NAME)

    request.state.auth_payload = None
    if token:
        try:
            request.state.auth_payload = decode_access_token(token)
        except Exception:
            request.state.auth_payload = None

    return await call_next(request)


app.add_middleware(TenantContextMiddleware)
# Outside TenantContextMiddleware: the reserved demo tenant rule and demo write refusal
# run before tenant resolution.
app.add_middleware(DemoModeMiddleware, demo_mode=settings.DEMO_MODE)
app.add_middleware(RateLimitMiddleware)

# Registered LAST => OUTERMOST (runs first). This normalises request.client.host
# from X-Forwarded-For for explicitly trusted proxies BEFORE the rate limiter or
# HTTPS/HSTS middleware read it. Do not move this above RateLimitMiddleware.
app.add_middleware(
    ProxyHeadersMiddleware,
    trusted_hosts=settings.trusted_proxy_hosts,
)

from app.api.v1.compliance_score import router as compliance_score_router

app.include_router(compliance_score_router)

from app.api.v1.offboarding import router as offboarding_router

app.include_router(offboarding_router)

from app.api.v1.insurance_readiness import router as insurance_router

app.include_router(insurance_router)

from app.api.v1.offboarding_eligibility import router as offboarding_eligibility_router

app.include_router(offboarding_eligibility_router)

from app.api.v1.audit_logs import router as audit_logs_router

app.include_router(audit_logs_router)

from app.api.v1.offboarding_rollback_summary import router as rollback_summary_router

app.include_router(rollback_summary_router)

from app.api.v1.insurance_evidence_report import router as insurance_report_router

app.include_router(insurance_report_router)

from app.api.v1.insurance_evidence_history import router as insurance_history_router

app.include_router(insurance_history_router)

from app.api.v1.reports.cyber_insurance import router as cyber_insurance_report_router

app.include_router(cyber_insurance_report_router)

from app.api.v1.posture.timeline import router as posture_timeline_router

app.include_router(posture_timeline_router)

from app.api.v1.posture.score import router as posture_score_router

app.include_router(posture_score_router)


from app.api.v1.posture_trend import router as posture_trend_router

app.include_router(posture_trend_router)

from app.api.v1.remediation_priority import router as remediation_priority_router

app.include_router(remediation_priority_router)

from app.api.v1.risk_feed import router as risk_feed_router

app.include_router(risk_feed_router, prefix="/api/v1")

from app.api.v1.fleet import router as fleet_router

app.include_router(fleet_router, prefix="/api/v1")

from app.api.v1.msp import router as msp_router

app.include_router(msp_router, prefix="/api/v1")

from app.api.v1.baseline import router as baseline

app.include_router(baseline, prefix="/api/v1")


from app.api.v1.msp_baseline import router as baseline_router

app.include_router(baseline_router, prefix="/api/v1")

from app.api.v1.executive_summary import router as executive_summary_router

app.include_router(executive_summary_router, prefix="/api/v1")

from app.api.v1.remediation_timeline import router as remediation_timeline_router

app.include_router(remediation_timeline_router, prefix="/api/v1")

from app.api.v1.remediation_history import router as remediation_history_router

app.include_router(remediation_history_router, prefix="/api/v1")

from app.api.v1.control import router as control_router
from app.api.v1.control import controls_router

app.include_router(control_router, prefix="/api/v1")
app.include_router(controls_router, prefix="/api/v1")

from app.api.v1.break_glass_events import router as break_glass_events_router

app.include_router(break_glass_events_router)

from app.api.v1.offboarding_sessions import router as offboarding_sessions_router

app.include_router(offboarding_sessions_router, prefix="/api/v1")

from app.api.v1.users import router as users_router

app.include_router(users_router, prefix="/api/v1")

from app.api.v1.license import router as license_router

app.include_router(license_router, prefix="/api/v1")

from app.api.v1.user_offboarding import router as user_offboarding_router

app.include_router(user_offboarding_router, prefix="/api/v1")

from app.api.v1.simulations import router as simulations_router

app.include_router(simulations_router, prefix="/api/v1")

from app.api.v1.support import router as support_router

app.include_router(support_router, prefix="/api/v1")

from app.api.v1.fleet_campaigns import router as fleet_campaigns_router

app.include_router(fleet_campaigns_router, prefix="/api/v1")

from app.api.v1.drift_notifications import router as drift_notifications_router

app.include_router(drift_notifications_router, prefix="/api/v1")

from app.api.v1.realtime import router as realtime_router

app.include_router(realtime_router, prefix="/api/v1")

# Sprint 1 — technician work queue (read-only presentation over existing findings).
from app.api.v1.work import router as work_router

app.include_router(work_router, prefix="/api/v1")

# Sprint 3 — workflow definition registry (library) and client timeline.
# Sprint 4 — workflow runtime.
#
# ORDER MATTERS: the runtime router owns concrete /workflows/runs/... paths and
# must be registered BEFORE the library router, whose /workflows/{workflow_id}
# would otherwise shadow them. Covered by
# test_the_active_runs_route_is_not_shadowed_by_the_definition_route.
from app.api.v1.workflow_runs import router as workflow_runs_router
from app.api.v1.workflows import router as workflows_router
from app.api.v1.clients import router as clients_router

# Wave 2 — the generic workflow review surface every workflow now shares. It
# owns /workflows/{key}/review/... and is registered before the library router
# for the same shadowing reason as workflow_runs_router above.
from app.api.v1.workflow_review import router as workflow_review_router

app.include_router(workflow_runs_router, prefix="/api/v1")
app.include_router(workflow_review_router, prefix="/api/v1")
app.include_router(workflows_router, prefix="/api/v1")
app.include_router(clients_router, prefix="/api/v1")

if settings.DEMO_MODE:
    from app.demo.router import router as demo_router

    app.include_router(demo_router)

# Importing the workflow packages registers their projectors, which the generic
# review surface above resolves by workflow id. OAuth Review had its own router
# through Sprint 5; Wave 2 retired it and serves OAuth from the generic surface
# under the key "oauth-review". Imported via `from ... import` and not
# `import app.services...`, which would rebind the name `app` in this module
# from the FastAPI instance to the `app` package.
from app.services.workflows import identity_hygiene as _identity_hygiene  # noqa: F401
from app.services.workflows import oauth_review as _oauth_review  # noqa: F401

for route in app.routes:
    path = getattr(route, "path", None)
    if path:
        logger_startup.debug("route_registered path=%s", path)

import asyncio
from app.scheduler import scheduler_loop


@app.on_event("startup")
def check_remediation_dry_run_config():
    if settings.ENVIRONMENT == "production" and settings.REMEDIATION_DRY_RUN:
        logger_startup.warning(
            "dry_run_enabled_in_production REMEDIATION_DRY_RUN=True in environment=production — "
            "remediations will NOT be applied"
        )
    if settings.ENVIRONMENT != "production" and not settings.REMEDIATION_DRY_RUN:
        logger_startup.warning(
            "live_remediation_outside_production REMEDIATION_DRY_RUN=False in environment=%s — "
            "remediations will be applied to real tenants",
            settings.ENVIRONMENT,
        )


@app.on_event("startup")
def verify_production_redis():
    verify_redis_available_in_production()


@app.on_event("startup")
def verify_database_schema():
    logger_startup.info("verifying_database_schema")
    with SyncSessionLocal() as db:
        try:
            db.execute(text("SELECT block_reason FROM compliance_results LIMIT 1"))
        except Exception as exc:
            raise RuntimeError("Database schema is outdated. Missing column: block_reason") from exc
    verify_required_schema()
    logger_startup.info("database_schema_verified")


@app.on_event("startup")
def validate_no_legacy_lowercase_ca_control_ids():
    logger_startup.info("validating_legacy_ca_control_ids")
    with SyncSessionLocal() as db:
        checks = [
            ("compliance_results", ComplianceResult),
            ("control_executions", ControlExecution),
            ("control_snapshots", ControlSnapshot),
            ("control_states", ControlState),
            ("remediation_audit_logs", RemediationAuditLog),
        ]
        violations: list[str] = []
        for table_name, model in checks:
            row = (
                db.query(model.control_id)
                .filter(model.control_id.like("ca_%"))
                .order_by(model.control_id.asc())
                .first()
            )
            if row and row[0]:
                violations.append(f"{table_name}:{row[0]}")
        if violations:
            raise RuntimeError("Legacy lowercase CA control IDs detected at startup: " + ", ".join(violations))
    logger_startup.info("legacy_ca_control_ids_validated")


@app.on_event("startup")
async def verify_graph_remediation_permissions():
    if settings.DEMO_MODE:
        logger_startup.info("graph_permission_check_skipped demo_mode")
        return
    try:
        await verify_graph_remediation_permissions_startup()
    except Exception as exc:
        if settings.ENVIRONMENT.lower() == "production":
            raise RuntimeError("Graph app missing required permissions for remediation") from exc
        logger_startup.warning(
            "graph_permission_check_failed env=%s error=%s — skipping in non-production",
            settings.ENVIRONMENT,
            exc,
        )


@app.on_event("startup")
async def start_background_scheduler():
    if settings.ENABLE_SCHEDULER:
        logger_startup.info("scheduler_starting")
        asyncio.create_task(scheduler_loop())


@app.on_event("startup")
def handle_crash_recovery():
    from app.services.remediation.crash_recovery import recover_campaign_jobs

    with SyncSessionLocal() as db:
        result = recover_stuck_executions(db)
        logger_startup.warning(
            "crash_recovery_completed processed=%s failed=%s verified_complete=%s",
            result.get("processed", 0),
            result.get("failed", 0),
            result.get("verified_complete", 0),
        )
        job_result = recover_campaign_jobs(db)
        if job_result["reclaimed"] or job_result["permanently_failed"]:
            logger_startup.warning(
                "campaign_job_recovery_completed reclaimed=%s permanently_failed=%s",
                job_result["reclaimed"],
                job_result["permanently_failed"],
            )


from app.core.metrics import get_metrics
from fastapi import APIRouter

router = APIRouter()


@app.get("/internal/health", tags=["internal"])
def internal_health():
    return get_metrics()


app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.PORT,
        reload=settings.ENVIRONMENT.lower() == "development",
    )
