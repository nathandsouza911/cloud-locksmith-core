"""POST /api/v1/demo/login: sign in as the seeded fictional owner. Demo mode only.

The router is mounted only when DEMO_MODE is on, and the handler re-checks the flag,
so the route answers 404 on every other deployment. The identity and tenant come from
server-side constants, never from the request. It issues the normal app JWT cookie, so
the usual tenant middleware and UserTenantAccess checks apply to every later request.
"""

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.api.v1.auth import _create_token, _set_auth_cookie
from app.db.models.platform_user import PlatformUser
from app.db.models.tenant import Tenant
from app.db.models.user_tenant_access import UserTenantAccess
from app.db.session import get_sync_db
from app.demo import DEMO_OWNER_EMAIL, DEMO_TENANT_ID, demo_mode_enabled
from app.utils.datetime import to_naive_utc, utc_now

router = APIRouter(prefix="/api/v1/demo", tags=["demo"])


@router.post("/login")
def demo_login(response: Response, db: Session = Depends(get_sync_db)):
    if not demo_mode_enabled():
        raise HTTPException(status_code=404, detail="Not Found")

    user = db.query(PlatformUser).filter(PlatformUser.email == DEMO_OWNER_EMAIL).one_or_none()
    if user is None:
        raise HTTPException(status_code=503, detail="Demo data not seeded; run `python -m app.demo.seed`")
    access = (
        db.query(UserTenantAccess)
        .filter(UserTenantAccess.user_id == user.id, UserTenantAccess.tenant_id == DEMO_TENANT_ID)
        .one_or_none()
    )
    if access is None:
        raise HTTPException(status_code=503, detail="Demo data incomplete; reseed the demo")

    # A real Microsoft sign-in records last_delegated_auth_at; do the same so the
    # "signed in recently" check behaves as after a real sign-in. Every write is
    # still refused by DemoModeMiddleware.
    tenant = db.get(Tenant, DEMO_TENANT_ID)
    tenant.last_delegated_auth_at = to_naive_utc(utc_now())
    db.commit()

    _set_auth_cookie(response, _create_token(user))
    return {"ok": True, "tenant_id": DEMO_TENANT_ID}
