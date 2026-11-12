from sqlalchemy import Column, String, DateTime, Index
from app.db.base import Base
from app.utils.datetime import utc_now


class OAuthStateNonce(Base):
    """
    Single-use store for OAuth state nonces.

    A nonce is written when OAuth /start is called and claimed (used_at set)
    atomically on the first /callback invocation.  Any second attempt with
    the same nonce is rejected, preventing replay attacks within the 10-minute
    state window.

    Rows older than 15 minutes can be purged by the cleanup task.
    """

    __tablename__ = "oauth_state_nonces"

    nonce = Column(String(64), primary_key=True)
    flow = Column(String(32), nullable=True)  # "smb_onboarding" | "connect_tenant"
    created_at = Column(DateTime, nullable=False, default=utc_now)
    used_at = Column(DateTime, nullable=True)

    __table_args__ = (Index("ix_oauth_state_nonces_created_at", "created_at"),)
