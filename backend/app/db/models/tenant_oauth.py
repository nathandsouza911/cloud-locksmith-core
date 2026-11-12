# app/models/tenant_oauth.py

from sqlalchemy import Column, String, DateTime, JSON
from app.db.base import Base
from datetime import datetime


class TenantOAuth(Base):
    __tablename__ = "tenant_oauth"

    tenant_id = Column(String, primary_key=True, index=True)
    provider = Column(String, primary_key=True)  # "microsoft"
    access_token = Column(String, nullable=False)
    refresh_token = Column(String, nullable=True)
    expires_at = Column(DateTime, nullable=False)
    scopes = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
