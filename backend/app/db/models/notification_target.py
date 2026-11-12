from sqlalchemy import Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from app.db.base import Base


class NotificationTarget(Base):
    __tablename__ = "notification_targets"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String, ForeignKey("tenants.id"), index=True)

    channel = Column(String(50))  # email | webhook | slack
    destination = Column(String(500))  # email address or webhook URL

    enabled = Column(Boolean, default=True)

    tenant = relationship("Tenant")
