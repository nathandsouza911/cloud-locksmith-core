from sqlalchemy import Column, String, Integer, DateTime
from sqlalchemy.sql import func
from app.db.base import Base


class ReportSchedule(Base):
    __tablename__ = "report_schedules"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String, index=True)

    report_type = Column(String)
    frequency = Column(String)

    last_run_at = Column(DateTime)
    next_run_at = Column(DateTime)

    created_at = Column(DateTime, server_default=func.now())
