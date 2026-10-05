from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, JSON
from app.database.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    actor = Column(String(100), nullable=False, index=True)
    action = Column(String(100), nullable=False, index=True)
    target = Column(String(100), nullable=True, index=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    result = Column(String(20), nullable=False, default="SUCCESS")  # SUCCESS, FAILURE, DENIED
    metadata_info = Column(JSON, nullable=True)
