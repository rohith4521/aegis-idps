from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database.base import Base


class PreventionAction(Base):
    __tablename__ = "prevention_actions"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    action = Column(String(50), nullable=False)  # TEMPORARY_BLOCK, PERMANENT_BLOCK, UNBLOCK, WHITELIST, LOG_ONLY
    target = Column(String(100), nullable=False, index=True)  # IP address or domain
    reason = Column(String(255), nullable=False)
    duration_minutes = Column(Integer, nullable=True)
    status = Column(String(20), nullable=False, default="EXECUTED")  # EXECUTED, FAILED, REVERTED
    provider = Column(String(50), nullable=False, default="mock")     # mock, firewall
    is_simulation = Column(Boolean, nullable=False, default=False, index=True)
    executed_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    incident = relationship("Incident", back_populates="prevention_actions")
