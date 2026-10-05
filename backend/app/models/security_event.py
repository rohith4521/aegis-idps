from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database.base import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False, index=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True, index=True)
    protocol = Column(String(10), nullable=False, default="TCP")
    event_type = Column(String(50), nullable=False, default="alert", index=True)
    signature = Column(String(255), nullable=False, index=True)
    signature_id = Column(Integer, nullable=True, index=True)
    category = Column(String(100), nullable=False, default="Generic Suspicious Activity", index=True)
    severity = Column(Integer, nullable=False, default=3)  # 1: High, 2: Medium, 3: Low
    action = Column(String(20), nullable=False, default="allowed")
    raw_reference = Column(Text, nullable=True)
    is_simulation = Column(Boolean, default=False, nullable=False, index=True)
    
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    incident = relationship("Incident", back_populates="events")
