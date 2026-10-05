from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import relationship
from app.database.base import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    category = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), nullable=False, default="MEDIUM", index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(20), nullable=False, default="ACTIVE", index=True)    # ACTIVE, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    threat_score = Column(Integer, nullable=False, default=50, index=True)
    confidence = Column(Integer, nullable=False, default=70)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=True)
    first_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    event_count = Column(Integer, default=1, nullable=False)
    is_simulation = Column(Boolean, default=False, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    events = relationship("SecurityEvent", back_populates="incident", cascade="all, delete-orphan")
    threat_score_detail = relationship("ThreatScore", uselist=False, back_populates="incident", cascade="all, delete-orphan")
    prevention_actions = relationship("PreventionAction", back_populates="incident")

    @property
    def origin(self) -> str:
        if self.events:
            has_sim = any(getattr(e, "is_simulation", False) for e in self.events)
            has_real = any(not getattr(e, "is_simulation", False) for e in self.events)
            if has_sim and has_real:
                return "MIXED"
            if has_sim:
                return "SIMULATION"
            return "REAL"
        if "[MIXED" in (self.title or ""):
            return "MIXED"
        return "SIMULATION" if self.is_simulation else "REAL"

