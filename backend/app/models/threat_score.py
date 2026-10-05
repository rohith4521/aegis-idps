from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database.base import Base


class ThreatScore(Base):
    __tablename__ = "threat_scores"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    score = Column(Integer, nullable=False, default=0)
    severity = Column(String(20), nullable=False, default="LOW")
    confidence = Column(Integer, nullable=False, default=70)
    factors = Column(JSON, nullable=False, default=list)  # [{"reason": "...", "points": 30, "category": "..."}]
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    incident = relationship("Incident", back_populates="threat_score_detail")
