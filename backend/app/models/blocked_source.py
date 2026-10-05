from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from app.database.base import Base


class BlockedSource(Base):
    __tablename__ = "blocked_sources"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(45), unique=True, nullable=False, index=True)
    reason = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False, default="CRITICAL")
    threat_score = Column(Integer, nullable=False, default=85)
    blocked_time = Column(DateTime, nullable=False, default=datetime.utcnow)
    expiry = Column(DateTime, nullable=True, index=True)
    status = Column(String(20), nullable=False, default="ACTIVE", index=True)  # ACTIVE, EXPIRED, MANUALLY_UNBLOCKED
    is_whitelisted = Column(Boolean, nullable=False, default=False, index=True)
    provider = Column(String(50), nullable=False, default="mock")
    is_simulation = Column(Boolean, nullable=False, default=False, index=True)
    created_by = Column(String(50), nullable=False, default="AUTOMATED_PREVENTION_ENGINE")
    unblocked_at = Column(DateTime, nullable=True)
    unblocked_by = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
