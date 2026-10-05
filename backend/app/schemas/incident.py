from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, Field, ConfigDict
from app.schemas.security_event import SecurityEventRead


class ThreatFactor(BaseModel):
    reason: str
    points: int

    model_config = ConfigDict(from_attributes=True)


class ThreatScoreRead(BaseModel):
    id: int
    incident_id: int
    score: int
    severity: str
    confidence: int
    factors: List[Dict[str, Any]]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentBase(BaseModel):
    title: str
    category: str
    severity: str
    status: str
    threat_score: int
    confidence: int
    source_ip: str
    destination_ip: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    event_count: int
    is_simulation: bool = False
    origin: str = "REAL"


class IncidentRead(IncidentBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentDetailRead(IncidentRead):
    threat_score_detail: Optional[ThreatScoreRead] = None
    events: List[SecurityEventRead] = []

    model_config = ConfigDict(from_attributes=True)


class IncidentStatusUpdate(BaseModel):
    status: str = Field(..., description="ACTIVE, INVESTIGATING, RESOLVED, FALSE_POSITIVE")
    notes: Optional[str] = Field(None, max_length=500)
