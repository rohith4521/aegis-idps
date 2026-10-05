from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, Field, ConfigDict


class SecurityEventBase(BaseModel):
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = Field(None, ge=1, le=65535)
    destination_port: Optional[int] = Field(None, ge=1, le=65535)
    protocol: str = "TCP"
    event_type: str = "alert"
    signature: str
    signature_id: Optional[int] = None
    category: str = "Generic Suspicious Activity"
    severity: int = Field(3, ge=1, le=4)
    action: str = "allowed"
    raw_reference: Optional[str] = None
    is_simulation: bool = False
    incident_id: Optional[int] = None


class SecurityEventCreate(SecurityEventBase):
    pass


class SecurityEventRead(SecurityEventBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EventIngestRawRequest(BaseModel):
    raw_event: Dict[str, Any] = Field(..., description="Single Suricata EVE JSON dictionary")


class EventIngestBatchRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(..., min_length=1, max_length=500, description="List of raw Suricata EVE JSON objects")


class EventIngestResponse(BaseModel):
    ingested_count: int
    skipped_count: int
    duplicate_count: int
    error_count: int
    errors: List[str] = []
    created_event_ids: List[int] = []


class DemoEventGenerateRequest(BaseModel):
    count: int = Field(10, ge=1, le=200, description="Number of demo events to generate")
    scenario: Optional[str] = Field("mixed", description="Scenario: 'mixed', 'brute_force', 'port_scan', 'sqli', 'benign'")
