from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class BlockedSourceRead(BaseModel):
    id: int
    ip: str
    reason: str
    severity: str
    threat_score: int
    blocked_time: datetime
    expiry: Optional[datetime] = None
    status: str
    is_whitelisted: bool
    provider: str
    is_simulation: bool
    created_by: str
    unblocked_at: Optional[datetime] = None
    unblocked_by: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class BlockedSourceUnblockRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=255, description="Auditable justification for manual unblock")


class AllowlistRequest(BaseModel):
    ip: str = Field(..., description="Target IPv4 or IPv6 address to allowlist")
    reason: str = Field(..., min_length=3, max_length=255, description="Business or operational justification for allowlist")


class PreventionActionRead(BaseModel):
    id: int
    incident_id: Optional[int] = None
    action: str
    target: str
    reason: str
    duration_minutes: Optional[int] = None
    status: str
    provider: str
    is_simulation: bool
    executed_at: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PreventionStatusRead(BaseModel):
    enabled: bool
    provider: str
    auto_block_threshold: int
    default_block_duration_minutes: int
    active_blocks_count: int
    whitelisted_count: int
    real_firewall_enabled: bool = False
    mode_description: str


class PreventionPolicyUpdate(BaseModel):
    enabled: Optional[bool] = None
    auto_block_threshold: Optional[int] = Field(None, ge=30, le=100)
    default_block_duration_minutes: Optional[int] = Field(None, ge=1, le=1440)
