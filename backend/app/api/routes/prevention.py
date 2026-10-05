from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.api.deps import get_db, get_current_user, get_current_admin
from app.models.user import User
from app.models.prevention_action import PreventionAction
from app.models.blocked_source import BlockedSource
from app.models.system_setting import SystemSetting
from app.schemas.prevention import (
    PreventionActionRead,
    PreventionStatusRead,
    PreventionPolicyUpdate,
)
from app.prevention.engine import PreventionEngine

router = APIRouter(prefix="/prevention", tags=["Prevention Engine"])


@router.get("/actions", response_model=List[PreventionActionRead])
def list_prevention_actions(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    action_type: Optional[str] = Query(None, alias="action"),
    provider: Optional[str] = Query(None),
    is_simulation: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List historical automated and manual prevention decisions."""
    query = db.query(PreventionAction)
    if action_type:
        query = query.filter(PreventionAction.action == action_type.upper())
    if provider:
        query = query.filter(PreventionAction.provider == provider)
    if is_simulation is not None:
        query = query.filter(PreventionAction.is_simulation == is_simulation)

    actions = query.order_by(desc(PreventionAction.executed_at)).offset(skip).limit(limit).all()
    return actions


@router.get("/status", response_model=PreventionStatusRead)
def get_prevention_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve operational status and readiness of the prevention engine."""
    provider = PreventionEngine.get_provider(db)
    health = provider.health_check()

    active_blocks = db.query(BlockedSource).filter(BlockedSource.status == "ACTIVE").count()
    whitelisted = db.query(BlockedSource).filter(BlockedSource.is_whitelisted == True).count()

    return PreventionStatusRead(
        enabled=PreventionEngine.is_prevention_enabled(db),
        provider=health.get("provider", "mock"),
        auto_block_threshold=PreventionEngine.get_auto_block_threshold(db),
        default_block_duration_minutes=PreventionEngine.get_default_duration_minutes(db),
        active_blocks_count=active_blocks,
        whitelisted_count=whitelisted,
        real_firewall_enabled=health.get("real_firewall_enabled", False),
        mode_description=health.get("description", "Safe Mock Prevention Provider")
    )


@router.get("/policies")
def get_prevention_policies(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get active prevention policies and threshold configurations."""
    return {
        "prevention_enabled": PreventionEngine.is_prevention_enabled(db),
        "auto_prevention_threshold": PreventionEngine.get_auto_block_threshold(db),
        "default_block_duration_minutes": PreventionEngine.get_default_duration_minutes(db),
        "provider": PreventionEngine.get_provider(db).health_check()["provider"],
        "tiers": {
            "LOW": "LOG_ONLY (score 0-29)",
            "MEDIUM": "ALERT_ONLY (score 30-59)",
            "HIGH": "MONITOR_ONLY (score 60-79)",
            "CRITICAL": f"AUTOMATED_MOCK_BLOCK_ELIGIBLE (score >= {PreventionEngine.get_auto_block_threshold(db)})"
        }
    }


@router.patch("/policies")
def update_prevention_policies(
    payload: PreventionPolicyUpdate,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
):
    """Update automated prevention policy thresholds (Admin only)."""
    if payload.enabled is not None:
        setting = db.query(SystemSetting).filter(SystemSetting.key == "prevention_enabled").first()
        if setting:
            setting.value = "true" if payload.enabled else "false"

    if payload.auto_block_threshold is not None:
        setting = db.query(SystemSetting).filter(SystemSetting.key == "auto_prevention_threshold").first()
        if setting:
            setting.value = str(payload.auto_block_threshold)

    if payload.default_block_duration_minutes is not None:
        setting = db.query(SystemSetting).filter(SystemSetting.key == "default_block_duration_minutes").first()
        if setting:
            setting.value = str(payload.default_block_duration_minutes)

    db.commit()
    return {"message": "Prevention policies updated successfully"}
