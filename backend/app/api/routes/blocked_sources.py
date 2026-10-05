from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.api.deps import get_db, get_current_user, get_current_admin
from app.models.user import User
from app.models.blocked_source import BlockedSource
from app.schemas.prevention import (
    BlockedSourceRead,
    BlockedSourceUnblockRequest,
    AllowlistRequest,
)
from app.prevention.engine import PreventionEngine

router = APIRouter(prefix="/blocked-sources", tags=["Blocked Sources & Allowlist"])


@router.get("", response_model=List[BlockedSourceRead])
def list_blocked_sources(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    status_filter: Optional[str] = Query(None, alias="status", description="ACTIVE, EXPIRED, MANUALLY_UNBLOCKED, WHITELISTED"),
    is_whitelisted: Optional[bool] = Query(None),
    is_simulation: Optional[bool] = Query(None),
    search_ip: Optional[str] = Query(None, alias="ip"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List blocked sources and allowlisted entries with status filters."""
    # Run lazy expiry cleanup so queries always reflect up-to-date state
    PreventionEngine.cleanup_expired_blocks(db)

    query = db.query(BlockedSource)
    if status_filter:
        query = query.filter(BlockedSource.status == status_filter.upper())
    if is_whitelisted is not None:
        query = query.filter(BlockedSource.is_whitelisted == is_whitelisted)
    if is_simulation is not None:
        query = query.filter(BlockedSource.is_simulation == is_simulation)
    if search_ip:
        query = query.filter(BlockedSource.ip.ilike(f"%{search_ip}%"))

    entries = query.order_by(desc(BlockedSource.blocked_time)).offset(skip).limit(limit).all()
    return entries


@router.get("/{blocked_id}", response_model=BlockedSourceRead)
def get_blocked_source_detail(
    blocked_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve details of a single blocked source entry."""
    entry = db.query(BlockedSource).filter(BlockedSource.id == blocked_id).first()
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Blocked source record #{blocked_id} not found"
        )
    return entry


@router.post("/{blocked_id}/unblock", response_model=BlockedSourceRead)
def unblock_source(
    blocked_id: int,
    payload: BlockedSourceUnblockRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Manually unblock a currently blocked source with SOC justification."""
    entry, message = PreventionEngine.manual_unblock(
        db=db,
        blocked_id=blocked_id,
        reason=payload.reason,
        actor_user=current_user
    )
    if not entry:
        if "not found" in message.lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=message)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)
    return entry


@router.post("/allowlist", response_model=BlockedSourceRead)
def add_source_to_allowlist(
    payload: AllowlistRequest,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
):
    """Add a trusted source address to the allowlist (Admin only)."""
    entry, message = PreventionEngine.set_allowlist(
        db=db,
        ip=payload.ip,
        reason=payload.reason,
        actor_user=current_admin
    )
    if not entry:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)
    return entry
