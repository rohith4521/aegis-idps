from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_user
from app.models.user import User
from app.schemas.incident import (
    IncidentRead,
    IncidentDetailRead,
    IncidentStatusUpdate,
)
from app.services.incident_service import IncidentService

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get("", response_model=List[IncidentRead])
def list_incidents(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = Query(None, description="LOW, MEDIUM, HIGH, CRITICAL"),
    status_filter: Optional[str] = Query(None, alias="status", description="ACTIVE, INVESTIGATING, RESOLVED, FALSE_POSITIVE"),
    category: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    is_simulation: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List correlated security incidents with filtering and pagination."""
    incidents, _ = IncidentService.get_incidents(
        db=db,
        skip=skip,
        limit=limit,
        severity=severity,
        status=status_filter,
        category=category,
        source_ip=source_ip,
        is_simulation=is_simulation,
    )
    return incidents


@router.get("/{incident_id}", response_model=IncidentDetailRead)
def get_incident_detail(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve full incident investigation dossier including correlated events and threat factors."""
    incident = IncidentService.get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident #{incident_id} not found"
        )
    return incident


@router.patch("/{incident_id}/status", response_model=IncidentRead)
def update_incident_status(
    incident_id: int,
    payload: IncidentStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update incident operational status with SOC analyst audit tracking."""
    allowed_statuses = ["ACTIVE", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
    if payload.status.upper() not in allowed_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{payload.status}'. Allowed: {', '.join(allowed_statuses)}"
        )

    incident = IncidentService.get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident #{incident_id} not found"
        )

    updated = IncidentService.update_status(
        db=db,
        incident=incident,
        new_status=payload.status,
        notes=payload.notes,
        current_user=current_user
    )
    return updated
