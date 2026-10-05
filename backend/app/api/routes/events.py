from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.api.deps import get_db, get_current_user, require_roles
from app.models.user import User
from app.models.security_event import SecurityEvent
from app.schemas.security_event import (
    SecurityEventRead,
    EventIngestBatchRequest,
    EventIngestResponse,
    DemoEventGenerateRequest,
)
from app.services.event_service import EventService
from app.detection.generator import DemoEventGenerator

router = APIRouter(prefix="/events", tags=["Security Events"])


@router.get("", response_model=List[SecurityEventRead])
def list_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[int] = Query(None, ge=1, le=4),
    category: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    is_simulation: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve normalized security events with pagination and filtering."""
    events, _ = EventService.get_events(
        db=db,
        skip=skip,
        limit=limit,
        severity=severity,
        category=category,
        source_ip=source_ip,
        is_simulation=is_simulation,
    )
    return events


@router.get("/{event_id}", response_model=SecurityEventRead)
def get_event_detail(
    event_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve detailed view of a single security event."""
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Security event not found")
    return event


@router.post("/ingest", response_model=EventIngestResponse)
def ingest_eve_events(
    payload: EventIngestBatchRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Ingest a batch of raw Suricata EVE JSON events.
    Events are parsed, normalized, validated, and deduplicated.
    """
    response = EventService.ingest_batch(db, payload.events)
    return response


@router.post("/demo/generate", response_model=EventIngestResponse)
def generate_demo_events(
    payload: DemoEventGenerateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Safe Demo Mode: Generate realistic simulated Suricata events.
    All generated events are explicitly marked as is_simulation=True.
    Passes directly into the normalization and ingestion pipeline.
    """
    raw_events = DemoEventGenerator.generate_batch(
        count=payload.count,
        scenario=payload.scenario or "mixed"
    )
    result = EventService.ingest_batch(db, raw_events)
    return result
