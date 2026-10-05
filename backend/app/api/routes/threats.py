from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.api.deps import get_db, get_current_user
from app.models.user import User
from app.models.threat_score import ThreatScore
from app.schemas.incident import ThreatScoreRead

router = APIRouter(prefix="/threats", tags=["Threat Intelligence & Scoring"])


@router.get("", response_model=List[ThreatScoreRead])
def list_threat_scores(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = Query(None, description="LOW, MEDIUM, HIGH, CRITICAL"),
    min_score: Optional[int] = Query(None, ge=0, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List threat intelligence evaluations with factor breakdowns."""
    query = db.query(ThreatScore)
    if severity:
        query = query.filter(ThreatScore.severity == severity.upper())
    if min_score is not None:
        query = query.filter(ThreatScore.score >= min_score)
    
    threats = query.order_by(desc(ThreatScore.score), desc(ThreatScore.created_at)).offset(skip).limit(limit).all()
    return threats


@router.get("/{threat_id}", response_model=ThreatScoreRead)
def get_threat_score_detail(
    threat_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve full factor explanation for a specific threat score assessment."""
    threat = db.query(ThreatScore).filter(ThreatScore.id == threat_id).first()
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat score assessment #{threat_id} not found"
        )
    return threat
