from typing import List, Tuple, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models.incident import Incident
from app.models.audit_log import AuditLog
from app.models.user import User


class IncidentService:
    @staticmethod
    def get_incidents(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        category: Optional[str] = None,
        source_ip: Optional[str] = None,
        is_simulation: Optional[bool] = None,
    ) -> Tuple[List[Incident], int]:
        query = db.query(Incident)

        if severity:
            query = query.filter(Incident.severity == severity.upper())
        if status:
            query = query.filter(Incident.status == status.upper())
        if category:
            query = query.filter(Incident.category.ilike(f"%{category}%"))
        if source_ip:
            query = query.filter(Incident.source_ip == source_ip)
        if is_simulation is not None:
            query = query.filter(Incident.is_simulation == is_simulation)

        total = query.count()
        incidents = query.order_by(desc(Incident.last_seen)).offset(skip).limit(limit).all()
        return incidents, total

    @staticmethod
    def get_incident_by_id(db: Session, incident_id: int) -> Optional[Incident]:
        return db.query(Incident).filter(Incident.id == incident_id).first()

    @staticmethod
    def update_status(
        db: Session,
        incident: Incident,
        new_status: str,
        notes: Optional[str],
        current_user: User
    ) -> Incident:
        old_status = incident.status
        incident.status = new_status.upper()

        # Audit log entry for SOC accountability
        audit = AuditLog(
            actor=current_user.username,
            action="INCIDENT_STATUS_UPDATE",
            target=f"Incident #{incident.id}",
            result="SUCCESS",
            metadata_info={
                "incident_id": incident.id,
                "old_status": old_status,
                "new_status": incident.status,
                "notes": notes,
                "user_role": current_user.role
            }
        )
        db.add(audit)
        db.commit()
        db.refresh(incident)
        return incident
