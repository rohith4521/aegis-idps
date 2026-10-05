import logging
from datetime import datetime, timedelta
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.security_event import SecurityEvent
from app.models.incident import Incident
from app.models.threat_score import ThreatScore
from app.models.system_setting import SystemSetting
from app.intelligence.scoring import ThreatScoringEngine, ThreatAssessment
from app.websocket.manager import broadcast_event_sync

logger = logging.getLogger(__name__)


class CorrelationService:
    DEFAULT_WINDOW_SECONDS = 300  # 5 minutes

    @classmethod
    def get_correlation_window_seconds(cls, db: Session) -> int:
        setting = db.query(SystemSetting).filter(SystemSetting.key == "correlation_window_seconds").first()
        if setting and setting.value:
            try:
                return int(setting.value)
            except ValueError:
                pass
        return cls.DEFAULT_WINDOW_SECONDS

    @classmethod
    def get_scoring_engine(cls, db: Session) -> ThreatScoringEngine:
        # Load weights from system settings
        settings_rows = db.query(SystemSetting).filter(SystemSetting.key.like("scoring_%")).all()
        config = {}
        for s in settings_rows:
            try:
                config[s.key] = int(s.value)
            except ValueError:
                pass
        return ThreatScoringEngine(config)

    @classmethod
    def correlate_event(
        cls,
        db: Session,
        event: SecurityEvent
    ) -> Optional[Incident]:
        """
        Correlates a newly ingested security event with an existing active incident
        or creates a new incident if no active matching incident is found within
        the correlation time window.
        """
        # Filter out informational telemetry (category == 'HTTP Traffic', 'Flow Telemetry', etc.)
        if event.severity >= 4 or "Traffic" in event.category or "Flow" in event.category:
            return None

        window_seconds = cls.get_correlation_window_seconds(db)
        window_start = event.timestamp - timedelta(seconds=window_seconds)

        # 1. Search for matching open incident
        candidate_incident = db.query(Incident).filter(
            Incident.source_ip == event.source_ip,
            Incident.category == event.category,
            Incident.status.in_(["ACTIVE", "INVESTIGATING"]),
            Incident.last_seen >= window_start
        ).order_by(desc(Incident.last_seen)).first()

        scoring_engine = cls.get_scoring_engine(db)

        if candidate_incident:
            # Associate event to existing incident
            event.incident_id = candidate_incident.id
            if event.timestamp > candidate_incident.last_seen:
                candidate_incident.last_seen = event.timestamp
            if event.timestamp < candidate_incident.first_seen:
                candidate_incident.first_seen = event.timestamp
            
            if not candidate_incident.destination_ip and event.destination_ip:
                candidate_incident.destination_ip = event.destination_ip

            # Fetch all events currently linked to this incident
            all_events = db.query(SecurityEvent).filter(
                SecurityEvent.incident_id == candidate_incident.id
            ).all()
            if event not in all_events:
                all_events.append(event)

            candidate_incident.event_count = len(all_events)
            sim_count = sum(1 for e in all_events if getattr(e, "is_simulation", False))
            real_count = len(all_events) - sim_count

            if sim_count > 0 and real_count > 0:
                # Mixed-origin: contains both real telemetry and synthetic events.
                # Mark as simulation for prevention engine safety while explicitly labelling title and origin.
                candidate_incident.is_simulation = True
                clean_title = candidate_incident.title.replace("[SIMULATION] ", "").replace("[MIXED: REAL+SIMULATION] ", "")
                candidate_incident.title = f"[MIXED: REAL+SIMULATION] {clean_title}"
            elif sim_count > 0:
                candidate_incident.is_simulation = True
                if not candidate_incident.title.startswith("[SIMULATION]"):
                    clean_title = candidate_incident.title.replace("[MIXED: REAL+SIMULATION] ", "")
                    candidate_incident.title = f"[SIMULATION] {clean_title}"
            else:
                candidate_incident.is_simulation = False
                candidate_incident.title = candidate_incident.title.replace("[SIMULATION] ", "").replace("[MIXED: REAL+SIMULATION] ", "")

            # Recalculate threat assessment across all events
            assessment: ThreatAssessment = scoring_engine.evaluate_events(all_events)
            candidate_incident.threat_score = assessment.score
            candidate_incident.severity = assessment.severity
            candidate_incident.confidence = assessment.confidence
            candidate_incident.updated_at = datetime.utcnow()

            # Update threat score detail record
            threat_detail = candidate_incident.threat_score_detail
            if threat_detail:
                threat_detail.score = assessment.score
                threat_detail.severity = assessment.severity
                threat_detail.confidence = assessment.confidence
                threat_detail.factors = assessment.factors
            else:
                threat_detail = ThreatScore(
                    incident_id=candidate_incident.id,
                    score=assessment.score,
                    severity=assessment.severity,
                    confidence=assessment.confidence,
                    factors=assessment.factors
                )
                db.add(threat_detail)

            db.commit()
            db.refresh(candidate_incident)

            # Evaluate Prevention Policy on updated incident
            try:
                from app.prevention.engine import PreventionEngine
                PreventionEngine.evaluate_and_prevent(db, candidate_incident)
            except Exception as e:
                logger.error(f"Error during prevention policy evaluation: {e}")

            # Safe broadcast after commit
            broadcast_event_sync(
                "incident.updated",
                {
                    "id": candidate_incident.id,
                    "title": candidate_incident.title,
                    "category": candidate_incident.category,
                    "severity": candidate_incident.severity,
                    "threat_score": candidate_incident.threat_score,
                    "source_ip": candidate_incident.source_ip,
                    "event_count": candidate_incident.event_count,
                    "is_simulation": candidate_incident.is_simulation,
                    "origin": candidate_incident.origin,
                },
                resource_id=candidate_incident.id
            )

            return candidate_incident

        else:
            # 2. Create new incident
            prefix = "[SIMULATION] " if event.is_simulation else ""
            title = f"{prefix}{event.category} detected from {event.source_ip}"
            
            assessment = scoring_engine.evaluate_events([event])

            incident = Incident(
                title=title,
                category=event.category,
                severity=assessment.severity,
                status="ACTIVE",
                threat_score=assessment.score,
                confidence=assessment.confidence,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                event_count=1,
                is_simulation=event.is_simulation,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            db.add(incident)
            db.flush()

            event.incident_id = incident.id

            threat_detail = ThreatScore(
                incident_id=incident.id,
                score=assessment.score,
                severity=assessment.severity,
                confidence=assessment.confidence,
                factors=assessment.factors,
                created_at=datetime.utcnow()
            )
            db.add(threat_detail)

            db.commit()
            db.refresh(incident)

            # Evaluate Prevention Policy on new incident
            try:
                from app.prevention.engine import PreventionEngine
                PreventionEngine.evaluate_and_prevent(db, incident)
            except Exception as e:
                logger.error(f"Error during prevention policy evaluation: {e}")

            # Safe broadcast after commit
            broadcast_event_sync(
                "incident.created",
                {
                    "id": incident.id,
                    "title": incident.title,
                    "category": incident.category,
                    "severity": incident.severity,
                    "threat_score": incident.threat_score,
                    "source_ip": incident.source_ip,
                    "event_count": incident.event_count,
                    "is_simulation": incident.is_simulation,
                    "origin": incident.origin,
                },
                resource_id=incident.id
            )

            return incident
