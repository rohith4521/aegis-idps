import logging
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models.security_event import SecurityEvent
from app.detection.parser import SuricataEveParser, ParsedEvent
from app.schemas.security_event import EventIngestResponse
from app.services.correlation_service import CorrelationService

logger = logging.getLogger(__name__)


class EventService:
    @staticmethod
    def is_duplicate(db: Session, parsed: ParsedEvent) -> bool:
        """
        Check if an event with matching core characteristics already exists
        within a 1-second window.
        """
        existing = db.query(SecurityEvent.id).filter(
            SecurityEvent.timestamp == parsed.timestamp,
            SecurityEvent.source_ip == parsed.source_ip,
            SecurityEvent.destination_ip == parsed.destination_ip,
            SecurityEvent.destination_port == parsed.destination_port,
            SecurityEvent.signature == parsed.signature
        ).first()
        return existing is not None

    @classmethod
    def ingest_single_event(
        cls,
        db: Session,
        raw_event_dict: Dict[str, Any]
    ) -> Tuple[Optional[SecurityEvent], Optional[str], bool]:
        """
        Ingest, parse, deduplicate, persist, and correlate a single Suricata EVE event.
        Returns: (SecurityEvent, error_msg, is_duplicate)
        """
        parsed, error = SuricataEveParser.parse_event_dict(raw_event_dict)
        if error or not parsed:
            return None, error, False

        # Duplicate check
        if cls.is_duplicate(db, parsed):
            return None, None, True

        event = SecurityEvent(
            timestamp=parsed.timestamp,
            source_ip=parsed.source_ip,
            destination_ip=parsed.destination_ip,
            source_port=parsed.source_port,
            destination_port=parsed.destination_port,
            protocol=parsed.protocol,
            event_type=parsed.event_type,
            signature=parsed.signature,
            signature_id=parsed.signature_id,
            category=parsed.category,
            severity=parsed.severity,
            action=parsed.action,
            raw_reference=parsed.raw_reference,
            is_simulation=parsed.is_simulation,
        )

        db.add(event)
        db.flush()

        # Connect to Correlation & Threat Scoring Pipeline
        CorrelationService.correlate_event(db, event)

        db.commit()
        db.refresh(event)
        return event, None, False

    @classmethod
    def ingest_batch(
        cls,
        db: Session,
        events: List[Dict[str, Any]]
    ) -> EventIngestResponse:
        """
        Ingests a batch of raw EVE JSON dictionaries transactionally and correlates them.
        """
        ingested = 0
        skipped = 0
        duplicates = 0
        errors = []
        created_ids = []
        persisted_events = []

        for item in events:
            parsed, err = SuricataEveParser.parse_event_dict(item)
            if err or not parsed:
                errors.append(f"Parsing error: {err}")
                skipped += 1
                continue

            if cls.is_duplicate(db, parsed):
                duplicates += 1
                continue

            event = SecurityEvent(
                timestamp=parsed.timestamp,
                source_ip=parsed.source_ip,
                destination_ip=parsed.destination_ip,
                source_port=parsed.source_port,
                destination_port=parsed.destination_port,
                protocol=parsed.protocol,
                event_type=parsed.event_type,
                signature=parsed.signature,
                signature_id=parsed.signature_id,
                category=parsed.category,
                severity=parsed.severity,
                action=parsed.action,
                raw_reference=parsed.raw_reference,
                is_simulation=parsed.is_simulation,
            )
            db.add(event)
            db.flush()
            created_ids.append(event.id)
            persisted_events.append(event)
            ingested += 1

        # Correlate all newly added events
        for ev in persisted_events:
            try:
                CorrelationService.correlate_event(db, ev)
            except Exception as e:
                logger.error(f"Error correlating event {ev.id}: {e}")

        db.commit()

        return EventIngestResponse(
            ingested_count=ingested,
            skipped_count=skipped,
            duplicate_count=duplicates,
            error_count=len(errors),
            errors=errors[:10],
            created_event_ids=created_ids
        )

    @staticmethod
    def get_events(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        severity: Optional[int] = None,
        category: Optional[str] = None,
        source_ip: Optional[str] = None,
        is_simulation: Optional[bool] = None,
    ) -> Tuple[List[SecurityEvent], int]:
        query = db.query(SecurityEvent)

        if severity is not None:
            query = query.filter(SecurityEvent.severity == severity)
        if category:
            query = query.filter(SecurityEvent.category.ilike(f"%{category}%"))
        if source_ip:
            query = query.filter(SecurityEvent.source_ip == source_ip)
        if is_simulation is not None:
            query = query.filter(SecurityEvent.is_simulation == is_simulation)

        total = query.count()
        events = query.order_by(desc(SecurityEvent.timestamp)).offset(skip).limit(limit).all()
        return events, total
