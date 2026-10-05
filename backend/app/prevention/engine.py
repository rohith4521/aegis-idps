import ipaddress
import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.incident import Incident
from app.models.prevention_action import PreventionAction
from app.models.blocked_source import BlockedSource
from app.models.audit_log import AuditLog
from app.models.system_setting import SystemSetting
from app.models.user import User
from app.core.config import settings
from app.prevention.provider import (
    BasePreventionProvider,
    MockPreventionProvider,
    FirewallPreventionProvider,
    PreventionResult,
)

logger = logging.getLogger(__name__)


class PreventionEngine:
    """
    Safe, auditable prevention policy and decision engine.
    Ensures safe mock execution by default, strictly validates targets,
    protects allowlisted IPs, and records transparent audit trails.
    """
    _lock = threading.RLock()

    @classmethod
    def get_provider(cls, db: Optional[Session] = None) -> BasePreventionProvider:
        provider_name = settings.PREVENTION_PROVIDER
        if db:
            setting = db.query(SystemSetting).filter(SystemSetting.key == "prevention_provider").first()
            if setting and setting.value:
                provider_name = setting.value.lower()

        if provider_name == "firewall":
            # Disabled boundary in this phase
            return FirewallPreventionProvider(authorized_in_lab=False)
        return MockPreventionProvider()

    @classmethod
    def is_prevention_enabled(cls, db: Session) -> bool:
        setting = db.query(SystemSetting).filter(SystemSetting.key == "prevention_enabled").first()
        if setting and setting.value:
            return setting.value.lower() in ("true", "1", "yes")
        return settings.PREVENTION_ENABLED

    @classmethod
    def get_auto_block_threshold(cls, db: Session) -> int:
        setting = db.query(SystemSetting).filter(SystemSetting.key == "auto_prevention_threshold").first()
        if setting and setting.value:
            try:
                return int(setting.value)
            except ValueError:
                pass
        return settings.AUTO_PREVENTION_THRESHOLD

    @classmethod
    def get_default_duration_minutes(cls, db: Session) -> int:
        setting = db.query(SystemSetting).filter(SystemSetting.key == "default_block_duration_minutes").first()
        if setting and setting.value:
            try:
                return int(setting.value)
            except ValueError:
                pass
        return settings.DEFAULT_BLOCK_DURATION_MINUTES

    @classmethod
    def validate_ip_address(cls, ip_str: str) -> Optional[str]:
        if not ip_str or not isinstance(ip_str, str):
            return None
        try:
            addr = ipaddress.ip_address(ip_str.strip())
            return str(addr)
        except ValueError:
            return None

    @classmethod
    def is_allowlisted(cls, db: Session, ip: str) -> bool:
        entry = db.query(BlockedSource).filter(
            BlockedSource.ip == ip,
            BlockedSource.is_whitelisted == True
        ).first()
        return entry is not None

    @classmethod
    def evaluate_and_prevent(
        cls,
        db: Session,
        incident: Incident
    ) -> Tuple[Optional[PreventionAction], str]:
        """
        Evaluate policy for an incident and execute a safe prevention action if eligible.
        Returns: (PreventionAction or None, policy_reason)
        """
        # 1. Check if prevention is globally enabled
        if not cls.is_prevention_enabled(db):
            return None, "Prevention engine is currently disabled in system settings."

        # 2. Simulation safety check: Simulated events must never trigger automated prevention
        if incident.is_simulation:
            return None, "Simulation safety check: Simulated events are excluded from automated prevention."

        # 3. Validate IP target
        validated_ip = cls.validate_ip_address(incident.source_ip)
        if not validated_ip:
            return None, f"Invalid source IP address: {incident.source_ip}"

        # 3. Allowlist check
        if cls.is_allowlisted(db, validated_ip):
            action = PreventionAction(
                incident_id=incident.id,
                action="WHITELIST_BYPASS",
                target=validated_ip,
                reason=f"Incident threat score is {incident.threat_score}, but source is explicitly allowlisted.",
                duration_minutes=0,
                status="REVERTED",
                provider="policy_guard",
                is_simulation=incident.is_simulation,
                executed_at=datetime.utcnow(),
                created_at=datetime.utcnow()
            )
            db.add(action)
            db.commit()
            return action, "Source IP is allowlisted; prevention blocked by policy."

        # 4. Check policy threshold
        threshold = cls.get_auto_block_threshold(db)
        if incident.threat_score < 30:
            return None, "Policy decision: LOW threat score (LOG_ONLY)."
        elif incident.threat_score < 60:
            return None, "Policy decision: MEDIUM threat score (ALERT_ONLY)."
        elif incident.threat_score < threshold:
            return None, f"Policy decision: HIGH threat score (MONITOR_ONLY). Below automated block threshold ({threshold})."

        # 5. Lock and evaluate active block / provider execution
        with cls._lock:
            existing_block = db.query(BlockedSource).filter(
                BlockedSource.ip == validated_ip,
                BlockedSource.status == "ACTIVE"
            ).first()

            if existing_block:
                # Update threat score on existing block if higher
                if incident.threat_score > existing_block.threat_score:
                    existing_block.threat_score = incident.threat_score
                    try:
                        db.commit()
                    except Exception:
                        db.rollback()
                return None, f"Source {validated_ip} already has an active block entry."

            # 6. Execute Provider
            provider = cls.get_provider(db)
            duration_minutes = cls.get_default_duration_minutes(db)
            
            result: PreventionResult = provider.block_source(
                target=validated_ip,
                reason=f"Automated threat response for {incident.category} (Score: {incident.threat_score})",
                duration_minutes=duration_minutes,
                is_simulation=incident.is_simulation
            )

            now = datetime.utcnow()
            expiry = now + timedelta(minutes=duration_minutes) if duration_minutes else None

            # 7. Persist PreventionAction
            action_record = PreventionAction(
                incident_id=incident.id,
                action=result.action,
                target=validated_ip,
                reason=result.message,
                duration_minutes=duration_minutes,
                status=result.status,
                provider=result.provider,
                is_simulation=incident.is_simulation,
                executed_at=result.executed_at,
                created_at=now
            )
            db.add(action_record)

            # 8. Persist or Update BlockedSource only on successful execution
            if result.success:
                blocked_source = db.query(BlockedSource).filter(BlockedSource.ip == validated_ip).first()
                if blocked_source:
                    blocked_source.reason = f"{incident.category} - Threat Score {incident.threat_score}"
                    blocked_source.severity = incident.severity
                    blocked_source.threat_score = incident.threat_score
                    blocked_source.blocked_time = now
                    blocked_source.expiry = expiry
                    blocked_source.status = "ACTIVE"
                    blocked_source.is_whitelisted = False
                    blocked_source.provider = result.provider
                    blocked_source.is_simulation = incident.is_simulation
                    blocked_source.created_by = "AUTOMATED_PREVENTION_ENGINE"
                    blocked_source.unblocked_at = None
                    blocked_source.unblocked_by = None
                else:
                    blocked_source = BlockedSource(
                        ip=validated_ip,
                        reason=f"{incident.category} - Threat Score {incident.threat_score}",
                        severity=incident.severity,
                        threat_score=incident.threat_score,
                        blocked_time=now,
                        expiry=expiry,
                        status="ACTIVE",
                        is_whitelisted=False,
                        provider=result.provider,
                        is_simulation=incident.is_simulation,
                        created_by="AUTOMATED_PREVENTION_ENGINE",
                        created_at=now
                    )
                    db.add(blocked_source)

            # 9. Audit Log
            audit = AuditLog(
                actor="AUTOMATED_PREVENTION_ENGINE",
                action="SOURCE_BLOCKED",
                target=validated_ip,
                result=result.status,
                metadata_info={
                    "incident_id": incident.id,
                    "provider": result.provider,
                    "threat_score": incident.threat_score,
                    "duration_minutes": duration_minutes,
                    "is_simulation": incident.is_simulation,
                    "message": result.message
                }
            )
            db.add(audit)
            try:
                db.commit()
                db.refresh(action_record)
            except Exception as e:
                db.rollback()
                logger.error(f"Database error during prevention commit: {e}")
                raise
            return action_record, result.message

    @classmethod
    def manual_unblock(
        cls,
        db: Session,
        blocked_id: int,
        reason: str,
        actor_user: User
    ) -> Tuple[Optional[BlockedSource], str]:
        with cls._lock:
            blocked_entry = db.query(BlockedSource).filter(BlockedSource.id == blocked_id).first()
            if not blocked_entry:
                return None, f"Blocked source record #{blocked_id} not found"

            if blocked_entry.status != "ACTIVE":
                return None, f"Source {blocked_entry.ip} is not currently active (status: {blocked_entry.status})"

            provider = cls.get_provider(db)
            result = provider.unblock_source(
                target=blocked_entry.ip,
                reason=reason,
                is_simulation=blocked_entry.is_simulation
            )

            now = datetime.utcnow()
            if result.success:
                blocked_entry.status = "MANUALLY_UNBLOCKED"
                blocked_entry.unblocked_at = now
                blocked_entry.unblocked_by = actor_user.username

            action_record = PreventionAction(
                incident_id=None,
                action="UNBLOCK",
                target=blocked_entry.ip,
                reason=f"Manual unblock by {actor_user.username}: {reason}" if result.success else f"Manual unblock failed: {result.message}",
                duration_minutes=None,
                status=result.status,
                provider=result.provider,
                is_simulation=blocked_entry.is_simulation,
                executed_at=now,
                created_at=now
            )
            db.add(action_record)

            audit = AuditLog(
                actor=actor_user.username,
                action="MANUAL_UNBLOCK",
                target=blocked_entry.ip,
                result="SUCCESS" if result.success else "FAILURE",
                metadata_info={
                    "reason": reason,
                    "actor_role": actor_user.role,
                    "previous_threat_score": blocked_entry.threat_score,
                    "provider_message": result.message
                }
            )
            db.add(audit)
            try:
                db.commit()
                if result.success:
                    db.refresh(blocked_entry)
            except Exception as e:
                db.rollback()
                logger.error(f"Database error during manual unblock commit: {e}")
                raise

            if not result.success:
                return None, f"Provider unblock failed: {result.message}"

            return blocked_entry, result.message

    @classmethod
    def set_allowlist(
        cls,
        db: Session,
        ip: str,
        reason: str,
        actor_user: User
    ) -> Tuple[Optional[BlockedSource], str]:
        validated_ip = cls.validate_ip_address(ip)
        if not validated_ip:
            return None, f"Invalid IP address format: {ip}"

        with cls._lock:
            entry = db.query(BlockedSource).filter(BlockedSource.ip == validated_ip).first()
            now = datetime.utcnow()

            if entry:
                entry.is_whitelisted = True
                entry.status = "WHITELISTED"
                entry.reason = f"Allowlisted: {reason}"
                entry.unblocked_at = now
                entry.unblocked_by = actor_user.username
            else:
                entry = BlockedSource(
                    ip=validated_ip,
                    reason=f"Allowlisted: {reason}",
                    severity="LOW",
                    threat_score=0,
                    blocked_time=now,
                    expiry=None,
                    status="WHITELISTED",
                    is_whitelisted=True,
                    provider="mock",
                    is_simulation=False,
                    created_by=actor_user.username,
                    created_at=now
                )
                db.add(entry)

            audit = AuditLog(
                actor=actor_user.username,
                action="SOURCE_ALLOWLISTED",
                target=validated_ip,
                result="SUCCESS",
                metadata_info={"reason": reason, "actor_role": actor_user.role}
            )
            db.add(audit)
            try:
                db.commit()
                db.refresh(entry)
            except Exception as e:
                db.rollback()
                logger.error(f"Database error during allowlist commit: {e}")
                raise
            return entry, f"Source IP {validated_ip} has been added to the SOC allowlist."

    @classmethod
    def cleanup_expired_blocks(cls, db: Session) -> int:
        now = datetime.utcnow()
        with cls._lock:
            expired_entries = db.query(BlockedSource).filter(
                BlockedSource.status == "ACTIVE",
                BlockedSource.expiry != None,
                BlockedSource.expiry <= now
            ).all()

            count = len(expired_entries)
            for entry in expired_entries:
                entry.status = "EXPIRED"
                entry.unblocked_at = now
                entry.unblocked_by = "EXPIRY_CLEANUP_WORKER"

                action = PreventionAction(
                    incident_id=None,
                    action="EXPIRED_BLOCK_LIFTED",
                    target=entry.ip,
                    reason="Temporary block duration has elapsed.",
                    duration_minutes=None,
                    status="EXECUTED",
                    provider=entry.provider,
                    is_simulation=entry.is_simulation,
                    executed_at=now,
                    created_at=now
                )
                db.add(action)

            if count > 0:
                try:
                    db.commit()
                except Exception as e:
                    db.rollback()
                    logger.error(f"Database error during cleanup commit: {e}")
                    raise
            return count
