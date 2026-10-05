import logging
from datetime import datetime
from sqlalchemy.orm import Session
from app.database.session import engine
from app.database.base import Base
from app.models import (
    User, RoleEnum, DetectionRule, SystemSetting
)
from app.core.security import get_password_hash
from app.core.config import settings

logger = logging.getLogger(__name__)


def init_db(db: Session) -> None:
    # Create all tables if not exist
    Base.metadata.create_all(bind=engine)

    is_production = settings.ENVIRONMENT.lower() == "production"

    # 1. Administrator User Configuration
    admin = db.query(User).filter(User.username == "admin").first()
    if not admin:
        if is_production:
            if not settings.ADMIN_PASSWORD or settings.ADMIN_PASSWORD in ("Admin@123456", "admin", "password"):
                raise ValueError("Production mode requires an explicit secure ADMIN_PASSWORD configuration.")
            admin_pwd = settings.ADMIN_PASSWORD
        else:
            admin_pwd = settings.ADMIN_PASSWORD or "Admin@123456"

        admin = User(
            username="admin",
            email="admin@aegis-idps.net",
            full_name="SOC Administrator",
            hashed_password=get_password_hash(admin_pwd),
            role=RoleEnum.ADMIN.value,
            is_active=True,
        )
        db.add(admin)
        logger.info("Created administrator user: admin")
    else:
        if admin.email.endswith(".local"):
            admin.email = "admin@aegis-idps.net"

    # 2. Seed Demo Analyst User ONLY in development / demo mode
    if not is_production and settings.DEMO_MODE:
        analyst = db.query(User).filter(User.username == "analyst").first()
        if not analyst:
            analyst = User(
                username="analyst",
                email="analyst@aegis-idps.net",
                full_name="Tier-1 SOC Analyst",
                hashed_password=get_password_hash("Analyst@123456"),
                role=RoleEnum.ANALYST.value,
                is_active=True,
            )
            db.add(analyst)
            logger.info("Created default demo analyst user: analyst")
        else:
            if analyst.email.endswith(".local"):
                analyst.email = "analyst@aegis-idps.net"
    elif is_production:
        logger.info("Production environment: Demo analyst account skipped.")

    # 3. Seed Default Detection Rules
    default_rules = [
        {
            "sid": 2000001,
            "name": "ET SCAN Potential SSH Brute Force Attack",
            "category": "Brute Force",
            "severity": "HIGH",
            "pattern": "flags:S; threshold:count 5, seconds 30",
            "protocol": "TCP",
            "action": "ALERT",
            "enabled": True,
        },
        {
            "sid": 2000002,
            "name": "ET WEB_SPECIFIC_APPS SQL Injection Attempt in URI",
            "category": "Web Application Attack",
            "severity": "CRITICAL",
            "pattern": 'content:"UNION"; content:"SELECT"',
            "protocol": "TCP",
            "action": "ALERT",
            "enabled": True,
        },
        {
            "sid": 2000003,
            "name": "ET EXPLOIT Remote Command Execution Shell Spawn Attempt",
            "category": "Exploit",
            "severity": "CRITICAL",
            "pattern": 'content:"/bin/sh"',
            "protocol": "TCP",
            "action": "ALERT",
            "enabled": True,
        },
        {
            "sid": 2000004,
            "name": "ET SCAN Nmap Scripting Engine User-Agent",
            "category": "Reconnaissance",
            "severity": "MEDIUM",
            "pattern": 'content:"Nmap"; http_header',
            "protocol": "TCP",
            "action": "ALERT",
            "enabled": True,
        },
        {
            "sid": 2000005,
            "name": "ET SCAN SYN Port Scan Detected",
            "category": "Port Scan",
            "severity": "HIGH",
            "pattern": "flags:S; threshold:count 20, seconds 10",
            "protocol": "TCP",
            "action": "ALERT",
            "enabled": True,
        },
        {
            "sid": 2000006,
            "name": "ET EXPLOIT SMB Ghost Remote Code Execution Attempt",
            "category": "Exploit",
            "severity": "CRITICAL",
            "pattern": 'content:"|fe|SMB"',
            "protocol": "TCP",
            "action": "ALERT",
            "enabled": True,
        },
        {
            "sid": 2000007,
            "name": "ET SCAN RDP Scan Detected",
            "category": "Port Scan",
            "severity": "MEDIUM",
            "pattern": "flags:S; threshold:count 5, seconds 60",
            "protocol": "TCP",
            "action": "ALERT",
            "enabled": True,
        },
    ]

    for rule_data in default_rules:
        existing = db.query(DetectionRule).filter(DetectionRule.sid == rule_data["sid"]).first()
        if not existing:
            rule = DetectionRule(**rule_data)
            db.add(rule)

    # 4. Seed Default System Settings
    default_settings = [
        ("prevention_enabled", "true", "boolean", "Master switch for automated prevention engine"),
        ("prevention_provider", "mock", "string", "Active prevention provider adapter (mock/firewall)"),
        ("auto_prevention_threshold", "80", "integer", "Minimum threat score to trigger automated block"),
        ("default_block_duration_minutes", "60", "integer", "Default duration in minutes for temporary blocks"),
        ("scoring_port_scan_points", "30", "integer", "Threat score points for port scanning activity"),
        ("scoring_malicious_sig_points", "30", "integer", "Threat score points for known malicious signatures"),
        ("scoring_repeated_conn_points", "20", "integer", "Threat score points for repeated suspicious connections"),
        ("scoring_freq_activity_points", "10", "integer", "Threat score points for high-frequency activity burst"),
        ("correlation_window_seconds", "300", "integer", "Time window in seconds to correlate events from same IP"),
    ]

    for key, val, val_type, desc in default_settings:
        existing = db.query(SystemSetting).filter(SystemSetting.key == key).first()
        if not existing:
            db.add(SystemSetting(key=key, value=val, value_type=val_type, description=desc))

    db.commit()
    logger.info("Database initialized and default seeds applied successfully.")


if __name__ == "__main__":
    from app.database.session import SessionLocal
    logging.basicConfig(level=logging.INFO)
    db = SessionLocal()
    try:
        init_db(db)
        print("AEGIS-IDPS database initialized and seeded successfully.")
    finally:
        db.close()
