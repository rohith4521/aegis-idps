import os
from typing import List, Union, Optional
from pydantic import AnyHttpUrl, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Intelligent IDPS"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    API_PREFIX: str = "/api"

    # Security & JWT
    SECRET_KEY: str = "idps_super_secret_jwt_key_development_only_change_in_production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    ADMIN_PASSWORD: Optional[str] = None

    # Database
    DATABASE_URL: str = "sqlite:///./idps.db"

    # Suricata Detection Integration
    SURICATA_EVE_PATH: str = "./infra/suricata/eve.json"
    DEMO_MODE: bool = True

    # Prevention Engine Policy
    PREVENTION_PROVIDER: str = "mock"  # "mock" or "firewall"
    PREVENTION_ENABLED: bool = True
    AUTO_PREVENTION_THRESHOLD: int = 80
    DEFAULT_BLOCK_DURATION_MINUTES: int = 60

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "https://aegis-idps.vercel.app",
    ]

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_database_url(cls, v: str) -> str:
        if isinstance(v, str):
            v_clean = v.strip()
            # If running in Vercel serverless environment and SQLite is requested without explicit path
            if os.environ.get("VERCEL") and v_clean.startswith("sqlite:///."):
                v_clean = "sqlite:////tmp/idps.db"
            # Normalize PostgreSQL dialect prefixes for SQLAlchemy 2.0
            # Common managed services (Neon, Supabase, Render, Railway) often provide postgres://
            if v_clean.startswith("postgres://"):
                return v_clean.replace("postgres://", "postgresql+psycopg2://", 1)
            elif v_clean.startswith("postgresql://") and not v_clean.startswith("postgresql+"):
                return v_clean.replace("postgresql://", "postgresql+psycopg2://", 1)
            return v_clean
        return v

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            separator = ";" if ";" in v else ","
            return [i.strip() for i in v.split(separator) if i.strip()]
        elif isinstance(v, (list, str)):
            import json
            if isinstance(v, str):
                return json.loads(v)
            return v
        raise ValueError(v)

    @model_validator(mode="after")
    def validate_production_security(self):
        env = self.ENVIRONMENT.lower()
        if env == "production":
            insecure_keys = [
                "idps_super_secret_jwt_key_development_only_change_in_production",
                "dev-insecure-secret-key-change-in-production",
                "secret",
                "changeme",
            ]
            if self.SECRET_KEY in insecure_keys or len(self.SECRET_KEY) < 32:
                raise ValueError(
                    "Production environment requires a strong SECRET_KEY (at least 32 characters, non-default)."
                )
            if self.DEMO_MODE:
                raise ValueError("DEMO_MODE cannot be enabled in production environment.")
            if not self.ADMIN_PASSWORD or self.ADMIN_PASSWORD in ("Admin@123456", "admin", "password"):
                raise ValueError(
                    "Production environment requires an explicit secure ADMIN_PASSWORD environment variable (default demo credentials are prohibited)."
                )
        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


settings = Settings()
