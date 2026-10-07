"""Purple Team service configuration."""

from __future__ import annotations

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PURPLE_TEAM_", env_file=".env", extra="ignore", populate_by_name=True)

    # Database
    # Compose sets plain DATABASE_URL, but this class has the PURPLE_TEAM_ prefix, so it was IGNORED and the service fell back to localhost.
    database_url: str = Field(
        default="postgresql+asyncpg://aisoc:aisoc@localhost:5432/aisoc",
        validation_alias=AliasChoices("PURPLE_TEAM_DATABASE_URL", "DATABASE_URL"),
    )

    # Caldera integration
    caldera_url: str = "http://localhost:8888"
    caldera_api_key: str = "ADMIN123"

    # Atomic Red Team
    art_repo_path: str = "/opt/atomic-red-team"
    art_atomics_path: str = "/opt/atomic-red-team/atomics"

    # ATT&CK STIX bundle URL (for coverage mapping)
    attack_stix_url: str = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    # OTel
    otel_endpoint: str = "http://localhost:4317"
    service_name: str = "aisoc-purple-team"

    # API
    host: str = "0.0.0.0"
    port: int = 8006

    # Drift snapshot scheduler
    # Default cadence: weekly (7 days) — matches the 2026 KPI bar's
    # "delta vs. last week" mandate. Set to 0 to disable.
    drift_snapshot_interval_seconds: int = 7 * 24 * 60 * 60
    drift_scheduler_enabled: bool = True


settings = Settings()
