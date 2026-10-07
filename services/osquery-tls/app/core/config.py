"""Configuration settings for the AiSOC osquery TLS service.

All settings are read from environment variables prefixed with
``AISOC_OSQUERY_TLS_``, with sane defaults for local dev.
"""

from __future__ import annotations

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AISOC_OSQUERY_TLS_",
        populate_by_name=True,
        env_file=".env",
        extra="ignore",
    )

    # --- Database -------------------------------------------------------
    # Reuses the main API Postgres; all tables live in the `osquery_tls` schema.
    database_url: str = "postgresql+asyncpg://aisoc:aisoc@localhost:5432/aisoc"

    # --- Ingest service -------------------------------------------------
    # Where normalised osquery rows are forwarded to.
    # The compose service is `ingest-worker` (there is no host called `ingest`), and compose sets AISOC_INGEST_BASE_URL, which this
    # class (prefix AISOC_OSQUERY_TLS_) never read: both names are accepted now, and the default is the real host.
    ingest_url: str = Field(default="http://ingest-worker:8080", validation_alias=AliasChoices("AISOC_OSQUERY_TLS_INGEST_URL", "AISOC_INGEST_BASE_URL"))

    # --- Enrollment auth ------------------------------------------------
    # The enroll secret that osqueryd must present. In production this should
    # be a long random string stored in a secrets manager and rotated
    # periodically.  Per-tenant secrets are looked up by the ``X-AiSOC-Tenant``
    # request header; this value is used as the fallback single-tenant secret.
    enroll_secret: str = "change-me-in-production"
    # Bearer token for the INTERNAL API (queue a distributed query, read its results, manage tenant packs,
    # read FIM events). Agents never use it (they have the enroll secret and their node key); the API
    # service and the actions service do. The docstrings always said these routes were protected by
    # AISOC_OSQUERY_TLS_API_TOKEN, but no such setting existed and the routes checked nothing.
    api_token: str = ""
    # Only "development", "dev", "local" and "test" may run without the token / with the placeholder enroll
    # secret. Anything else (production, staging, a typo) must be configured, so a mistake fails closed.
    environment: str = "development"

    # --- mTLS -----------------------------------------------------------
    # When True the service validates the client TLS certificate on every
    # request after enroll.  The client cert CN must match host_identifier.
    require_client_cert: bool = False

    # --- Service identity -----------------------------------------------
    # Public hostname (used to build TLS flag-file docs).
    public_hostname: str = "osquery.tryaisoc.com"

    # --- Pack stubs (overridden fully in PR5) ---------------------------
    # Default query interval for the baseline schedule shipped to every node.
    default_interval_seconds: int = 300

    # --- Log level ------------------------------------------------------
    log_level: str = "INFO"


settings = Settings()
