from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HONEYTOKEN_", env_file=".env", extra="ignore", populate_by_name=True)

    # Database
    # Compose sets plain DATABASE_URL, but this class has the HONEYTOKEN_ prefix, so it was IGNORED and the service fell back to localhost.
    database_url: str = Field(
        default="postgresql+asyncpg://aisoc:aisoc@localhost:5432/aisoc",
        validation_alias=AliasChoices("HONEYTOKEN_DATABASE_URL", "DATABASE_URL"),
    )

    # Webhook alerting. ``alert_webhook_secret`` previously defaulted to the
    # literal string ``"changeme"`` — anyone running this service with the
    # defaults would sign every outbound honeytoken alert with a public secret,
    # so a downstream verifier couldn't distinguish a real trigger from a
    # forged one. We now default to empty and require operators to wire a
    # real HMAC secret before alerts will be signed.
    alert_webhook_url: str = ""
    alert_webhook_secret: str = ""

    # Token defaults
    token_ttl_days: int = 365

    # The address a planted link calls (HONEYTOKEN_CANARY_BASE_URL): the web console, which proxies /api/v1 to the API, so a link is <base>/api/v1/canary/<token id>.
    # The default is the console on this machine, which is right for trying a token on the same computer. For a token planted where other machines will find it, set it to an
    # address those machines can reach (the AiSOC host's LAN address, or a public one).
    canary_base_url: str = "http://localhost:3000"

    # OTel
    otel_endpoint: str = "http://localhost:4317"
    service_name: str = "aisoc-honeytokens"

    # API
    host: str = "0.0.0.0"
    port: int = 8005


settings = Settings()
