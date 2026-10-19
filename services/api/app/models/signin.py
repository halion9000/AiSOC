"""Sign-in events collected from an identity provider (migration 091)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


def _now() -> datetime:
    return datetime.now(UTC)


class SigninEvent(Base):
    __tablename__ = "signin_events"
    __table_args__ = (UniqueConstraint("tenant_id", "source", "source_id", name="uq_signin_events_source"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    source: Mapped[str] = mapped_column(String(40), nullable=False)
    source_id: Mapped[str] = mapped_column(String(200), nullable=False)
    user_principal: Mapped[str] = mapped_column(String(320), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    country: Mapped[str | None] = mapped_column(String(16), nullable=True)
    city: Mapped[str | None] = mapped_column(String(120), nullable=True)
    app: Mapped[str | None] = mapped_column(String(160), nullable=True)
    client_app: Mapped[str | None] = mapped_column(String(100), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    error_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    interactive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    mfa: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    risk: Mapped[str | None] = mapped_column(String(20), nullable=True)
    conditional_access: Mapped[str | None] = mapped_column(String(40), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    scored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
