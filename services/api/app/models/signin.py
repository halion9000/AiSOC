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


class DirectoryAuditEvent(Base):
    """An identity-related entry of the directory audit log (migration 093)."""

    __tablename__ = "directory_audit_events"
    __table_args__ = (UniqueConstraint("tenant_id", "source", "source_id", name="uq_directory_audit_events_source"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    source: Mapped[str] = mapped_column(String(40), nullable=False)
    source_id: Mapped[str] = mapped_column(String(200), nullable=False)
    actor: Mapped[str] = mapped_column(String(320), nullable=False)
    actor_is_app: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    actor_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    activity: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(60), nullable=False)
    service: Mapped[str | None] = mapped_column(String(80), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    target: Mapped[str | None] = mapped_column(String(320), nullable=True)
    target_type: Mapped[str | None] = mapped_column(String(40), nullable=True)
    sensitivity: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    scored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)


class IdentityMfaUser(Base):
    """One person's multi-factor state from the latest snapshot (migration 093)."""

    __tablename__ = "identity_mfa_users"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    source: Mapped[str] = mapped_column(String(40), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    upn: Mapped[str] = mapped_column(String(320), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    user_type: Mapped[str | None] = mapped_column(String(20), nullable=True)
    admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    licensed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    registered: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    capable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    per_user: Mapped[str | None] = mapped_column(String(20), nullable=True)
    ca_enforced: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    security_defaults: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    methods: Mapped[str | None] = mapped_column(String(400), nullable=True)
    snapshot_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    refreshed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
