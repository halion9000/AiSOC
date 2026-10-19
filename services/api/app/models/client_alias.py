"""Client alias ORM model: links one vendor's name for a customer to one AiSOC tenant (migration 083)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class ClientAlias(Base):
    __tablename__ = "client_aliases"
    __table_args__ = (
        UniqueConstraint("tenant_id", "vendor", "vendor_client_id", name="client_aliases_tenant_id_vendor_vendor_client_id_key"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    vendor: Mapped[str] = mapped_column(String(40), nullable=False)
    vendor_client_id: Mapped[str] = mapped_column(String(200), nullable=False)
    vendor_client_name: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_name: Mapped[str] = mapped_column(Text, nullable=False)
    child_tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True, index=True
    )
    ignored: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    match_source: Mapped[str] = mapped_column(String(16), default="suggested", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC), nullable=False
    )


class ClientDeviceHint(Base):
    """A machine name seen for a tool's client that is not mapped yet (migration 092): evidence for suggesting which AiSOC client it belongs to."""

    __tablename__ = "client_device_hints"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    vendor: Mapped[str] = mapped_column(String(40), primary_key=True)
    vendor_client_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    hostname_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
