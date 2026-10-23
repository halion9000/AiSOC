"""One person as one connected tool knows them (migration 101)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class IdentitySource(Base):
    __tablename__ = "identity_sources"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    vendor: Mapped[str] = mapped_column(String(40), primary_key=True)
    external_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    kind: Mapped[str] = mapped_column(String(20), nullable=False, default="user")
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    refreshed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
