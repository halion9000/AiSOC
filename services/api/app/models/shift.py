"""Shift ORM model — mirrors migration 050 (aisoc_shifts).

Records who was on duty, when, and what happened during a SOC shift.
Handoff notes and pending items are stored inline (no separate table).
Tenant-scoped via RLS in the database; queries here are automatically
filtered by the TenantDBSession dependency.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class Shift(Base):
    __tablename__ = "aisoc_shifts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="active", server_default="active"
    )
    lead_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    lead_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    lead_role: Mapped[str | None] = mapped_column(Text, nullable=True)
    analyst_ids: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default="ARRAY[]::TEXT[]"
    )
    analyst_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    alerts_handled: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    escalations: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    handoff_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    pending_items: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default="ARRAY[]::TEXT[]"
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    ended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )