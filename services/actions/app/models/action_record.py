"""A response action as stored in the response_actions table (created by services/api/migrations/055_response_actions.sql)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class ActionRecord(Base):
    __tablename__ = "response_actions"
    __table_args__ = (
        Index("response_actions_tenant_status_idx", "tenant_id", "status", "created_at"),
        Index("response_actions_incident_idx", "incident_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    action_type: Mapped[str] = mapped_column(String(60), nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    blast_radius: Mapped[str] = mapped_column(String(20), nullable=False)
    gate_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    requested_by_user_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved_by_user_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    request: Mapped[dict] = mapped_column(JSONB, nullable=False)  # the COMPLETE original request, immutable
    result: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)  # output, rollback_data, error, ChatOps choice, ...
    chatops_responded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
