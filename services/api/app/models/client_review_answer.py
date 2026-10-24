"""An answer typed into the client review, or a note on a question (migration 102)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class ClientReviewAnswer(Base):
    __tablename__ = "client_review_answers"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    section: Mapped[str] = mapped_column(String(12), primary_key=True)  # readiness / tech / m365
    key: Mapped[str] = mapped_column(String(400), primary_key=True)
    status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    answer: Mapped[str | None] = mapped_column(String(300), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
