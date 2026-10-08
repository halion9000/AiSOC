"""A STIX indicator or bundle a tenant has published, stored as the JSON document that was published.

Published STIX used to live in process memory and vanished on every API restart; see migrations/053_stix_objects.sql.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class StixObject(Base):
    __tablename__ = "stix_objects"
    __table_args__ = (
        UniqueConstraint("tenant_id", "stix_id", name="stix_objects_unique_stix_id"),
        Index("stix_objects_tenant_kind_idx", "tenant_id", "kind", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)  # "indicator" | "bundle"
    stix_id: Mapped[str] = mapped_column(String(120), nullable=False)
    document: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
