"""One entry in the community catalog (a plugin, detection or playbook), stored as the JSON document the API serves.

The catalog used to live in three module-level dictionaries and was lost on every API restart; see migrations/054_community_catalog.sql.
It is global (shared across tenants), so unlike most tables it has no tenant_id and no row-level security.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class CommunityCatalogItem(Base):
    __tablename__ = "community_catalog_items"
    __table_args__ = (Index("community_catalog_kind_status_idx", "kind", "status", "created_at"),)

    kind: Mapped[str] = mapped_column(String(20), primary_key=True)  # "plugin" | "detection" | "playbook"
    item_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # "pending" | "approved" | "rejected"
    submitter_tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True)
    data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
