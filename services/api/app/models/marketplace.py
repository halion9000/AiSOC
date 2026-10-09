"""Which marketplace items a tenant has installed (enabled).

The catalogue itself is a static index plus files on disk, the same for every tenant; an install is only the tenant's "enabled" marker. One row per (tenant, item type, item id), so installing the same item twice is one row.
Row-level security applies (migration 068), and the endpoints filter by tenant explicitly as well.
"""
import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class MarketplaceInstall(Base):
    __tablename__ = "marketplace_installs"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    item_type: Mapped[str] = mapped_column(String(20), primary_key=True)
    item_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    path: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    installed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    installed_by: Mapped[str] = mapped_column(Text, nullable=False)
