"""A person's explicit access to a tenant other than their own (migration 072).

A person belongs to one tenant but may be GRANTED read-only access to others. The grant belongs to the granted tenant: row-level security applies on `tenant_id`, so that tenant's own people can see who has access to their data.
(app/services/view_as.py decides who may view what; app/api/v1/endpoints/tenants.py manages the grants.)
"""
import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base

ACCESS_VIEW = "view"


class TenantAccessGrant(Base):
    __tablename__ = "tenant_access_grants"
    __table_args__ = (UniqueConstraint("user_id", "tenant_id", name="uq_tenant_access_grants_user_tenant"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    access: Mapped[str] = mapped_column(String(16), nullable=False, default=ACCESS_VIEW)
    granted_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    granted_by_label: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
