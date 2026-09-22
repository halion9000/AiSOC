"""OutcomeSuppression ORM model — mirrors migration 048 (aisoc_outcome_suppressions).

Records each time the auto-triage worker suppresses a repeat alert based on
a trusted prior benign/false-positive disposition. Used for the compounding
alert-reduction metric in /metrics. Tenant isolation is at the query layer
(every read filters by tenant_id); no RLS on this analytics table.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class OutcomeSuppression(Base):
    __tablename__ = "aisoc_outcome_suppressions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    disposition: Mapped[str] = mapped_column(Text, nullable=False)
    prior_author: Mapped[str] = mapped_column(
        Text, nullable=False, default="ai", server_default="ai"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )