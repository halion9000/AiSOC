"""Emailing alerts to platform administrators (migration 073; app/services/alert_email, app/workers/alert_email_worker).

Nothing here belongs to a tenant: one platform-wide settings row, and a log of which alerts have been emailed. The JSON column is a plain JSON type on SQLite so the unit tests can use a real database.
"""
import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, SmallInteger, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base

_JSON = JSON().with_variant(JSONB(), "postgresql")


class PlatformAlertEmailSettings(Base):
    __tablename__ = "platform_alert_email_settings"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, default=1)  # a singleton: the database CHECKs id = 1
    enabled: Mapped[bool] = mapped_column(nullable=False, default=False)
    enabled_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    min_severity: Mapped[str] = mapped_column(String(20), nullable=False, default="high")
    recipients: Mapped[list] = mapped_column(_JSON, nullable=False, default=list)
    updated_by_label: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class AlertEmailLog(Base):
    """One row per alert that has been emailed. The primary key is what makes 'already sent' a fact the database enforces."""

    __tablename__ = "alert_email_log"

    alert_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    alert_tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    batch_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    recipient_count: Mapped[int] = mapped_column(Integer, nullable=False)
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
