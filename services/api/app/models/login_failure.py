"""One failed sign-in attempt, for login throttling (app.services.login_throttle, migration 069).

The address is kept as typed, lower-cased and trimmed, whether or not an account exists for it: the lock must treat a real address and a made-up one the same, or it would tell an attacker which are real.
No tenant column: a sign-in happens before anyone's tenant is known.
"""
import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class LoginFailure(Base):
    __tablename__ = "login_failures"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email_key: Mapped[str] = mapped_column(String(320), nullable=False)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
