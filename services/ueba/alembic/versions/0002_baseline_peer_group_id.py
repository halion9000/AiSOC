"""Add ueba_entity_baselines.peer_group_id.

The EntityBaseline model has always declared this column (and the baselines listing selects it), but 0001 never created it, so every
query against ueba_entity_baselines failed with "column ueba_entity_baselines.peer_group_id does not exist" the first time the tables were
actually built. Nothing had ever run these migrations, so nothing had noticed.

Revision ID: 0002
Revises: 0001
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ueba_entity_baselines", sa.Column("peer_group_id", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("ueba_entity_baselines", "peer_group_id")
