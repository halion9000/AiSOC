"""One baseline per person: remove duplicate rows, then make it a rule.

``BaselineService.get_or_create`` read the baseline and created it when absent, with nothing in the database to stop two requests for the same new entity creating one each. Once two rows
existed, every later read of that entity raised ``MultipleResultsFound`` and the score request failed with a 500 for good (seen on the live stack, 2026-10-20: 269 people with duplicates).

Duplicates are collapsed to the row that has seen the most observations (ties: the most recently updated), then a unique index is added so it cannot happen again.

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

INDEX = "ux_ueba_entity_baselines_tenant_entity"


def upgrade() -> None:
    op.execute(
        """
        DELETE FROM ueba_entity_baselines b
        USING (
            SELECT id,
                   row_number() OVER (
                       PARTITION BY tenant_id, entity_type, entity_id
                       ORDER BY (SELECT coalesce(sum((e.value ->> 'count')::float), 0) FROM jsonb_each(feature_stats) AS e) DESC,
                                updated_at DESC NULLS LAST,
                                id
                   ) AS rn
            FROM ueba_entity_baselines
        ) d
        WHERE b.id = d.id AND d.rn > 1
        """
    )
    op.create_index(INDEX, "ueba_entity_baselines", ["tenant_id", "entity_type", "entity_id"], unique=True)


def downgrade() -> None:
    op.drop_index(INDEX, table_name="ueba_entity_baselines")
