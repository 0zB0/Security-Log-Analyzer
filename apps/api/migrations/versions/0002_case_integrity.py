"""Persist complete case and incident scoring state.

Revision ID: 0002_case_integrity
Revises: 0001_current_schema
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0002_case_integrity"
down_revision: Union[str, None] = "0001_current_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "analysis_runs",
        sa.Column("sources", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column(
        "analysis_runs",
        sa.Column(
            "cross_source_links", sa.JSON(), nullable=False, server_default=sa.text("'[]'")
        )
    )
    op.add_column("analysis_runs", sa.Column("case_quality", sa.JSON(), nullable=True))

    op.add_column(
        "incidents",
        sa.Column("score_breakdown", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )
    op.add_column(
        "incidents",
        sa.Column("score_rationale", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )


def downgrade() -> None:
    op.drop_column("incidents", "score_rationale")
    op.drop_column("incidents", "score_breakdown")
    op.drop_column("analysis_runs", "case_quality")
    op.drop_column("analysis_runs", "cross_source_links")
    op.drop_column("analysis_runs", "sources")
