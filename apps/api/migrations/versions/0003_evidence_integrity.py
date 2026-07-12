"""Persist evidence-integrity provenance.

Revision ID: 0003_evidence_integrity
Revises: 0002_case_integrity
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0003_evidence_integrity"
down_revision: Union[str, None] = "0002_case_integrity"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "analysis_runs",
        sa.Column("evidence_integrity", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("analysis_runs", "evidence_integrity")
