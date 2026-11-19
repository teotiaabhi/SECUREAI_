"""Create scan_history table for per-scan resource tracking.

Revision ID: 002_scan_history
Revises: 001_user_columns
Create Date: 2026-03-07
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "002_scan_history"
down_revision = "001_user_columns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_time", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("tokens_used", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("files_scanned", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("duration", sa.Float(), nullable=False, server_default="0"),
    )
    op.create_index("ix_scan_history_user_id", "scan_history", ["user_id"])
    op.create_index("ix_scan_history_scan_id", "scan_history", ["scan_id"])
    op.create_index("ix_scan_history_scan_time", "scan_history", ["scan_time"])


def downgrade() -> None:
    op.drop_index("ix_scan_history_scan_time", table_name="scan_history")
    op.drop_index("ix_scan_history_scan_id", table_name="scan_history")
    op.drop_index("ix_scan_history_user_id", table_name="scan_history")
    op.drop_table("scan_history")
