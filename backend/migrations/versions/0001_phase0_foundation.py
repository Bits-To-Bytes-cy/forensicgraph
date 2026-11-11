"""Phase 0 foundation baseline.

Revision ID: 0001_phase0_foundation
Revises:
"""

revision = "0001_phase0_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Reserve the initial migration boundary for Phase 1 domain models."""


def downgrade() -> None:
    """No Phase 0 tables to remove."""
