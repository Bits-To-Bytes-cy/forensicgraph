"""Evidence Vault and TrustLedger.

Revision ID: 0004_evidence_vault
Revises: 0003_case_management
"""

import sqlalchemy as sa
from alembic import op

revision = "0004_evidence_vault"
down_revision = "0003_case_management"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evidence_upload_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("original_filename", sa.String(255), nullable=False),
        sa.Column("media_type", sa.String(160), nullable=False),
        sa.Column("expected_size", sa.BigInteger()),
        sa.Column(
            "bytes_received", sa.BigInteger(), nullable=False, server_default="0"
        ),
        sa.Column("uploaded_sha256", sa.String(64)),
        sa.Column("uploaded_sha512", sa.String(128)),
        sa.Column("quarantine_key", sa.String(500), nullable=False),
        sa.Column("final_evidence_id", sa.String(36)),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("error_message", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["cases.id", "cases.organization_id"],
            name="fk_upload_session_case_org",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "created_by"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_upload_session_creator_org",
        ),
        sa.UniqueConstraint("quarantine_key"),
        sa.UniqueConstraint("final_evidence_id", name="uq_upload_final_evidence"),
    )
    op.create_index(
        "ix_upload_sessions_case_status",
        "evidence_upload_sessions",
        ["case_id", "status"],
    )

    op.create_table(
        "evidence_items",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("evidence_number", sa.Integer(), nullable=False),
        sa.Column("original_filename", sa.String(255), nullable=False),
        sa.Column("media_type", sa.String(160), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("sha512", sa.String(128), nullable=False),
        sa.Column("storage_key", sa.String(500), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["cases.id", "cases.organization_id"],
            name="fk_evidence_case_org",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "created_by"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_evidence_creator_org",
        ),
        sa.UniqueConstraint(
            "case_id", "evidence_number", name="uq_evidence_case_number"
        ),
        sa.UniqueConstraint("id", "organization_id", name="uq_evidence_id_org"),
        sa.UniqueConstraint("storage_key"),
    )
    op.create_index(
        "ix_evidence_case_created", "evidence_items", ["case_id", "created_at"]
    )
    op.create_index(
        "ix_evidence_org_sha256", "evidence_items", ["organization_id", "sha256"]
    )
    op.create_index("ix_evidence_case_status", "evidence_items", ["case_id", "status"])

    op.create_table(
        "evidence_custody_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("evidence_id", sa.String(36), nullable=False),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("actor_id", sa.String(36), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("previous_hash", sa.String(64)),
        sa.Column("event_hash", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"]),
        sa.ForeignKeyConstraint(
            ["evidence_id", "organization_id"],
            ["evidence_items.id", "evidence_items.organization_id"],
            name="fk_custody_evidence_org",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "actor_id"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_custody_actor_org",
        ),
        sa.UniqueConstraint(
            "evidence_id", "sequence_number", name="uq_custody_evidence_sequence"
        ),
        sa.UniqueConstraint(
            "evidence_id", "event_hash", name="uq_custody_evidence_hash"
        ),
    )
    op.create_index(
        "ix_custody_evidence_sequence",
        "evidence_custody_events",
        ["evidence_id", "sequence_number"],
    )

    op.create_table(
        "evidence_integrity_checks",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("evidence_id", sa.String(36), nullable=False),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("checked_by", sa.String(36), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("sha512", sa.String(128), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("storage_readback", sa.Boolean(), nullable=False),
        sa.Column("hashes_match", sa.Boolean(), nullable=False),
        sa.Column("chain_valid", sa.Boolean(), nullable=False),
        sa.Column("details", sa.Text(), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["checked_by"], ["users.id"]),
        sa.ForeignKeyConstraint(
            ["evidence_id", "organization_id"],
            ["evidence_items.id", "evidence_items.organization_id"],
            name="fk_integrity_evidence_org",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "checked_by"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_integrity_checker_org",
        ),
    )
    op.create_index(
        "ix_integrity_evidence_checked",
        "evidence_integrity_checks",
        ["evidence_id", "checked_at"],
    )

    op.create_table(
        "evidence_derivatives",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("evidence_id", sa.String(36), nullable=False),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("original_filename", sa.String(255), nullable=False),
        sa.Column("media_type", sa.String(160), nullable=False),
        sa.Column("purpose", sa.String(500), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("sha512", sa.String(128), nullable=False),
        sa.Column("storage_key", sa.String(500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(
            ["evidence_id", "organization_id"],
            ["evidence_items.id", "evidence_items.organization_id"],
            name="fk_derivative_evidence_org",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "created_by"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_derivative_creator_org",
        ),
        sa.UniqueConstraint("storage_key", name="uq_derivative_storage_key"),
    )
    op.create_index(
        "ix_derivatives_evidence_created",
        "evidence_derivatives",
        ["evidence_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_derivatives_evidence_created", table_name="evidence_derivatives")
    op.drop_table("evidence_derivatives")
    op.drop_index(
        "ix_integrity_evidence_checked", table_name="evidence_integrity_checks"
    )
    op.drop_table("evidence_integrity_checks")
    op.drop_index("ix_custody_evidence_sequence", table_name="evidence_custody_events")
    op.drop_table("evidence_custody_events")
    op.drop_index("ix_evidence_case_status", table_name="evidence_items")
    op.drop_index("ix_evidence_org_sha256", table_name="evidence_items")
    op.drop_index("ix_evidence_case_created", table_name="evidence_items")
    op.drop_table("evidence_items")
    op.drop_index(
        "ix_upload_sessions_case_status", table_name="evidence_upload_sessions"
    )
    op.drop_table("evidence_upload_sessions")
