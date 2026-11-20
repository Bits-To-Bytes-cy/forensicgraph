"""Evidence ingestion processing and raw records.

Revision ID: 0005_processing_ingestion
Revises: 0004_evidence_vault
"""

import sqlalchemy as sa
from alembic import op

revision = "0005_processing_ingestion"
down_revision = "0004_evidence_vault"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "processing_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("evidence_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("requested_by", sa.String(36), nullable=False),
        sa.Column("parser_name", sa.String(120), nullable=False),
        sa.Column("parser_version", sa.String(64), nullable=False),
        sa.Column("source_sha256", sa.String(64), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("batch_size", sa.Integer(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("total_records", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column(
            "processed_records", sa.BigInteger(), nullable=False, server_default="0"
        ),
        sa.Column(
            "failed_records", sa.BigInteger(), nullable=False, server_default="0"
        ),
        sa.Column("next_locator", sa.String(500)),
        sa.Column("error_summary", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"]),
        sa.ForeignKeyConstraint(
            ["evidence_id", "organization_id"],
            ["evidence_items.id", "evidence_items.organization_id"],
            name="fk_processing_run_evidence_org",
        ),
        sa.ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["cases.id", "cases.organization_id"],
            name="fk_processing_run_case_org",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "requested_by"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_processing_run_requester_org",
        ),
        sa.UniqueConstraint(
            "evidence_id",
            "parser_name",
            "parser_version",
            "source_sha256",
            "attempt",
            name="uq_processing_run_attempt",
        ),
        sa.UniqueConstraint("id", "organization_id", name="uq_processing_run_id_org"),
    )
    op.create_index(
        "ix_processing_runs_case_created",
        "processing_runs",
        ["case_id", "created_at"],
    )
    op.create_index(
        "ix_processing_runs_evidence_status",
        "processing_runs",
        ["evidence_id", "status"],
    )

    op.create_table(
        "raw_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("processing_run_id", sa.String(36), nullable=False),
        sa.Column("evidence_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("parser_name", sa.String(120), nullable=False),
        sa.Column("parser_version", sa.String(64), nullable=False),
        sa.Column("record_number", sa.BigInteger(), nullable=False),
        sa.Column("source_locator", sa.String(500), nullable=False),
        sa.Column("raw_payload", sa.Text(), nullable=False),
        sa.Column("raw_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["processing_run_id", "organization_id"],
            ["processing_runs.id", "processing_runs.organization_id"],
            name="fk_raw_record_run_org",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id", "organization_id"],
            ["evidence_items.id", "evidence_items.organization_id"],
            name="fk_raw_record_evidence_org",
        ),
        sa.ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["cases.id", "cases.organization_id"],
            name="fk_raw_record_case_org",
        ),
        sa.UniqueConstraint(
            "processing_run_id",
            "source_locator",
            name="uq_raw_record_run_locator",
        ),
    )
    op.create_index(
        "ix_raw_records_evidence_locator",
        "raw_records",
        ["evidence_id", "source_locator"],
    )
    op.create_index(
        "ix_raw_records_run_number",
        "raw_records",
        ["processing_run_id", "record_number"],
    )

    op.create_table(
        "processing_errors",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("processing_run_id", sa.String(36), nullable=False),
        sa.Column("evidence_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("source_locator", sa.String(500)),
        sa.Column("error_type", sa.String(120), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("details", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["processing_run_id", "organization_id"],
            ["processing_runs.id", "processing_runs.organization_id"],
            name="fk_processing_error_run_org",
        ),
        sa.ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["cases.id", "cases.organization_id"],
            name="fk_processing_error_case_org",
        ),
    )
    op.create_index(
        "ix_processing_errors_run_created",
        "processing_errors",
        ["processing_run_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_processing_errors_run_created", table_name="processing_errors")
    op.drop_table("processing_errors")
    op.drop_index("ix_raw_records_run_number", table_name="raw_records")
    op.drop_index("ix_raw_records_evidence_locator", table_name="raw_records")
    op.drop_table("raw_records")
    op.drop_index("ix_processing_runs_evidence_status", table_name="processing_runs")
    op.drop_index("ix_processing_runs_case_created", table_name="processing_runs")
    op.drop_table("processing_runs")
