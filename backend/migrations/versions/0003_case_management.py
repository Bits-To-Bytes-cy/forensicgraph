"""Investigation case management.

Revision ID: 0003_case_management
Revises: 0002_auth_organizations
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_case_management"
down_revision = "0002_auth_organizations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cases",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("case_number", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(240), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("priority", sa.String(16), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True)),
        sa.Column("archived_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(
            ["organization_id", "created_by"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_case_creator_org_member",
        ),
        sa.UniqueConstraint(
            "organization_id", "case_number", name="uq_case_org_number"
        ),
        sa.UniqueConstraint("id", "organization_id", name="uq_case_id_org"),
    )
    op.create_index(
        "ix_cases_organization_status", "cases", ["organization_id", "status"]
    )
    op.create_table(
        "case_memberships",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("assigned_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["assigned_by"], ["users.id"]),
        sa.ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["cases.id", "cases.organization_id"],
            name="fk_case_membership_case_org",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "user_id"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_case_membership_org_member",
        ),
        sa.UniqueConstraint("case_id", "user_id", name="uq_case_membership_user"),
    )
    op.create_index("ix_case_memberships_case", "case_memberships", ["case_id"])
    op.create_index(
        "ix_case_memberships_user",
        "case_memberships",
        ["organization_id", "user_id"],
    )
    op.create_table(
        "case_status_history",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("from_status", sa.String(32)),
        sa.Column("to_status", sa.String(32), nullable=False),
        sa.Column("changed_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["cases.id", "cases.organization_id"],
            name="fk_status_history_case_org",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "changed_by"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_status_history_actor_org",
        ),
        sa.ForeignKeyConstraint(["changed_by"], ["users.id"]),
    )
    op.create_index(
        "ix_case_status_history_case",
        "case_status_history",
        ["case_id", "created_at"],
    )
    op.create_table(
        "system_audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("actor_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("resource_type", sa.String(80), nullable=False),
        sa.Column("resource_id", sa.String(36), nullable=False),
        sa.Column("details", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(
            ["organization_id", "actor_id"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_audit_actor_org",
        ),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"]),
    )
    op.create_index(
        "ix_system_audit_org_created",
        "system_audit_events",
        ["organization_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_system_audit_org_created", table_name="system_audit_events")
    op.drop_table("system_audit_events")
    op.drop_index("ix_case_status_history_case", table_name="case_status_history")
    op.drop_table("case_status_history")
    op.drop_index("ix_case_memberships_user", table_name="case_memberships")
    op.drop_index("ix_case_memberships_case", table_name="case_memberships")
    op.drop_table("case_memberships")
    op.drop_index("ix_cases_organization_status", table_name="cases")
    op.drop_table("cases")
