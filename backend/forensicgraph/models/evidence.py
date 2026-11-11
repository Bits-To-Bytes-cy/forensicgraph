"""Evidence Vault and append-only TrustLedger persistence models."""

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from forensicgraph.db import Base


class EvidenceUploadSession(Base):
    __tablename__ = "evidence_upload_sessions"
    __table_args__ = (
        UniqueConstraint("final_evidence_id", name="uq_upload_final_evidence"),
        ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["cases.id", "cases.organization_id"],
            name="fk_upload_session_case_org",
        ),
        ForeignKeyConstraint(
            ["organization_id", "created_by"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_upload_session_creator_org",
        ),
        Index("ix_upload_sessions_case_status", "case_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    media_type: Mapped[str] = mapped_column(String(160), nullable=False)
    expected_size: Mapped[int | None] = mapped_column(BigInteger)
    bytes_received: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    uploaded_sha256: Mapped[str | None] = mapped_column(String(64))
    uploaded_sha512: Mapped[str | None] = mapped_column(String(128))
    quarantine_key: Mapped[str] = mapped_column(
        String(500), nullable=False, unique=True
    )
    final_evidence_id: Mapped[str | None] = mapped_column(String(36))
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="created")
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class EvidenceItem(Base):
    __tablename__ = "evidence_items"
    __table_args__ = (
        UniqueConstraint("case_id", "evidence_number", name="uq_evidence_case_number"),
        UniqueConstraint("id", "organization_id", name="uq_evidence_id_org"),
        ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["cases.id", "cases.organization_id"],
            name="fk_evidence_case_org",
        ),
        ForeignKeyConstraint(
            ["organization_id", "created_by"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_evidence_creator_org",
        ),
        Index("ix_evidence_case_created", "case_id", "created_at"),
        Index("ix_evidence_org_sha256", "organization_id", "sha256"),
        Index("ix_evidence_case_status", "case_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    evidence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    media_type: Mapped[str] = mapped_column(String(160), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    sha512: Mapped[str] = mapped_column(String(128), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(500), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="available")
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EvidenceCustodyEvent(Base):
    __tablename__ = "evidence_custody_events"
    __table_args__ = (
        UniqueConstraint(
            "evidence_id", "sequence_number", name="uq_custody_evidence_sequence"
        ),
        UniqueConstraint("evidence_id", "event_hash", name="uq_custody_evidence_hash"),
        ForeignKeyConstraint(
            ["evidence_id", "organization_id"],
            ["evidence_items.id", "evidence_items.organization_id"],
            name="fk_custody_evidence_org",
        ),
        ForeignKeyConstraint(
            ["organization_id", "actor_id"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_custody_actor_org",
        ),
        Index("ix_custody_evidence_sequence", "evidence_id", "sequence_number"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    evidence_id: Mapped[str] = mapped_column(String(36), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    previous_hash: Mapped[str | None] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class EvidenceIntegrityCheck(Base):
    __tablename__ = "evidence_integrity_checks"
    __table_args__ = (
        ForeignKeyConstraint(
            ["evidence_id", "organization_id"],
            ["evidence_items.id", "evidence_items.organization_id"],
            name="fk_integrity_evidence_org",
        ),
        ForeignKeyConstraint(
            ["organization_id", "checked_by"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_integrity_checker_org",
        ),
        Index("ix_integrity_evidence_checked", "evidence_id", "checked_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    evidence_id: Mapped[str] = mapped_column(String(36), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    checked_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    sha512: Mapped[str] = mapped_column(String(128), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    storage_readback: Mapped[bool] = mapped_column(Boolean, nullable=False)
    hashes_match: Mapped[bool] = mapped_column(Boolean, nullable=False)
    chain_valid: Mapped[bool] = mapped_column(Boolean, nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class EvidenceDerivative(Base):
    __tablename__ = "evidence_derivatives"
    __table_args__ = (
        UniqueConstraint("storage_key", name="uq_derivative_storage_key"),
        ForeignKeyConstraint(
            ["evidence_id", "organization_id"],
            ["evidence_items.id", "evidence_items.organization_id"],
            name="fk_derivative_evidence_org",
        ),
        ForeignKeyConstraint(
            ["organization_id", "created_by"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_derivative_creator_org",
        ),
        Index("ix_derivatives_evidence_created", "evidence_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    evidence_id: Mapped[str] = mapped_column(String(36), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    media_type: Mapped[str] = mapped_column(String(160), nullable=False)
    purpose: Mapped[str] = mapped_column(String(500), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    sha512: Mapped[str] = mapped_column(String(128), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(500), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
