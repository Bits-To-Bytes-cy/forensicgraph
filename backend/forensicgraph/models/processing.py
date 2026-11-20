"""Evidence ingestion processing runs, raw records, and parser errors."""

from datetime import datetime

from sqlalchemy import (
    BigInteger,
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


class ProcessingRun(Base):
    __tablename__ = "processing_runs"
    __table_args__ = (
        UniqueConstraint(
            "evidence_id",
            "parser_name",
            "parser_version",
            "source_sha256",
            "attempt",
            name="uq_processing_run_attempt",
        ),
        UniqueConstraint("id", "organization_id", name="uq_processing_run_id_org"),
        ForeignKeyConstraint(
            ["evidence_id", "organization_id"],
            ["evidence_items.id", "evidence_items.organization_id"],
            name="fk_processing_run_evidence_org",
        ),
        ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["cases.id", "cases.organization_id"],
            name="fk_processing_run_case_org",
        ),
        ForeignKeyConstraint(
            ["organization_id", "requested_by"],
            ["memberships.organization_id", "memberships.user_id"],
            name="fk_processing_run_requester_org",
        ),
        Index("ix_processing_runs_case_created", "case_id", "created_at"),
        Index("ix_processing_runs_evidence_status", "evidence_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    evidence_id: Mapped[str] = mapped_column(String(36), nullable=False)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    parser_name: Mapped[str] = mapped_column(String(120), nullable=False)
    parser_version: Mapped[str] = mapped_column(String(64), nullable=False)
    source_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    batch_size: Mapped[int] = mapped_column(Integer, nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    total_records: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    processed_records: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0
    )
    failed_records: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    next_locator: Mapped[str | None] = mapped_column(String(500))
    error_summary: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class RawRecord(Base):
    __tablename__ = "raw_records"
    __table_args__ = (
        UniqueConstraint(
            "processing_run_id",
            "source_locator",
            name="uq_raw_record_run_locator",
        ),
        ForeignKeyConstraint(
            ["processing_run_id", "organization_id"],
            ["processing_runs.id", "processing_runs.organization_id"],
            name="fk_raw_record_run_org",
        ),
        ForeignKeyConstraint(
            ["evidence_id", "organization_id"],
            ["evidence_items.id", "evidence_items.organization_id"],
            name="fk_raw_record_evidence_org",
        ),
        ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["cases.id", "cases.organization_id"],
            name="fk_raw_record_case_org",
        ),
        Index("ix_raw_records_evidence_locator", "evidence_id", "source_locator"),
        Index("ix_raw_records_run_number", "processing_run_id", "record_number"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    processing_run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    evidence_id: Mapped[str] = mapped_column(String(36), nullable=False)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    parser_name: Mapped[str] = mapped_column(String(120), nullable=False)
    parser_version: Mapped[str] = mapped_column(String(64), nullable=False)
    record_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    source_locator: Mapped[str] = mapped_column(String(500), nullable=False)
    raw_payload: Mapped[str] = mapped_column(Text, nullable=False)
    raw_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class ProcessingError(Base):
    __tablename__ = "processing_errors"
    __table_args__ = (
        ForeignKeyConstraint(
            ["processing_run_id", "organization_id"],
            ["processing_runs.id", "processing_runs.organization_id"],
            name="fk_processing_error_run_org",
        ),
        ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["cases.id", "cases.organization_id"],
            name="fk_processing_error_case_org",
        ),
        Index("ix_processing_errors_run_created", "processing_run_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    processing_run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    evidence_id: Mapped[str] = mapped_column(String(36), nullable=False)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False)
    source_locator: Mapped[str | None] = mapped_column(String(500))
    error_type: Mapped[str] = mapped_column(String(120), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
